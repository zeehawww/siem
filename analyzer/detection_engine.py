"""
Detection Engine
=================
Rule-based detection with:
  ✅ MITRE ATT&CK enrichment
  ✅ Numeric risk scoring
  ✅ Behavioral IP baseline (UEBA)
  ✅ After-hours login detection

Novel additions:
  🆕 Alert Explainability Engine (P0) — every alert carries a structured
     explanation of WHY it was raised and what DIDN'T happen (counterfactuals)
  🆕 Alert Confidence Decay Engine (P1) — risk scores decay over time when
     no corroborating events follow. Alerts "cool down" automatically.
  🆕 What-If Simulation Support (P2) — analyze_event() accepts a simulation
     mode flag to test rule coverage without affecting live state.
"""

import time
from typing import Optional, List, Dict, Any
from collections import defaultdict

failed_attempts = defaultdict(int)
# Behavior analytics: user -> set of IPs we've seen for successful logins
user_ip_baseline = defaultdict(set)

# --- Confidence Decay: track when an alert type was last raised per entity ---
# Structure: {(type, entity): timestamp_float}
_alert_timestamps: Dict[tuple, float] = {}

# MITRE ATT&CK tactic mapping per alert type
MITRE_TACTICS = {
    "BRUTE_FORCE":          {"tactic": "Credential Access",    "technique": "T1110"},
    "COMPROMISED_ACCOUNT":  {"tactic": "Initial Access",       "technique": "T1078"},
    "NEW_IP_FOR_USER":      {"tactic": "Lateral Movement",     "technique": "T1021"},
    "PRIV_ESC":             {"tactic": "Privilege Escalation", "technique": "T1548"},
    "ROOT_LOGIN":           {"tactic": "Privilege Escalation", "technique": "T1078.003"},
    "AFTER_HOURS_LOGIN":    {"tactic": "Initial Access",       "technique": "T1078"},
}

# Base risk scores per severity tier (0-100)
RISK_SCORES = {
    "CRITICAL": 90,
    "HIGH":     70,
    "MEDIUM":   45,
    "LOW":      15,
}

# Business hours window (24h format, inclusive)
BUSINESS_HOURS = (9, 17)  # 9 AM – 5 PM

# ── Explainability: contributing factors per alert type ─────────────────────
# Each entry: {"factor": text, "weight": "high"|"medium"|"low", "check": callable(event, state)}
_EXPLANATION_FACTORS = {
    "BRUTE_FORCE": [
        {
            "factor": "3 or more failed login attempts from the same IP address",
            "weight": "high",
        },
        {
            "factor": "Repeated targeting of different usernames from same source",
            "weight": "medium",
            "conditional": True,
            "condition_desc": "multiple usernames targeted (would escalate to CREDENTIAL_STUFFING)",
        },
    ],
    "COMPROMISED_ACCOUNT": [
        {
            "factor": "Prior brute-force activity from same IP (failed_attempts >= 3)",
            "weight": "high",
        },
        {
            "factor": "Successful authentication followed the failure chain",
            "weight": "high",
        },
        {
            "factor": "If sudo usage followed, this would be a FULL CHAIN alert",
            "weight": "counterfactual",
        },
    ],
    "NEW_IP_FOR_USER": [
        {
            "factor": "User authenticated from an IP address not in their baseline",
            "weight": "high",
        },
        {
            "factor": "Baseline of known IPs exists for this user",
            "weight": "medium",
        },
        {
            "factor": "If the new IP is in a foreign country, severity would be CRITICAL",
            "weight": "counterfactual",
        },
    ],
    "PRIV_ESC": [
        {
            "factor": "sudo command executed by non-root user",
            "weight": "high",
        },
        {
            "factor": "If root login preceded this, severity would be CRITICAL + ROOT_CHAIN",
            "weight": "counterfactual",
        },
    ],
    "ROOT_LOGIN": [
        {
            "factor": "Direct login as root user detected (bypasses normal privilege escalation)",
            "weight": "high",
        },
        {
            "factor": "Root logins are unconditionally flagged — no threshold required",
            "weight": "medium",
        },
        {
            "factor": "If followed by sudo, this would trigger a ROOT_CHAIN escalation",
            "weight": "counterfactual",
        },
    ],
    "AFTER_HOURS_LOGIN": [
        {
            "factor": "Login occurred outside configured business hours (09:00-17:00)",
            "weight": "medium",
        },
        {
            "factor": "Could indicate stolen credentials used outside monitored working period",
            "weight": "medium",
        },
        {
            "factor": "If this IP had prior failures, this would be COMPROMISED_ACCOUNT candidate",
            "weight": "counterfactual",
        },
    ],
}


def _build_explanation(alert_type: str, event: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a structured explanation for why an alert was raised.
    Returns:
      {
        "factors": [{"factor": str, "weight": str}],       # what triggered it
        "counterfactuals": [str],                          # what DIDN'T happen
        "severity_rationale": str,                        # why this severity
        "what_would_escalate": str,                       # what next event would do
      }
    """
    factors_def = _EXPLANATION_FACTORS.get(alert_type, [])
    factors = []
    counterfactuals = []

    for f in factors_def:
        if f["weight"] == "counterfactual":
            counterfactuals.append(f["factor"])
        else:
            factors.append({"factor": f["factor"], "weight": f["weight"]})

    # Severity rationale
    sev = state.get("severity", "MEDIUM")
    rationale_map = {
        "CRITICAL": "Severity is CRITICAL because this event represents a confirmed security breach or direct access by a privileged account.",
        "HIGH":     "Severity is HIGH because the event indicates active attack behavior with significant potential for damage.",
        "MEDIUM":   "Severity is MEDIUM because the event is suspicious but lacks direct confirmation of a breach.",
        "LOW":      "Severity is LOW because the event is informational with minimal immediate threat.",
    }
    severity_rationale = rationale_map.get(sev, "Severity assigned based on rule match.")

    return {
        "factors":            factors,
        "counterfactuals":    counterfactuals,
        "severity_rationale": severity_rationale,
    }


# ── Confidence Decay: compute decayed risk score ─────────────────────────────
_DECAY_HALF_LIFE_SECONDS = 3600  # risk halves every 1 hour with no corroboration

def _compute_decayed_score(base_score: int, alert_type: str, entity: str) -> Dict[str, Any]:
    """
    Compute a time-decayed effective risk score.
    Returns:
      { "base_score": int, "decayed_score": int, "decay_pct": int,
        "seconds_since_last": int|None, "decay_explanation": str }
    """
    key = (alert_type, entity)
    now = time.time()

    if key in _alert_timestamps:
        elapsed = now - _alert_timestamps[key]
        # Exponential decay: S(t) = S0 * 0.5^(t/half_life)
        decay_factor = 0.5 ** (elapsed / _DECAY_HALF_LIFE_SECONDS)
        decayed = round(base_score * decay_factor)
        decay_pct = round((1 - decay_factor) * 100)
        explanation = (
            f"Risk score decayed by {decay_pct}% because no corroborating event "
            f"was observed for {int(elapsed)}s (half-life: {_DECAY_HALF_LIFE_SECONDS}s)"
        )
    else:
        decayed = base_score
        decay_pct = 0
        elapsed = None
        explanation = "No prior occurrence — full base risk score applied."

    # Update timestamp for next decay calculation
    _alert_timestamps[key] = now

    return {
        "base_score":          base_score,
        "decayed_score":       max(1, decayed),
        "decay_pct":           decay_pct,
        "seconds_since_last":  int(elapsed) if elapsed is not None else None,
        "decay_explanation":   explanation,
    }


def _enrich_alert(alert: Dict[str, Any], event: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Attach MITRE info, risk score, explainability, and decay data to an alert."""
    alert_type = alert.get("type", "")
    mitre = MITRE_TACTICS.get(alert_type, {"tactic": "Unknown", "technique": "N/A"})
    alert["mitre_tactic"]     = mitre["tactic"]
    alert["mitre_technique"]  = mitre["technique"]

    base_score = RISK_SCORES.get(alert.get("severity", "LOW"), 15)
    entity = alert.get("entity_ip") or alert.get("entity_user") or "global"

    # Confidence decay
    decay_info = _compute_decayed_score(base_score, alert_type, entity)
    alert["risk_score"]          = base_score
    alert["decayed_risk_score"]  = decay_info["decayed_score"]
    alert["decay_pct"]           = decay_info["decay_pct"]
    alert["decay_explanation"]   = decay_info["decay_explanation"]

    # Explainability
    alert["explanation"] = _build_explanation(
        alert_type, event or {}, {"severity": alert.get("severity", "LOW")}
    )

    return alert


def _parse_hour(timestamp: str) -> int | None:
    """Extract the hour from timestamps like 'Jan 27 11:00:01'."""
    try:
        parts = timestamp.strip().split()
        time_part = parts[2]
        return int(time_part.split(":")[0])
    except (IndexError, ValueError):
        return None


def analyze_event(event: Dict[str, Any], simulation_mode: bool = False) -> List[Dict[str, Any]]:
    """
    Analyze a single normalized event against all detection rules.

    Args:
        event: normalized event dict from the parser
        simulation_mode: if True, run rules without modifying any state
                         (used by the What-If Simulator)

    Returns:
        list of enriched alert dicts
    """
    alerts = []

    # ── Make copies of state for simulation to avoid side effects ────────────
    if simulation_mode:
        sim_failed = dict(failed_attempts)
        sim_baseline = {u: set(ips) for u, ips in user_ip_baseline.items()}
    else:
        sim_failed = failed_attempts
        sim_baseline = user_ip_baseline

    if event["event_type"] == "FAILED_LOGIN":
        if not simulation_mode:
            failed_attempts[event["ip"]] += 1
        else:
            sim_failed[event["ip"]] = sim_failed.get(event["ip"], 0) + 1

        count = sim_failed.get(event["ip"], failed_attempts[event["ip"]])
        if count >= 3:
            alerts.append(_enrich_alert({
                "type":      "BRUTE_FORCE",
                "message":   f"Multiple failed logins from {event['ip']}",
                "severity":  "HIGH",
                "entity_ip": event["ip"],
            }, event))

    if event["event_type"] == "SUCCESS_LOGIN":
        count = sim_failed.get(event["ip"], failed_attempts.get(event["ip"], 0))
        if count >= 3:
            alerts.append(_enrich_alert({
                "type":      "COMPROMISED_ACCOUNT",
                "message":   f"Successful login after failures from {event['ip']}",
                "severity":  "CRITICAL",
                "entity_ip": event["ip"],
            }, event))

        user = event.get("username")
        ip   = event.get("ip")
        if user and ip:
            known_ips = sim_baseline.get(user, user_ip_baseline.get(user, set()))
            if known_ips and ip not in known_ips:
                alerts.append(_enrich_alert({
                    "type":        "NEW_IP_FOR_USER",
                    "message":     f"User {user} logged in from new IP {ip} (previously seen: {', '.join(sorted(known_ips))})",
                    "severity":    "MEDIUM",
                    "entity_user": user,
                    "entity_ip":   ip,
                }, event))
            if not simulation_mode:
                user_ip_baseline[user].add(ip)

        ts   = event.get("timestamp", "")
        hour = _parse_hour(ts) if ts else None
        if hour is not None and not (BUSINESS_HOURS[0] <= hour < BUSINESS_HOURS[1]):
            alerts.append(_enrich_alert({
                "type":        "AFTER_HOURS_LOGIN",
                "message":     f"Login by {event.get('username', 'unknown')} from {ip} at hour {hour:02d}:xx (outside business hours)",
                "severity":    "MEDIUM",
                "entity_user": event.get("username"),
                "entity_ip":   ip,
            }, event))

    if event["event_type"] == "SUDO_USAGE":
        alerts.append(_enrich_alert({
            "type":        "PRIV_ESC",
            "message":     f"Sudo used by {event['username']}",
            "severity":    "HIGH",
            "entity_user": event["username"],
        }, event))

    if event["event_type"] == "SUCCESS_LOGIN" and event["username"] == "root":
        alerts.append(_enrich_alert({
            "type":      "ROOT_LOGIN",
            "message":   f"Root login detected from {event['ip']}",
            "severity":  "CRITICAL",
            "entity_ip": event["ip"],
        }, event))

    return alerts
