"""
Threat Narrative Engine
=======================
Novel Feature #1 (P0): Synthesizes a plain-English "attack story" from a
sequence of correlated alerts, grouped by attacking entity (IP or user).

No SIEM today automatically writes human-readable narratives — analysts do
this manually in incident reports. This engine does it programmatically.

Patent angle: "System for automatic natural-language attack narrative
synthesis from correlated security event sequences."
"""

from collections import defaultdict
from datetime import datetime
from typing import Optional, List, Dict, Any


# ── Human-readable descriptions for each alert type ──────────────────────────
_TYPE_PHRASES = {
    "BRUTE_FORCE":         "launched a brute-force campaign",
    "COMPROMISED_ACCOUNT": "successfully gained unauthorized access after repeated failures",
    "NEW_IP_FOR_USER":     "authenticated from a previously unseen IP address (lateral movement indicator)",
    "PRIV_ESC":            "escalated privileges via sudo",
    "ROOT_LOGIN":          "logged in directly as root",
    "AFTER_HOURS_LOGIN":   "authenticated outside of business hours",
}

# MITRE chain descriptions
_CHAIN_DESCRIPTIONS = {
    ("BRUTE_FORCE", "COMPROMISED_ACCOUNT"):            "Classic credential attack: brute-force → account compromise",
    ("COMPROMISED_ACCOUNT", "PRIV_ESC"):               "Post-compromise escalation: account takeover → privilege escalation",
    ("BRUTE_FORCE", "COMPROMISED_ACCOUNT", "PRIV_ESC"):"Full attack chain: credential access → initial access → privilege escalation",
    ("ROOT_LOGIN", "PRIV_ESC"):                        "High-privilege activity: root login paired with sudo escalation",
    ("NEW_IP_FOR_USER", "PRIV_ESC"):                   "Suspicious lateral movement followed by privilege escalation",
    ("AFTER_HOURS_LOGIN", "PRIV_ESC"):                 "After-hours login with immediate privilege escalation — insider threat indicator",
}

_SEVERITY_EMOJI = {
    "LOW":      "🟢",
    "MEDIUM":   "🟡",
    "HIGH":     "🟠",
    "CRITICAL": "🔴",
}


def _fmt_time(ts: str) -> str:
    """Return a short human-readable time string from raw timestamps."""
    if not ts:
        return "unknown time"
    parts = ts.strip().split()
    if len(parts) >= 3:
        return f"{parts[0]} {parts[1]} at {parts[2]}"
    return ts.strip()


def _detect_chain(type_sequence: list[str]) -> str | None:
    """Match known multi-stage attack chain patterns."""
    seq = tuple(type_sequence)
    # Exact match
    if seq in _CHAIN_DESCRIPTIONS:
        return _CHAIN_DESCRIPTIONS[seq]
    # Subset match (any known chain is a prefix/sub-sequence)
    for chain, desc in _CHAIN_DESCRIPTIONS.items():
        if all(t in seq for t in chain):
            return desc
    return None


def generate_narratives(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group alerts by attacking entity (IP or user) and generate a narrative
    paragraph for each group.

    Returns a list of narrative dicts:
        {
          "entity":    str,          # IP or username
          "kind":      "ip"|"user",
          "severity":  str,          # max severity in group
          "risk_score": int,         # max risk score
          "sentences": list[str],    # individual narrative sentences
          "chain":     str|None,     # detected MITRE chain description
          "mitre_techniques": list,  # unique techniques involved
          "summary":   str,          # one-line executive summary
          "alert_count": int,
        }
    """
    # Group alerts by primary entity
    by_entity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    entity_kind: Dict[str, str] = {}

    for a in alerts:
        ip   = a.get("event", {}).get("ip") if a.get("event") else None
        user = a.get("event", {}).get("username") if a.get("event") else None

        # Determine grouping entity — prefer IP for network attacks
        if ip and ip not in ("", "None"):
            key = ip
            entity_kind[key] = "ip"
        elif user:
            key = user
            entity_kind[key] = "user"
        else:
            key = "unknown"
            entity_kind[key] = "unknown"

        by_entity[key].append(a)

    narratives = []

    for entity, group in by_entity.items():
        if entity == "unknown":
            continue

        # Sort by timestamp of underlying event
        def _ts(a):
            ev = a.get("event") or {}
            return ev.get("timestamp") or ""
        group.sort(key=_ts)

        sentences = []
        seen_types = []
        max_severity = "LOW"
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        max_risk = 0
        techniques = []

        for a in group:
            atype    = a.get("type", "UNKNOWN")
            sev      = a.get("severity", "LOW")
            msg      = a.get("message", "")
            ts       = _fmt_time((a.get("event") or {}).get("timestamp", ""))
            emoji    = _SEVERITY_EMOJI.get(sev, "⚪")
            tech     = a.get("mitre_technique")
            tactic   = a.get("mitre_tactic", "")
            risk     = a.get("risk_score", 0)
            count    = a.get("count", 1)

            if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                max_severity = sev
            if risk > max_risk:
                max_risk = risk
            if tech and tech not in techniques:
                techniques.append(tech)

            phrase = _TYPE_PHRASES.get(atype, f"triggered a {atype.lower().replace('_', ' ')} event")
            count_str = f" ({count} occurrences)" if count > 1 else ""
            tactic_str = f" [{tactic} — {tech}]" if tactic and tactic != "Unknown" else ""

            sentences.append(
                f"{emoji} At {ts}, this entity {phrase}{count_str}{tactic_str}."
            )
            seen_types.append(atype)

        chain = _detect_chain(seen_types)

        # Build executive summary
        kind_label = "IP address" if entity_kind[entity] == "ip" else "user account"
        total = len(group)
        summary = (
            f"The {kind_label} **{entity}** was involved in {total} security event(s) "
            f"reaching a maximum severity of **{max_severity}**"
        )
        if chain:
            summary += f". Attack pattern: {chain}"
        summary += "."

        narratives.append({
            "entity":           entity,
            "kind":             entity_kind.get(entity, "unknown"),
            "severity":         max_severity,
            "risk_score":       max_risk,
            "sentences":        sentences,
            "chain":            chain,
            "mitre_techniques": techniques,
            "summary":          summary,
            "alert_count":      len(group),
        })

    # Sort by severity desc, then risk score
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    narratives.sort(key=lambda n: (sev_order.get(n["severity"], 4), -n["risk_score"]))
    return narratives
