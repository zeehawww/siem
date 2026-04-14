"""
Entity Reputation Heat Score Engine
=====================================
Novel Feature #4 (P1): Builds a persistent, internal reputation score for
each network entity (IP or user) based solely on the SIEM's own observed
alert history — not external threat intelligence feeds.

Unlike commercial SIEMs that rely on paid TI lookups, this system derives
reputation organically from behavioral evidence, accumulating across pipeline
runs.

Patent angle: "Internal behavioral reputation scoring system for network
entities using historical alert telemetry without external threat intelligence
dependencies."
"""

import json
import os
from datetime import datetime, timezone
from collections import defaultdict

REPUTATION_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "storage", "reputation.json"
)

# Score weights per alert type severity
_SEVERITY_WEIGHT = {
    "LOW":      5,
    "MEDIUM":   15,
    "HIGH":     30,
    "CRITICAL": 50,
}

# Score weights per alert type (bonus on top of severity weight)
_TYPE_WEIGHT = {
    "BRUTE_FORCE":         10,
    "COMPROMISED_ACCOUNT": 25,
    "NEW_IP_FOR_USER":     10,
    "PRIV_ESC":            15,
    "ROOT_LOGIN":          30,
    "AFTER_HOURS_LOGIN":   8,
}

# Decay factor per pipeline run (score * decay = new score for quiet entities)
DECAY_FACTOR = 0.85
MAX_SCORE    = 1000


def _load_reputation() -> dict:
    if not os.path.exists(REPUTATION_FILE):
        return {}
    try:
        with open(REPUTATION_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_reputation(rep: dict) -> None:
    os.makedirs(os.path.dirname(REPUTATION_FILE), exist_ok=True)
    with open(REPUTATION_FILE, "w") as f:
        json.dump(rep, f, indent=2)


def update_reputation(alerts: list[dict]) -> dict:
    """
    Update reputation scores for all entities involved in alerts.
    Applies decay to ALL existing entities even if not seen this run.
    Returns the full updated reputation dict.
    """
    rep = _load_reputation()
    now = datetime.now(timezone.utc).isoformat()

    # 1. Apply decay to all existing entities (quiet = less suspicious over time)
    for entity in rep:
        rep[entity]["score"] = max(0, rep[entity]["score"] * DECAY_FACTOR)
        rep[entity]["runs_since_last_alert"] = rep[entity].get("runs_since_last_alert", 0) + 1

    # 2. Accumulate scores for entities seen this run
    seen_this_run = defaultdict(float)
    entity_meta   = {}

    for a in alerts:
        ev   = a.get("event") or {}
        ip   = ev.get("ip")
        user = ev.get("username")
        sev  = a.get("severity", "LOW")
        atype = a.get("type", "")

        score_delta = _SEVERITY_WEIGHT.get(sev, 0) + _TYPE_WEIGHT.get(atype, 0)

        for entity, kind in [(ip, "ip"), (user, "user")]:
            if entity and entity not in ("", "None", None):
                seen_this_run[entity] += score_delta
                if entity not in entity_meta:
                    entity_meta[entity] = {"kind": kind}
                # Track highest alert type for labelling
                if "worst_type" not in entity_meta[entity]:
                    entity_meta[entity]["worst_type"] = atype
                    entity_meta[entity]["worst_sev"] = sev

    # 3. Write back accumulated scores
    for entity, delta in seen_this_run.items():
        if entity not in rep:
            rep[entity] = {
                "score": 0,
                "first_seen": now,
                "alert_count": 0,
                "kind": entity_meta[entity].get("kind", "unknown"),
                "worst_type": "",
                "worst_severity": "LOW",
                "runs_since_last_alert": 0,
            }

        rep[entity]["score"] = min(MAX_SCORE, rep[entity]["score"] + delta)
        rep[entity]["alert_count"] = rep[entity].get("alert_count", 0) + 1
        rep[entity]["last_seen"]   = now
        rep[entity]["runs_since_last_alert"] = 0

        meta = entity_meta.get(entity, {})
        # Update worst type if new alert is more severe
        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if sev_order.get(meta.get("worst_sev", "LOW"), 0) >= sev_order.get(
            rep[entity].get("worst_severity", "LOW"), 0
        ):
            rep[entity]["worst_type"]     = meta.get("worst_type", rep[entity]["worst_type"])
            rep[entity]["worst_severity"] = meta.get("worst_sev", rep[entity]["worst_severity"])

    _save_reputation(rep)
    return rep


def get_reputation() -> list[dict]:
    """
    Return reputation entries sorted by score descending, with heat labels.
    """
    rep = _load_reputation()

    def _heat_label(score: float) -> str:
        if score >= 200: return "CRITICAL"
        if score >= 100: return "HIGH"
        if score >= 40:  return "MEDIUM"
        return "LOW"

    result = []
    for entity, data in rep.items():
        score = data.get("score", 0)
        result.append({
            "entity":        entity,
            "kind":          data.get("kind", "unknown"),
            "score":         round(score),
            "heat":          _heat_label(score),
            "alert_count":   data.get("alert_count", 0),
            "first_seen":    data.get("first_seen", ""),
            "last_seen":     data.get("last_seen", ""),
            "worst_type":    data.get("worst_type", ""),
            "worst_severity":data.get("worst_severity", "LOW"),
            "runs_quiet":    data.get("runs_since_last_alert", 0),
        })

    result.sort(key=lambda x: -x["score"])
    return result
