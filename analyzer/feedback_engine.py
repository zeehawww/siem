"""
Analyst Feedback Loop Engine
==============================
Novel Feature #7 (P3): Allows analysts to mark alerts as True Positive,
False Positive, or Needs Investigation. Feedback is stored persistently and
used to adjust confidence (effective risk score) of future similar alerts
(same DNA fingerprint) WITHOUT any machine learning retraining cycle.

This is patent-novel because rule-based SIEMs have no self-adjusting
confidence mechanism. ML SIEMs require full retraining pipelines.

Patent angle: "Rule-based alert confidence calibration system using analyst
feedback without machine learning retraining."
"""

import json
import os
from datetime import datetime, timezone

FEEDBACK_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "storage", "feedback.json"
)

# Confidence modifier applied to risk_score of future alerts with same DNA
_FEEDBACK_MODIFIERS = {
    "TRUE_POSITIVE":       +10,   # confirmed real threat → boost confidence
    "FALSE_POSITIVE":      -20,   # analyst rejected → reduce confidence
    "NEEDS_INVESTIGATION": +2,    # uncertain → slight boost
}

_VERDICT_LABELS = {
    "TRUE_POSITIVE":       "✅ Confirmed Threat",
    "FALSE_POSITIVE":      "❌ False Positive",
    "NEEDS_INVESTIGATION": "🔍 Under Investigation",
}


def _load_feedback() -> dict:
    if not os.path.exists(FEEDBACK_FILE):
        return {}
    try:
        with open(FEEDBACK_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_feedback(fb: dict) -> None:
    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    with open(FEEDBACK_FILE, "w") as f:
        json.dump(fb, f, indent=2)


def record_feedback(alert_id: str, dna: str, verdict: str, analyst: str = "analyst") -> bool:
    """
    Record an analyst verdict for an alert.
    alert_id: unique alert identifier (e.g. "1", "2")
    dna: the DNA fingerprint of the alert being judged
    verdict: one of TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_INVESTIGATION
    """
    if verdict not in _FEEDBACK_MODIFIERS:
        return False

    fb = _load_feedback()
    now = datetime.now(timezone.utc).isoformat()

    # Per-alert entry
    if alert_id not in fb:
        fb[alert_id] = {"verdicts": [], "dna": dna}
    fb[alert_id]["verdicts"].append({
        "verdict":   verdict,
        "analyst":   analyst,
        "timestamp": now,
    })
    fb[alert_id]["latest_verdict"] = verdict
    fb[alert_id]["latest_ts"]      = now

    # Per-DNA aggregate (used for confidence calibration)
    dna_key = f"dna_{dna}"
    if dna_key not in fb:
        fb[dna_key] = {"tp": 0, "fp": 0, "ni": 0, "net_modifier": 0}
    if verdict == "TRUE_POSITIVE":
        fb[dna_key]["tp"] += 1
    elif verdict == "FALSE_POSITIVE":
        fb[dna_key]["fp"] += 1
    else:
        fb[dna_key]["ni"] += 1
    fb[dna_key]["net_modifier"] = (
        fb[dna_key]["tp"] * _FEEDBACK_MODIFIERS["TRUE_POSITIVE"]
        + fb[dna_key]["fp"] * _FEEDBACK_MODIFIERS["FALSE_POSITIVE"]
        + fb[dna_key]["ni"] * _FEEDBACK_MODIFIERS["NEEDS_INVESTIGATION"]
    )

    _save_feedback(fb)
    return True


def get_confidence_modifier(dna: str) -> int:
    """
    Return the cumulative confidence modifier for a given DNA pattern,
    based on all historical analyst feedback.
    """
    fb = _load_feedback()
    dna_key = f"dna_{dna}"
    return fb.get(dna_key, {}).get("net_modifier", 0)


def apply_feedback_to_alerts(alerts: list[dict]) -> list[dict]:
    """
    Apply stored analyst feedback modifiers to alert risk scores.
    Clamps effective_risk_score to [0, 100].
    """
    fb = _load_feedback()
    out = []
    for a in alerts:
        dna = a.get("dna", "")
        modifier = fb.get(f"dna_{dna}", {}).get("net_modifier", 0)
        alert_id = str(a.get("id", ""))
        verdict_info = fb.get(alert_id, {})
        latest = verdict_info.get("latest_verdict", None)

        effective = max(0, min(100, a.get("risk_score", 0) + modifier))
        out.append({
            **a,
            "effective_risk_score": effective,
            "confidence_modifier":  modifier,
            "analyst_verdict":      latest,
            "verdict_label":        _VERDICT_LABELS.get(latest, "Unreviewed"),
        })
    return out


def get_all_feedback() -> dict:
    return _load_feedback()


def get_verdict_label(verdict: str) -> str:
    return _VERDICT_LABELS.get(verdict, "Unreviewed")
