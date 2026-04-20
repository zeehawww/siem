"""
ATRS — Adaptive Threat Risk Score Engine
=========================================
Novel multi-dimensional entity risk scoring algorithm (patent-grade).

Fuses five independent behavioral signals for each observed entity:
  V — Attack Velocity Score       (events/hour vs. learned quiet baseline)
  E — Behavioral Entropy Score    (Shannon entropy of event-type distribution)
  R — Entity Reputation Score     (accumulated historical threat weight)
  T — Temporal Anomaly Score      (off-hours / scheduling deviation)
  P — Markov Prediction Score     (probability of next threat step)

Adjustments applied after weighted fusion:
  ① Exponential time-decay        (stale threats fade automatically)
  ② Analyst feedback modifier     (FALSE_POSITIVE suppresses; TRUE_POSITIVE amplifies)
  ③ DNA cluster amplification     (entities in critical-pattern clusters score higher)

Formula:
  ATRS_raw = 0.25·V + 0.20·E + 0.25·R + 0.15·T + 0.15·P
  ATRS_adj = ATRS_raw × decay(hours) × feedback_mod × cluster_boost
  ATRS     = clamp(ATRS_adj, 0, 100)

Each component is individually readable → full explainability / auditability.
"""

from __future__ import annotations

import math
import os
import json
from datetime import datetime, timezone

# ── Weight constants ──────────────────────────────────────────────────────────
W_VELOCITY    = 0.25
W_ENTROPY     = 0.20
W_REPUTATION  = 0.25
W_TEMPORAL    = 0.15
W_PREDICTION  = 0.15

# Decay rate λ: score halves if entity is silent for ~14 hours
DECAY_LAMBDA  = 0.05

# Feedback modifiers
FB_TRUE_POS   = 1.20   # confirmed threat → amplify
FB_FALSE_POS  = 0.50   # analyst dismissed → suppress hard
FB_INVESTIG   = 1.05   # under review → slight nudge

# DNA cluster boost for HIGH / CRITICAL pattern groups
CLUSTER_BOOST = 1.15

# Risk bands
RISK_BANDS = [
    (85, "CRITICAL", "#ef4444"),
    (65, "HIGH",     "#f97316"),
    (40, "MEDIUM",   "#eab308"),
    (0,  "LOW",      "#22c55e"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _decay(hours_silent: float) -> float:
    """Exponential decay: f(t) = e^(-λt). Caps at 1.0 for very recent events."""
    return math.exp(-DECAY_LAMBDA * max(hours_silent, 0.0))


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _risk_band(score: float) -> tuple[str, str]:
    for threshold, label, color in RISK_BANDS:
        if score >= threshold:
            return label, color
    return "LOW", "#22c55e"


def _hours_since(iso_ts: str | None) -> float:
    """Return hours elapsed since an ISO-8601 timestamp. Returns 72 if unknown."""
    if not iso_ts:
        return 72.0
    try:
        ts = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        delta = (now - ts).total_seconds() / 3600
        return max(0.0, delta)
    except (ValueError, TypeError):
        return 72.0


# ── Component scorers ─────────────────────────────────────────────────────────

def _velocity_score(entity: str, velocity_data: dict) -> float:
    """
    velocity_data[entity] = {"velocity_score": int (0-100), "profile": str, ...}
    The score is already normalised by the velocity engine.
    """
    profile = velocity_data.get(entity, {})
    return _clamp(float(profile.get("velocity_score", 0.0)))


def _entropy_score(entity: str, entropy_data: dict) -> float:
    """
    entropy_data[entity] = {"entropy": float (0.0–3.0+), ...}
    High entropy = unpredictable behaviour = more suspicious.
    Normalise to 0-100 with a cap at entropy=3.0.
    """
    profile = entropy_data.get(entity, {})
    entropy = float(profile.get("entropy", 0.0))
    return _clamp(entropy / 3.0 * 100)


def _reputation_score(entity: str, reputation_data: list) -> float:
    """
    reputation_data is a list of {'entity', 'score', 'heat', 'last_seen', ...}.
    'score' is a cumulative unbounded value; normalise against a cap of 500.
    """
    for item in reputation_data:
        if item.get("entity") == entity:
            raw = float(item.get("score", 0))
            return _clamp(raw / 500.0 * 100)
    return 0.0


def _temporal_score(entity: str, tbf_data: dict) -> float:
    """
    Temporal Behavioural Fingerprint: measures deviation from the entity's
    learned hourly activity pattern.
    tbf_data[entity] = {"anomaly_score": float (0-100), ...}
    """
    profile = tbf_data.get(entity, {})
    return _clamp(float(profile.get("anomaly_score", 0.0)))


def _prediction_score(entity: str, predictions: dict) -> float:
    """
    predictions[entity] = {
        "predictions": [{"next_type": str, "probability": float, ...}, ...],
        "risk_label": str, ...
    }
    Take the top prediction probability and amplify if it is a high-risk step.
    """
    profile = predictions.get(entity, {})
    plist   = profile.get("predictions", [])
    if not plist:
        return 0.0
    top         = plist[0]
    probability = float(top.get("probability", 0.0))
    next_type   = top.get("next_type", "").upper()
    high_risk   = {"PRIV_ESC", "ROOT_LOGIN", "COMPROMISED_ACCOUNT", "LATERAL_MOVE"}
    amplifier   = 1.3 if next_type in high_risk else 1.0
    return _clamp(probability * 100 * amplifier)


def _feedback_modifier(entity: str, feedback_data: list) -> float:
    """
    feedback_data: list of {'entity', 'verdict', ...} from feedback_engine.
    Most-recent verdict for the entity wins.
    """
    matches = [f for f in feedback_data if f.get("entity") == entity]
    if not matches:
        return 1.0
    # Take the most recent verdict
    latest = matches[-1].get("verdict", "")
    if latest == "TRUE_POSITIVE":
        return FB_TRUE_POS
    if latest == "FALSE_POSITIVE":
        return FB_FALSE_POS
    if latest == "NEEDS_INVESTIGATION":
        return FB_INVESTIG
    return 1.0


def _cluster_boost(entity: str, alerts: list) -> float:
    """
    If the entity appears in a HIGH or CRITICAL DNA cluster, boost the score.
    alerts: full alert list with 'dna' and 'severity' fields.
    """
    entity_alerts = [
        a for a in alerts
        if a.get("entity_ip") == entity or a.get("entity_user") == entity
        or a.get("username") == entity or a.get("ip") == entity
    ]
    if any(a.get("severity") in ("HIGH", "CRITICAL") for a in entity_alerts):
        return CLUSTER_BOOST
    return 1.0


# ── Main public API ───────────────────────────────────────────────────────────

def compute_atrs_for_entity(
    entity: str,
    velocity_data: dict,
    entropy_data: dict,
    reputation_data: list,
    tbf_data: dict,
    predictions: dict,
    alerts: list,
    feedback_data: list,
) -> dict:
    """
    Compute a full ATRS record for a single entity.

    Returns a dict with:
      entity, atrs_score, risk_label, color,
      components: {V, E, R, T, P},
      modifiers:  {decay, feedback_mod, cluster_boost},
      explanation: human-readable breakdown
    """
    V = _velocity_score(entity, velocity_data)
    E = _entropy_score(entity, entropy_data)
    R = _reputation_score(entity, reputation_data)
    T = _temporal_score(entity, tbf_data)
    P = _prediction_score(entity, predictions)

    raw = (
        W_VELOCITY   * V +
        W_ENTROPY    * E +
        W_REPUTATION * R +
        W_TEMPORAL   * T +
        W_PREDICTION * P
    )

    # Last-seen timestamp: pull from reputation or velocity data
    last_seen = (
        next((item.get("last_seen") for item in reputation_data if item.get("entity") == entity), None)
        or velocity_data.get(entity, {}).get("last_seen")
    )
    hours = _hours_since(last_seen)
    decay  = _decay(hours)
    fb_mod = _feedback_modifier(entity, feedback_data)
    cb     = _cluster_boost(entity, alerts)

    final = _clamp(raw * decay * fb_mod * cb)
    label, color = _risk_band(final)

    return {
        "entity":       entity,
        "atrs_score":   round(final, 1),
        "risk_label":   label,
        "color":        color,
        "last_seen":    last_seen,
        "hours_silent": round(hours, 1),
        "components": {
            "V": round(V, 1),
            "E": round(E, 1),
            "R": round(R, 1),
            "T": round(T, 1),
            "P": round(P, 1),
        },
        "modifiers": {
            "decay":        round(decay, 3),
            "feedback_mod": round(fb_mod, 2),
            "cluster_boost": round(cb, 2),
        },
        "explanation": _build_explanation(entity, V, E, R, T, P, decay, fb_mod, cb, final),
    }


def _build_explanation(entity, V, E, R, T, P, decay, fb_mod, cb, final) -> str:
    """Plain-English explanation of the ATRS score — auditability for analysts."""
    parts = []
    if V >= 60:
        parts.append(f"high attack velocity ({V:.0f}/100)")
    if E >= 60:
        parts.append(f"unpredictable behavioural entropy ({E:.0f}/100)")
    if R >= 60:
        parts.append(f"accumulated bad reputation ({R:.0f}/100)")
    if T >= 60:
        parts.append(f"off-hours activity anomaly ({T:.0f}/100)")
    if P >= 60:
        parts.append(f"Markov prediction of next threat step ({P:.0f}/100)")
    if not parts:
        parts.append("low-level activity across all dimensions")

    modifiers = []
    if decay < 0.8:
        modifiers.append(f"time-decayed (entity silent for {-math.log(decay)/DECAY_LAMBDA:.0f}h)")
    if fb_mod == FB_FALSE_POS:
        modifiers.append("suppressed by analyst (FALSE_POSITIVE verdict)")
    if fb_mod == FB_TRUE_POS:
        modifiers.append("amplified by analyst (TRUE_POSITIVE verdict)")
    if cb > 1.0:
        modifiers.append("co-clustered with HIGH/CRITICAL DNA pattern")

    explanation = f"Score driven by: {'; '.join(parts)}."
    if modifiers:
        explanation += f" Modifiers: {'; '.join(modifiers)}."
    return explanation


def compute_all_atrs(
    velocity_data: dict,
    entropy_data: dict,
    reputation_data: list,
    tbf_data: dict,
    predictions: dict,
    alerts: list,
    feedback_data: list,
) -> list[dict]:
    """
    Compute ATRS for every known entity across all data sources.
    Returns a list sorted by atrs_score descending.
    """
    # Collect all known entities
    entities: set[str] = set()
    entities.update(velocity_data.keys())
    entities.update(entropy_data.keys())
    entities.update(predictions.keys())
    entities.update(tbf_data.keys())
    for item in reputation_data:
        if item.get("entity"):
            entities.add(item["entity"])

    results = []
    for ent in entities:
        if not ent or ent.lower() in ("unknown", "none", ""):
            continue
        record = compute_atrs_for_entity(
            ent, velocity_data, entropy_data, reputation_data,
            tbf_data, predictions, alerts, feedback_data,
        )
        results.append(record)

    results.sort(key=lambda r: r["atrs_score"], reverse=True)
    return results
