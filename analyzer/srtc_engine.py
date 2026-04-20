"""
SRTC Engine — Sequence Resonance Threat Coefficient
===================================================
Original SIEM scoring method designed for this project.

Core idea:
Threats are not just "which events happened", but "how their sequence repeats
and how machine-like the timing is". SRTC combines three dimensions:

1) Sequence Motif Resonance (SMR)
   - Detects risky 3-event motifs (e.g. FAILED->FAILED->SUCCESS).
   - Measures how densely these motifs appear in an entity timeline.

2) Temporal Rhythm Regularity (TRR)
   - Measures interval regularity between consecutive events.
   - Highly regular short intervals suggest automation/scripted behavior.

3) Transition Surprise Divergence (TSD)
   - Builds per-entity transition probabilities and compares them against
     a global baseline transition graph from all entities.
   - Large divergence => behavior differs from environment baseline.

Final score (0-100):
  SRTC = 100 * (0.45*SMR + 0.25*TRR + 0.30*TSD)
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


_RISKY_MOTIFS = {
    ("FAILED_LOGIN", "FAILED_LOGIN", "SUCCESS_LOGIN"),
    ("FAILED_LOGIN", "FAILED_LOGIN", "FAILED_LOGIN"),
    ("SUCCESS_LOGIN", "SUDO_USAGE", "SUDO_USAGE"),
    ("SUCCESS_LOGIN", "SUDO_USAGE", "SUCCESS_LOGIN"),
    ("SUCCESS_LOGIN", "SUCCESS_LOGIN", "SUDO_USAGE"),
}


def _parse_ts(ts: str) -> Optional[float]:
    """Parse common timestamps used in this project."""
    if not ts:
        return None
    candidates = (
        "%b %d %H:%M:%S",      # Jan 27 10:22:01
        "%Y-%m-%dT%H:%M:%S",   # ISO-like
        "%Y-%m-%d %H:%M:%S",
    )
    s = ts.strip()[:19]
    for fmt in candidates:
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return None


def _entity_key(event: Dict[str, Any]) -> Optional[str]:
    """Use IP when available, else username."""
    ip = event.get("ip")
    if ip and ip not in ("", "0.0.0.0", "None"):
        return ip
    user = event.get("username")
    if user and user not in ("", "None"):
        return user
    return None


def _motif_resonance(event_types: List[str]) -> float:
    """Density of risky trigrams in sequence."""
    if len(event_types) < 3:
        return 0.0
    total = len(event_types) - 2
    risky = 0
    for i in range(total):
        tri = (event_types[i], event_types[i + 1], event_types[i + 2])
        if tri in _RISKY_MOTIFS:
            risky += 1
    return risky / total if total else 0.0


def _rhythm_regularity(timestamps: List[float]) -> float:
    """
    Bot-likeness score from interval regularity.
    High if intervals are short and consistent.
    """
    if len(timestamps) < 3:
        return 0.0

    intervals = []
    for i in range(1, len(timestamps)):
        dt = max(0.0, timestamps[i] - timestamps[i - 1])
        intervals.append(dt)

    mean_dt = sum(intervals) / len(intervals)
    if mean_dt <= 0:
        return 1.0

    var = sum((x - mean_dt) ** 2 for x in intervals) / len(intervals)
    std = math.sqrt(var)
    cv = std / mean_dt  # coefficient of variation

    # Regularity: low CV = high regularity
    regularity = max(0.0, 1.0 - min(cv, 1.0))
    # Burstiness: shorter mean interval => more suspicious
    burst = max(0.0, 1.0 - min(mean_dt / 60.0, 1.0))  # 0 if >= 60s
    return 0.6 * regularity + 0.4 * burst


def _transition_probs(event_types: List[str]) -> Dict[Tuple[str, str], float]:
    if len(event_types) < 2:
        return {}
    pair_counts = Counter()
    from_counts = Counter()
    for i in range(len(event_types) - 1):
        a = event_types[i]
        b = event_types[i + 1]
        pair_counts[(a, b)] += 1
        from_counts[a] += 1
    probs = {}
    for (a, b), c in pair_counts.items():
        probs[(a, b)] = c / from_counts[a]
    return probs


def _transition_surprise(entity_probs: Dict[Tuple[str, str], float],
                         baseline_probs: Dict[Tuple[str, str], float]) -> float:
    """L1 divergence between entity transitions and baseline transitions."""
    keys = set(entity_probs.keys()) | set(baseline_probs.keys())
    if not keys:
        return 0.0
    l1 = sum(abs(entity_probs.get(k, 0.0) - baseline_probs.get(k, 0.0)) for k in keys)
    # Normalize rough bound to 0..1 (L1 max in this context can exceed 1; clamp)
    return min(1.0, l1 / 2.0)


def compute_srtc_scores(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Compute SRTC per entity.
    Returns:
      { entity: {srtc_score, label, smr, trr, tsd, event_count, last_event_type} }
    """
    by_entity = defaultdict(list)
    for e in events:
        ent = _entity_key(e)
        if ent:
            by_entity[ent].append(e)

    # Build global baseline from all events
    global_types = []
    for evs in by_entity.values():
        ordered = sorted(evs, key=lambda x: x.get("timestamp", ""))
        global_types.extend([x.get("event_type", "UNKNOWN") for x in ordered])
    baseline_probs = _transition_probs(global_types)

    out = {}
    for entity, evs in by_entity.items():
        ordered = sorted(evs, key=lambda x: x.get("timestamp", ""))
        types = [x.get("event_type", "UNKNOWN") for x in ordered]
        ts_vals = [t for t in (_parse_ts(x.get("timestamp", "")) for x in ordered) if t is not None]

        smr = _motif_resonance(types)
        trr = _rhythm_regularity(ts_vals) if len(ts_vals) >= 3 else 0.0
        entity_probs = _transition_probs(types)
        tsd = _transition_surprise(entity_probs, baseline_probs)

        score = round(100 * (0.45 * smr + 0.25 * trr + 0.30 * tsd), 1)
        if score >= 75:
            label = "CRITICAL"
        elif score >= 55:
            label = "HIGH"
        elif score >= 35:
            label = "MEDIUM"
        else:
            label = "LOW"

        out[entity] = {
            "entity": entity,
            "srtc_score": score,
            "label": label,
            "smr": round(smr, 3),
            "trr": round(trr, 3),
            "tsd": round(tsd, 3),
            "event_count": len(types),
            "last_event_type": types[-1] if types else None,
            "formula": "100*(0.45*SMR + 0.25*TRR + 0.30*TSD)",
        }

    return out

