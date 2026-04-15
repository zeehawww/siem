"""
Behavioral Entropy Anomaly Detection (BEAD) Engine
====================================================
Novel Feature: Computes Shannon entropy of every entity's event-type
distribution across its full observed history.

Normal users have LOW, predictable entropy — they mostly do one or two
event types (e.g. always SUCCESS_LOGIN). Compromised or anomalous accounts
show sudden ENTROPY SPIKES as an attacker performs many unfamiliar action
types in rapid succession.

  H(X) = −Σ p(xᵢ) · log₂(p(xᵢ))

This is the first application of information-theoretic entropy to per-entity
behavioral scoring in a rule-based SIEM context.

Patent: "Information-theoretic behavioral baseline monitoring using Shannon
entropy for compromised account detection in authentication event streams."
"""

import math
from collections import Counter, defaultdict
from typing import Any, Dict, List


# Maximum theoretical entropy with the 7 defined event types ≈ log₂(7) = 2.807 bits
_MAX_ENTROPY = math.log2(7)


def _shannon_entropy(counts: Dict[str, int]) -> float:
    """Compute Shannon entropy in bits from an event-type frequency counter."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )


def compute_entropy_scores(events: List[Dict[str, Any]]) -> Dict[str, Dict]:
    """
    Compute behavioral entropy for every observed entity from the event log.

    Returns a dict keyed by entity (IP or username):
        {
          "<entity>": {
            "entity":        str,
            "entropy":       float,   # Shannon entropy in bits
            "entropy_label": str,     # NORMAL | MODERATE | ELEVATED | ANOMALOUS
            "event_dist":    dict,    # event_type → count
            "dominant_type": str,     # most frequent event type
            "event_count":   int,
            "entropy_pct":   int,     # 0–100 bar-chart percentage
          }
        }
    """
    by_entity: Dict[str, Counter] = defaultdict(Counter)

    for e in events:
        ip     = e.get("ip")
        user   = e.get("username")
        etype  = e.get("event_type", "UNKNOWN")
        entity = ip if (ip and ip not in ("", "None", None)) else user
        if not entity:
            continue
        by_entity[entity][etype] += 1

    results: Dict[str, Dict] = {}

    for entity, counts in by_entity.items():
        H       = _shannon_entropy(dict(counts))
        total   = sum(counts.values())
        dominant = counts.most_common(1)[0][0] if counts else "—"

        # Thresholds calibrated for ~7 possible event types (max 2.807 bits)
        if H < 0.5:
            label = "NORMAL"      # Highly predictable — expected for a real user
        elif H < 1.2:
            label = "MODERATE"    # Some variety — still likely benign
        elif H < 2.0:
            label = "ELEVATED"    # Multiple action types — worth monitoring
        else:
            label = "ANOMALOUS"   # Near-uniform distribution — highly suspicious

        results[entity] = {
            "entity":        entity,
            "entropy":       round(H, 3),
            "entropy_label": label,
            "event_dist":    dict(counts),
            "dominant_type": dominant,
            "event_count":   total,
            "entropy_pct":   min(100, int((H / _MAX_ENTROPY) * 100)),
        }

    return results
