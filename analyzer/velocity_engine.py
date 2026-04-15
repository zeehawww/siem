"""
Attack Velocity Profiling (AVP) Engine
========================================
Novel Feature: Computes the first-order (rate) and second-order (acceleration)
derivatives of attack event intensity per entity over rolling time windows.

A brute-force escalating 1→2→4→8 attempts/minute is fundamentally different
from one stuck at a flat rate of 1/min. The VELOCITY PROFILE of an attack —
how fast it changes — is a distinct behavioral fingerprint that no SIEM
today computes.

Patent: "Method for multi-order derivative profiling of attack intensity
in real-time security event streams for threat velocity fingerprinting."
"""

from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional


_WINDOWS = [5, 15, 60]     # rolling windows in minutes


def _parse_ts(ts: str) -> Optional[float]:
    """Parse ISO-8601 or syslog timestamp into a Unix epoch float."""
    if not ts:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",
    ):
        try:
            return datetime.strptime(ts.strip()[:19], fmt).timestamp()
        except ValueError:
            continue
    return None


def compute_velocity_profiles(alerts: List[Dict[str, Any]]) -> Dict[str, Dict]:
    """
    Compute attack velocity and acceleration for every threat entity.

    Returns a dict keyed by entity identifier (IP or username):
        {
          "<entity>": {
            "entity":         str,
            "alert_count":    int,
            "velocity_5m":    float,   # alerts/min in last 5-min window
            "velocity_15m":   float,   # alerts/min in last 15-min window
            "velocity_60m":   float,   # alerts/min in last 60-min window
            "acceleration":   float,   # dv/dt = v_5m - v_15m
                                       #   positive = ESCALATING
                                       #   negative = DECELERATING
            "profile":        str,     # ESCALATING | SUSTAINED | DECELERATING | QUIET
            "velocity_score": int,     # 0–100, higher = more dangerous velocity
          }
        }
    """
    by_entity: Dict[str, List[float]] = defaultdict(list)

    for a in alerts:
        ev     = a.get("event") or {}
        ip     = ev.get("ip")
        user   = ev.get("username")
        entity = ip if (ip and ip not in ("", "None", None)) else user
        if not entity:
            continue
        ts = _parse_ts(ev.get("timestamp") or a.get("timestamp") or "")
        if ts:
            by_entity[entity].append(ts)

    if not by_entity:
        return {}

    all_ts = [t for ts_list in by_entity.values() for t in ts_list]
    now    = max(all_ts)

    results: Dict[str, Dict] = {}

    for entity, timestamps in by_entity.items():
        counts = {
            w: sum(1 for t in timestamps if t >= now - w * 60)
            for w in _WINDOWS
        }
        v5  = counts[5]  / 5.0
        v15 = counts[15] / 15.0
        v60 = counts[60] / 60.0

        # First derivative: rate of change of attack intensity
        acceleration = v5 - v15

        # Profile classification
        if v5 > v15 * 1.5 and v5 > 0.05:
            profile = "ESCALATING"
        elif v5 >= v15 * 0.7 and v15 > 0.02:
            profile = "SUSTAINED"
        elif v5 < v15 * 0.5 and v15 > 0.02:
            profile = "DECELERATING"
        else:
            profile = "QUIET"

        # Composite velocity score (0–100)
        raw_score = (len(timestamps) * 3) + (v5 * 25) + (max(0, acceleration) * 15)
        velocity_score = min(100, int(raw_score))

        results[entity] = {
            "entity":         entity,
            "alert_count":    len(timestamps),
            "velocity_5m":    round(v5,  4),
            "velocity_15m":   round(v15, 4),
            "velocity_60m":   round(v60, 4),
            "acceleration":   round(acceleration, 4),
            "profile":        profile,
            "velocity_score": velocity_score,
        }

    return results
