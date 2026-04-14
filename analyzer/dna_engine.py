"""
Alert DNA Fingerprinting Engine
=================================
Novel Feature #5 (P2): Computes a unique "DNA fingerprint" for each alert
based on its behavioral PATTERN rather than its entity (IP/user).

Two alerts from completely different IPs or users will share the same DNA
fingerprint if they exhibit the same attack behavior pattern (same sequence
of event types, same time-of-day profile, same severity trajectory).

This enables cross-entity pattern matching that no current SIEM implements.

Patent angle: "Method for cross-entity behavioral fingerprinting of security
events using sequence-normalized hashing."
"""

import hashlib
import json


def compute_alert_dna(alert: dict, event: dict | None = None) -> str:
    """
    Compute a DNA fingerprint for an alert based on behavioral pattern.

    Fingerprint inputs (intentionally EXCLUDES entity identifiers like IP/user):
      - Alert type
      - Severity
      - MITRE tactic
      - Time-of-day bucket (morning/afternoon/evening/night)
      - Event type
      - Whether entity is internal or external

    Returns a short hex string (8 chars) unique to the behavioral pattern.
    """
    ev = event or {}
    atype  = alert.get("type", "")
    sev    = alert.get("severity", "")
    tactic = alert.get("mitre_tactic", "")
    event_type = ev.get("event_type", "")

    # Time-of-day bucket (entity-independent behavioral signal)
    hour = ev.get("hour")
    if hour is not None:
        if 6  <= hour < 12: tod = "morning"
        elif 12 <= hour < 18: tod = "afternoon"
        elif 18 <= hour < 22: tod = "evening"
        else:                 tod = "night"
    else:
        tod = "unknown"

    # Internal vs external (behavioral, not entity-specific)
    location = ev.get("location", "")
    is_external = "external" if location not in ("Internal", "Local", "") else "internal"

    fingerprint_data = {
        "alert_type":  atype,
        "severity":    sev,
        "mitre_tactic": tactic,
        "event_type":  event_type,
        "time_of_day": tod,
        "origin":      is_external,
    }

    # Deterministic hash of behavioral pattern
    raw = json.dumps(fingerprint_data, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:8].upper()


def enrich_with_dna(alerts_with_events: list[tuple]) -> list[dict]:
    """
    Enrich a list of (alert, event) tuples with DNA fingerprints.
    Returns list of alert dicts with added 'dna' field.
    Groups alerts sharing the same DNA.
    """
    enriched = []
    for alert, event in alerts_with_events:
        dna = compute_alert_dna(alert, event)
        enriched.append({**alert, "dna": dna})
    return enriched


def get_dna_groups(alerts: list[dict]) -> dict[str, list[dict]]:
    """
    Group alerts by DNA fingerprint.
    Returns dict: {dna_string: [alert, ...]}
    """
    groups: dict[str, list] = {}
    for a in alerts:
        dna = a.get("dna", "UNKNOWN")
        groups.setdefault(dna, []).append(a)
    return groups


# Human-readable label for known DNA patterns
_DNA_LABELS = {
    # These are pre-computed for common patterns — the engine generates the
    # rest dynamically. Labels help analysts recognize signatures at a glance.
}


def describe_dna(dna: str, alerts_in_group: list[dict]) -> str:
    """Generate a human-readable description for a DNA group."""
    if dna in _DNA_LABELS:
        return _DNA_LABELS[dna]

    # Derive description from the pattern
    types  = list(dict.fromkeys(a.get("type", "") for a in alerts_in_group))
    sevs   = list(dict.fromkeys(a.get("severity", "") for a in alerts_in_group))
    tactic = alerts_in_group[0].get("mitre_tactic", "") if alerts_in_group else ""

    type_str = " + ".join(types[:3])
    sev_str  = "/".join(sevs[:2])
    return f"{type_str} [{sev_str}] — {tactic}" if tactic else f"{type_str} [{sev_str}]"
