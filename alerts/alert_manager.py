import json
import os
from datetime import datetime

ALERTS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "storage",
    "alerts.json",
)

# Noise reduction: suppress alerts below this severity (optional)
MIN_SEVERITY_LEVEL = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def deduplicate_alerts(alerts_with_events):
    """
    Noise reduction: merge alerts with same type and entity (IP or user).
    Reduces alert fatigue from repeated PRIV_ESC, etc.
    """
    merged = {}
    for alert, event in alerts_with_events:
        t = alert.get("type")
        entity = alert.get("entity_ip") or alert.get("entity_user") or "global"
        key = (t, entity)

        if key not in merged:
            merged[key] = {"alert": alert, "event": event, "count": 1}
        else:
            merged[key]["count"] += 1
            merged[key]["event"] = event  # keep last event for context

    result = []
    for (_, _), data in merged.items():
        a, ev, count = data["alert"], data["event"], data["count"]
        msg = a["message"]
        if count > 1:
            msg = f"{msg} (×{count} occurrences)"
        result.append(({**a, "message": msg, "count": count}, ev))
    return result


def filter_by_severity(alerts_with_events, min_severity="MEDIUM"):
    """Suppress low-priority alerts to reduce noise."""
    min_level = MIN_SEVERITY_LEVEL.get(min_severity, 1)
    return [
        (a, e) for a, e in alerts_with_events
        if MIN_SEVERITY_LEVEL.get(a.get("severity", ""), 0) >= min_level
    ]


def clear_alerts():
    """Clear persisted alerts (called at start of each pipeline run)."""
    _ensure_alerts_file()
    with open(ALERTS_FILE, "w") as f:
        json.dump([], f)


def _ensure_alerts_file():
    storage_dir = os.path.dirname(ALERTS_FILE)
    os.makedirs(storage_dir, exist_ok=True)
    if not os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "w") as f:
            json.dump([], f)


def raise_alert(alert, event=None):
    """Print alert to console and persist to storage/alerts.json."""
    print(f"[{alert['severity']}] {alert['type']} - {alert['message']}")

    persisted = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": alert["type"],
        "severity": alert["severity"],
        "message": alert["message"],
        "event": event,
        "count": alert.get("count", 1),
    }

    _ensure_alerts_file()
    with open(ALERTS_FILE, "r") as f:
        alerts = json.load(f)
    alerts.append(persisted)
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)


def persist_alerts(alerts_with_events, deduplicate=True, min_severity="LOW"):
    """
    Process and persist alerts with noise reduction:
    - Deduplicate same type+entity
    - Optionally suppress low severity
    """
    if deduplicate:
        alerts_with_events = deduplicate_alerts(alerts_with_events)
    if min_severity != "LOW":
        alerts_with_events = filter_by_severity(alerts_with_events, min_severity)

    clear_alerts()
    for alert, event in alerts_with_events:
        raise_alert(alert, event=event)
