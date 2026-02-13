import json
import os

from collector.log_collector import collect_logs
from parser.log_parser import parse_log
from analyzer.detection_engine import analyze_event
from alerts.alert_manager import persist_alerts

# Make paths independent of the current working directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "simulated_auth.log")
STORAGE_FILE = os.path.join(BASE_DIR, "storage", "events.json")


def run_pipeline() -> None:
    """
    End‑to‑end mini SIEM pipeline:
    1. Collect raw auth logs
    2. Parse them into normalized events
    3. Run rule‑based detections
    4. Persist events to storage/events.json

    Each run completely regenerates events.json from the log file so the UI
    always reflects the current log contents.
    """
    logs = collect_logs(LOG_FILE)

    normalized_events = []
    collected_alerts = []

    for line in logs:
        event = parse_log(line)
        if not event:
            continue

        normalized_events.append(event)

        for alert in analyze_event(event):
            collected_alerts.append((alert, event))

    # Noise reduction: deduplicate + persist
    persist_alerts(collected_alerts, deduplicate=True, min_severity="LOW")

    with open(STORAGE_FILE, "w") as f:
        json.dump(normalized_events, f, indent=4)


if __name__ == "__main__":
    run_pipeline()
