import json
import os

from collector.log_collector import collect_logs
from parser.log_parser import parse_log
from analyzer.detection_engine import analyze_event
from analyzer.dna_engine import enrich_with_dna
from analyzer.reputation_engine import update_reputation
from alerts.alert_manager import persist_alerts

# Make paths independent of the current working directory
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
_REAL_LOG     = os.path.join(BASE_DIR, "logs", "real_auth.log")
_SIM_LOG      = os.path.join(BASE_DIR, "logs", "simulated_auth.log")
# ── Prefer live macOS logs; fall back to simulation only if real log absent ──
LOG_FILE      = _REAL_LOG if os.path.exists(_REAL_LOG) else _SIM_LOG
STORAGE_FILE  = os.path.join(BASE_DIR, "storage", "events.json")


def run_pipeline(log_file: str = None) -> None:
    """
    End-to-end mini SIEM pipeline:
    1. Collect raw auth logs  (real macOS or simulated, auto-detected)
    2. Parse them into normalized events
    3. Run rule-based detections (with explainability + decay)
    4. DNA-fingerprint all alerts (cross-entity pattern matching)
    5. Update entity reputation heat scores
    6. Persist alerts and events

    Each run completely regenerates events.json from the log file so the UI
    always reflects the current log contents.
    """
    logs = collect_logs(log_file or LOG_FILE)

    normalized_events  = []
    collected_alerts   = []   # list of (alert_dict, event_dict)

    for line in logs:
        event = parse_log(line)
        if not event:
            continue

        normalized_events.append(event)

        for alert in analyze_event(event):
            collected_alerts.append((alert, event))

    # ── Novel Feature: DNA Fingerprinting ────────────────────────────────────
    # Enrich all alerts with behavioral DNA before deduplication so the DNA
    # field is preserved in the persisted records.
    if collected_alerts:
        alerts_only = [a for a, _ in collected_alerts]
        enriched    = enrich_with_dna(collected_alerts)
        # Re-pair enriched alerts with their events
        collected_alerts = [(enriched[i], collected_alerts[i][1]) for i in range(len(enriched))]

    # ── Novel Feature: Noise reduction — deduplicate + persist ───────────────
    persist_alerts(collected_alerts, deduplicate=True, min_severity="LOW")

    # ── Novel Feature: Entity Reputation Heat Scores ──────────────────────────
    # Load persisted alerts (post-dedup) to feed reputation engine
    alerts_file = os.path.join(BASE_DIR, "storage", "alerts.json")
    try:
        with open(alerts_file) as f:
            persisted_alerts = json.load(f)
    except Exception:
        persisted_alerts = []
    update_reputation(persisted_alerts)

    # ── Persist normalized events ─────────────────────────────────────────────
    with open(STORAGE_FILE, "w") as f:
        json.dump(normalized_events, f, indent=4)


if __name__ == "__main__":
    run_pipeline()
