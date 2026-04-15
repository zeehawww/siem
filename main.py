import json
import os

from collector.log_collector import collect_logs
from parser.log_parser import parse_log
from analyzer.detection_engine import analyze_event
from analyzer.dna_engine import enrich_with_dna
from analyzer.reputation_engine import update_reputation
from alerts.alert_manager import persist_alerts
from analyzer.velocity_engine          import compute_velocity_profiles
from analyzer.entropy_engine           import compute_entropy_scores
from analyzer.prediction_engine        import predict_next_steps
from analyzer.temporal_fingerprint_engine import compute_temporal_fingerprints

# Make paths independent of the current working directory
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
_REAL_LOG     = os.path.join(BASE_DIR, "logs", "real_auth.log")
_SIM_LOG      = os.path.join(BASE_DIR, "logs", "simulated_auth.log")
# ── Prefer live macOS logs; fall back to simulation only if real log absent ──
LOG_FILE      = _REAL_LOG if os.path.exists(_REAL_LOG) else _SIM_LOG
STORAGE_FILE     = os.path.join(BASE_DIR, "storage", "events.json")
VELOCITY_FILE    = os.path.join(BASE_DIR, "storage", "velocity.json")
ENTROPY_FILE     = os.path.join(BASE_DIR, "storage", "entropy.json")
PREDICTIONS_FILE = os.path.join(BASE_DIR, "storage", "predictions.json")
TBF_FILE         = os.path.join(BASE_DIR, "storage", "tbf.json")


def _save_json(data: object, path: str) -> None:
    """Persist a JSON-serialisable object to disk."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


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

    # ── Novel: Temporal Behavioral Fingerprinting ────────────────────────────────
    # Classifies threat actors by timing cadence: AUTOMATED / HUMAN / STEALTHY
    _save_json(compute_temporal_fingerprints(normalized_events), TBF_FILE)

    # ── Novel: Attack Velocity Profiling ────────────────────────────────────────
    # Computes rate-of-change and acceleration of attack events per entity.
    _save_json(compute_velocity_profiles(persisted_alerts), VELOCITY_FILE)

    # ── Novel: Behavioral Entropy Anomaly Detection ───────────────────────────────
    # Shannon entropy of event-type distribution per entity — spikes = compromise.
    _save_json(compute_entropy_scores(normalized_events), ENTROPY_FILE)

    # ── Novel: Markov Next-Step Attack Prediction ─────────────────────────────────
    # Predicts the most likely next attack move per entity from kill-chain model.
    _save_json(predict_next_steps(persisted_alerts), PREDICTIONS_FILE)

    # ── Persist normalized events ─────────────────────────────────────────────────
    with open(STORAGE_FILE, "w") as f:
        json.dump(normalized_events, f, indent=4)


if __name__ == "__main__":
    run_pipeline()
