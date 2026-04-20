from flask import Flask, render_template, redirect, url_for, request, Response, jsonify
import csv
import hashlib
import io
import json
import os
import random
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Ensure the project root (one level up from this file) is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.narrative_engine  import generate_narratives
from analyzer.reputation_engine import get_reputation
from analyzer.dna_engine        import get_dna_groups, describe_dna
from analyzer.feedback_engine   import (
    record_feedback, apply_feedback_to_alerts, get_all_feedback, get_verdict_label
)
from analyzer.detection_engine  import analyze_event
from collector.macos_log_collector import write_real_logs_to_file, collect_real_logs
from collector.syslog_listener     import start_listener_thread, stop_listener, get_status as syslog_status
from analyzer.velocity_engine   import compute_velocity_profiles
from analyzer.entropy_engine    import compute_entropy_scores
from analyzer.prediction_engine import predict_next_steps
from analyzer.atrs_engine       import compute_all_atrs

app = Flask(__name__)

EVENT_FILE    = os.path.join(PROJECT_ROOT, "storage", "events.json")
ALERTS_FILE   = os.path.join(PROJECT_ROOT, "storage", "alerts.json")
SIM_LOG_FILE  = os.path.join(PROJECT_ROOT, "logs", "simulated_auth.log")
REAL_LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "real_auth.log")
SYSLOG_LOG_FILE  = os.path.join(PROJECT_ROOT, "logs", "network_syslog.log")
ACTIVE_LOG_FILE  = os.path.join(PROJECT_ROOT, "logs", "active_auth.log")
COMBINED_LOG     = os.path.join(PROJECT_ROOT, "logs", "combined_auth.log")
VELOCITY_FILE    = os.path.join(PROJECT_ROOT, "storage", "velocity.json")
ENTROPY_FILE     = os.path.join(PROJECT_ROOT, "storage", "entropy.json")
PREDICTIONS_FILE = os.path.join(PROJECT_ROOT, "storage", "predictions.json")
TBF_FILE         = os.path.join(PROJECT_ROOT, "storage", "tbf.json")
SRTC_FILE        = os.path.join(PROJECT_ROOT, "storage", "srtc.json")

INGEST_CONFIG_FILE = os.path.join(PROJECT_ROOT, "storage", "ingest_config.json")


def _ensure_simulated_dataset_exists() -> None:
    """
    Ensure the demo dataset exists so 'simulated_only' and 'combined' modes work.
    We keep this file as a stable demo corpus; it should not be overwritten by
    real logs or network syslog ingestion.
    """
    Path(os.path.dirname(SIM_LOG_FILE)).mkdir(parents=True, exist_ok=True)
    if os.path.exists(SIM_LOG_FILE) and os.path.getsize(SIM_LOG_FILE) > 0:
        return
    samples = [
        "Jan 27 11:00:01 demo sshd[3333]: Failed password for invalid user hacker from 203.0.113.42 port 22",
        "Jan 27 11:00:05 demo sshd[3333]: Failed password for invalid user root from 203.0.113.42 port 22",
        "Jan 27 11:00:10 demo sshd[3333]: Failed password for invalid user admin from 203.0.113.42 port 22",
        "Jan 27 11:00:15 demo sshd[3333]: Accepted password for backup from 203.0.113.42 port 22",
        "Jan 27 11:01:00 demo sudo: backup : TTY=pts/1 ; COMMAND=/usr/bin/id",
        "Jan 27 12:00:01 demo sshd[4444]: Accepted password for developer from 172.16.0.99 port 22",
        "Jan 27 12:05:00 demo sshd[4444]: Accepted password for developer from 10.20.30.40 port 22",
        "Jan 27 12:01:00 demo sudo: developer : TTY=pts/2 ; COMMAND=/bin/cat /etc/shadow",
    ]
    with open(SIM_LOG_FILE, "w") as f:
        for line in samples:
            f.write(line + "\n")


def _write_active_log(mode: str) -> None:
    """
    Build logs/active_auth.log deterministically from selected sources.

    Modes:
      - real_only:      REAL only
      - simulated_only: SIM only (demo corpus + optional network syslog)
      - combined:       REAL + SIM + optional network syslog
    """
    _ensure_simulated_dataset_exists()

    lines: list[str] = []
    if mode in ("simulated_only", "combined"):
        if os.path.exists(SIM_LOG_FILE):
            with open(SIM_LOG_FILE) as f:
                lines += f.readlines()
        if os.path.exists(SYSLOG_LOG_FILE):
            with open(SYSLOG_LOG_FILE) as f:
                lines += f.readlines()

    if mode in ("real_only", "combined"):
        if os.path.exists(REAL_LOG_FILE):
            with open(REAL_LOG_FILE) as f:
                lines += f.readlines()

    seen = set()
    unique: list[str] = []
    for l in lines:
        if l not in seen:
            seen.add(l)
            unique.append(l)

    Path(os.path.dirname(ACTIVE_LOG_FILE)).mkdir(parents=True, exist_ok=True)
    with open(ACTIVE_LOG_FILE, "w") as f:
        f.writelines(unique)


def _seed_simulated_demo(overwrite: bool = True) -> int:
    """
    Write a deterministic, mentor-friendly simulated dataset that reliably triggers:
    - brute force
    - compromised account
    - sudo / privilege escalation
    - root login
    - new IP for user + after-hours
    Returns number of lines written.
    """
    Path(os.path.dirname(SIM_LOG_FILE)).mkdir(parents=True, exist_ok=True)
    if (not overwrite) and os.path.exists(SIM_LOG_FILE) and os.path.getsize(SIM_LOG_FILE) > 0:
        with open(SIM_LOG_FILE) as f:
            return len(f.readlines())

    lines = []
    # Scenario A: brute force then success (compromised account)
    for i in range(1, 6):
        lines.append(f"Jan 27 09:10:{i:02d} demo sshd[2222]: Failed password for invalid user admin from 203.0.113.42 port 22")
    lines.append("Jan 27 09:11:10 demo sshd[2222]: Accepted password for admin from 203.0.113.42 port 22")

    # Scenario B: privilege escalation via sudo
    lines.append("Jan 27 09:12:02 demo sudo: admin : TTY=pts/0 ; COMMAND=/bin/cat /etc/shadow")
    lines.append("Jan 27 09:12:20 demo sudo: admin : TTY=pts/0 ; COMMAND=/usr/bin/id")

    # Scenario C: root login (critical)
    lines.append("Jan 27 09:13:00 demo sshd[3333]: Accepted password for root from 198.51.100.77 port 22")

    # Scenario D: normal user from two IPs (new IP + after-hours)
    lines.append("Jan 27 22:45:00 demo sshd[4444]: Accepted password for developer from 10.20.30.40 port 22")
    lines.append("Jan 27 22:46:10 demo sshd[4444]: Accepted password for developer from 172.16.0.99 port 22")

    with open(SIM_LOG_FILE, "w") as f:
        for l in lines:
            f.write(l + "\n")
    return len(lines)


# ── Data loaders ──────────────────────────────────────────────────────────────

def load_events():
    if not os.path.exists(EVENT_FILE):
        return []
    with open(EVENT_FILE) as f:
        return json.load(f)


def load_alerts():
    """Load persisted alerts from storage (from last pipeline run)."""
    if not os.path.exists(ALERTS_FILE):
        return []
    with open(ALERTS_FILE) as f:
        return json.load(f)


def load_velocity() -> dict:
    if not os.path.exists(VELOCITY_FILE):
        return {}
    with open(VELOCITY_FILE) as f:
        return json.load(f)


def load_entropy() -> dict:
    if not os.path.exists(ENTROPY_FILE):
        return {}
    with open(ENTROPY_FILE) as f:
        return json.load(f)


def load_predictions() -> dict:
    if not os.path.exists(PREDICTIONS_FILE):
        return {}
    with open(PREDICTIONS_FILE) as f:
        return json.load(f)


def load_tbf() -> dict:
    if not os.path.exists(TBF_FILE):
        return {}
    with open(TBF_FILE) as f:
        return json.load(f)


def load_srtc() -> dict:
    if not os.path.exists(SRTC_FILE):
        return {}
    with open(SRTC_FILE) as f:
        return json.load(f)


def load_feedback_data() -> list:
    """Load analyst feedback records to pass into ATRS modifier."""
    all_fb = get_all_feedback()   # dict keyed by alert_id
    result = []
    for entry in all_fb.values():
        if isinstance(entry, dict):
            result.append(entry)
    return result


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/intelligence")
def intelligence():
    """
    Unified intelligence hub:
    • ATRS — Adaptive Threat Risk Score per entity (novel patent algorithm)
    • Threat Narratives — auto-generated plain-English attack stories
    • Predictions — Markov next-step, entropy, velocity
    Replaces separate /narrative, /reputation, /prediction pages.
    """
    alerts       = load_alerts()
    velocity     = load_velocity()
    entropy      = load_entropy()
    predictions  = load_predictions()
    tbf          = load_tbf()
    srtc         = load_srtc()
    rep_data     = get_reputation()
    narratives   = generate_narratives(alerts)
    feedback     = load_feedback_data()

    atrs_scores  = compute_all_atrs(
        velocity_data  = velocity,
        entropy_data   = entropy,
        reputation_data= rep_data,
        tbf_data       = tbf,
        predictions    = predictions,
        alerts         = alerts,
        feedback_data  = feedback,
    )

    return render_template(
        "intelligence.html",
        atrs_scores  = atrs_scores,
        narratives   = narratives,
        predictions  = predictions,
        entropy      = entropy,
        velocity     = velocity,
        srtc         = srtc,
    )


# Legacy redirect — keep old URLs working
@app.route("/prediction")
def prediction():
    return redirect(url_for("intelligence") + "#predictions")


@app.route("/narrative")
def narrative():
    return redirect(url_for("intelligence") + "#narratives")


@app.route("/reputation")
def reputation():
    return redirect(url_for("intelligence"))


# ── Existing routes ───────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/logs")
def logs():
    events = load_events()
    return render_template("logs.html", events=events)


@app.route("/analysis")
def analysis():
    """Folded into Dashboard — redirect kept for backward compat."""
    return redirect(url_for("home"))


@app.route("/alerts")
def alerts():
    """Show persisted alerts enriched with feedback loop data."""
    persisted = load_alerts()
    # Number them
    for idx, a in enumerate(persisted, start=1):
        a["id"] = idx
    # Apply analyst feedback confidence modifiers
    persisted   = apply_feedback_to_alerts(persisted)
    predictions = load_predictions()
    return render_template("alerts.html", alerts=persisted, predictions=predictions)


@app.route("/run-analysis")
def run_analysis():
    subprocess.run(
        [sys.executable, "-m", "main"],
        cwd=PROJECT_ROOT,
        check=False,
    )
    return redirect(url_for("home"))


@app.route("/correlation")
def correlation():
    events = load_events()
    ips    = sorted({e["ip"] for e in events if e.get("ip")})
    users  = sorted({e["username"] for e in events if e.get("username")})
    entity = request.args.get("entity", "").strip()

    chains = []
    if entity:
        if entity in ips:
            filtered  = [e for e in events if e.get("ip") == entity]
            group_by  = "ip"
        elif entity in users:
            filtered  = [e for e in events if e.get("username") == entity]
            group_by  = "user"
        else:
            filtered  = []
            group_by  = None
        if filtered:
            filtered.sort(key=lambda e: e.get("timestamp") or "")
            chains.append({"label": f"{entity} ({group_by})", "events": filtered})

    return render_template(
        "correlation.html",
        chains=chains,
        ips=ips,
        users=users,
        selected=entity,
    )


@app.route("/simulate")
def simulate():
    # Legacy: append a few demo lines and re-run pipeline.
    # Keep this behavior, but never write into the *active* log directly.
    _ensure_simulated_dataset_exists()
    samples = [
        "Jan 27 11:00:01 demo sshd[3333]: Failed password for invalid user hacker from 203.0.113.42 port 22",
        "Jan 27 11:00:05 demo sshd[3333]: Failed password for invalid user root from 203.0.113.42 port 22",
        "Jan 27 11:00:10 demo sshd[3333]: Failed password for invalid user admin from 203.0.113.42 port 22",
        "Jan 27 11:00:15 demo sshd[3333]: Accepted password for backup from 203.0.113.42 port 22",
        "Jan 27 11:01:00 demo sudo: backup : TTY=pts/1 ; COMMAND=/usr/bin/id",
        "Jan 27 12:00:01 demo sshd[4444]: Accepted password for developer from 172.16.0.99 port 22",
        "Jan 27 12:05:00 demo sshd[4444]: Accepted password for developer from 10.20.30.40 port 22",
        "Jan 27 12:01:00 demo sudo: developer : TTY=pts/2 ; COMMAND=/bin/cat /etc/shadow",
    ]
    to_append = random.sample(samples, min(3, len(samples)))
    with open(SIM_LOG_FILE, "a") as f:
        for line in to_append:
            f.write(line + "\n")

    # Rebuild active log using last selected mode (default: combined)
    mode = "combined"
    if os.path.exists(INGEST_CONFIG_FILE):
        try:
            with open(INGEST_CONFIG_FILE) as f:
                mode = (json.load(f) or {}).get("mode", "combined")
        except Exception:
            mode = "combined"
    _write_active_log(mode)

    subprocess.run([sys.executable, "-m", "main"], cwd=PROJECT_ROOT, check=False)
    return redirect(url_for("home"))


# ── Exports ───────────────────────────────────────────────────────────────────

@app.route("/export/events")
def export_events():
    events = load_events()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "event_type", "username", "ip", "severity", "raw_log"])
    for e in events:
        writer.writerow([
            e.get("timestamp", ""),
            e.get("event_type", ""),
            e.get("username", ""),
            e.get("ip", ""),
            e.get("severity", ""),
            (e.get("raw_log") or "").replace("\n", " "),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem-events.csv"},
    )


@app.route("/export/alerts")
def export_alerts():
    alerts = load_alerts()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "type", "severity", "message", "risk_score", "dna", "mitre_technique", "mitre_tactic"])
    for a in alerts:
        writer.writerow([
            a.get("timestamp", ""),
            a.get("type", ""),
            a.get("severity", ""),
            a.get("message", ""),
            a.get("risk_score", ""),
            a.get("dna", ""),
            a.get("mitre_technique", ""),
            a.get("mitre_tactic", ""),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem-alerts.csv"},
    )


@app.route("/compliance")
def compliance():
    events = load_events()
    alerts = load_alerts()

    failed_by_ip  = Counter(e["ip"] for e in events if e.get("event_type") == "FAILED_LOGIN" and e.get("ip"))
    sudo_by_user  = Counter(e["username"] for e in events if e.get("event_type") == "SUDO_USAGE" and e.get("username"))
    critical_events  = [e for e in events if e.get("severity") in ("HIGH", "CRITICAL")]
    critical_alerts  = [a for a in alerts if a.get("severity") in ("HIGH", "CRITICAL")]

    return render_template(
        "compliance.html",
        failed_by_ip=dict(failed_by_ip.most_common()),
        sudo_by_user=dict(sudo_by_user.most_common()),
        critical_events=critical_events,
        critical_alerts=critical_alerts,
        total_events=len(events),
        total_alerts=len(alerts),
    )


@app.route("/export/compliance")
def export_compliance():
    events = load_events()
    alerts = load_alerts()

    failed_by_ip = Counter(e["ip"] for e in events if e.get("event_type") == "FAILED_LOGIN" and e.get("ip"))
    critical = [a for a in alerts if a.get("severity") in ("HIGH", "CRITICAL")]

    lines = [
        "=== SIEM COMPLIANCE REPORT ===", "",
        "1. AUTHENTICATION FAILURES (by source IP)",
        "-" * 40,
    ]
    for ip, count in failed_by_ip.most_common():
        lines.append(f"  {ip}: {count} failed attempts")
    lines.extend(["", "2. PRIVILEGE ESCALATION (sudo usage by user)", "-" * 40])
    for user, count in Counter(e["username"] for e in events if e.get("event_type") == "SUDO_USAGE").most_common():
        lines.append(f"  {user}: {count} sudo commands")
    lines.extend(["", "3. CRITICAL ALERTS (with MITRE + risk)", "-" * 40])
    for a in critical:
        mitre = a.get("mitre_technique") or "—"
        tactic = a.get("mitre_tactic") or "—"
        risk = a.get("risk_score", 0)
        lines.append(
            f"  [{a.get('severity')}] {a.get('type')}: {a.get('message')}  "
            f"(MITRE: {mitre} / {tactic}, Risk: {risk})"
        )
    lines.append("")

    return Response(
        "\n".join(lines),
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=compliance-report.txt"},
    )


@app.route("/export/report")
def export_report():
    events = load_events()
    alerts = load_alerts()

    now          = datetime.now(timezone.utc)
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")
    report_id    = "RPT-" + hashlib.sha1(now.isoformat().encode()).hexdigest()[:8].upper()

    failed_by_ip    = Counter(e["ip"] for e in events if e.get("event_type") == "FAILED_LOGIN" and e.get("ip"))
    top_attackers   = failed_by_ip.most_common(10)
    sudo_by_user    = Counter(e["username"] for e in events if e.get("event_type") == "SUDO_USAGE" and e.get("username"))
    top_sudo        = sudo_by_user.most_common(10)
    critical_alerts = [a for a in alerts if a.get("severity") in ("HIGH", "CRITICAL")]
    all_alerts = sorted(alerts, key=lambda a: a.get("timestamp", ""), reverse=True)

    severity_count  = Counter(e["severity"] for e in events)
    total_e         = len(events) or 1
    severity_breakdown = [
        {"label": sev, "count": severity_count.get(sev, 0),
         "pct": round(severity_count.get(sev, 0) / total_e * 100)}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if severity_count.get(sev, 0) > 0
    ]

    etype_count = Counter(e["event_type"] for e in events if e.get("event_type"))
    event_type_breakdown = [
        {"label": k, "count": v, "pct": round(v / total_e * 100)}
        for k, v in etype_count.most_common()
    ]

    location_counter = Counter(
        e["location"] for e in events if e.get("location") and e["location"] != "Internal"
    )
    location_breakdown = location_counter.most_common()

    unique_ips = len({e["ip"] for e in events if e.get("ip")})

    risk_scores = [a.get("risk_score", 0) for a in alerts if a.get("risk_score")]
    risk_score_summary = {
        "avg": round(sum(risk_scores) / len(risk_scores)) if risk_scores else 0,
        "max": max(risk_scores) if risk_scores else 0,
        "total": sum(risk_scores) if risk_scores else 0,
    }

    mitre_counter = Counter(
        f"{a['mitre_technique']} — {a['mitre_tactic']}"
        for a in alerts
        if a.get('mitre_tactic') and a['mitre_tactic'] != 'Unknown'
    )
    mitre_tactic_freq = mitre_counter.most_common()

    max_sev = next(
        (s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
         if any(a.get("severity") == s for a in alerts)),
        "LOW"
    )

    # Data mode for demo vs real-only runs
    ingest_mode = "auto"
    if os.path.exists(INGEST_CONFIG_FILE):
        try:
            with open(INGEST_CONFIG_FILE) as f:
                ingest_mode = (json.load(f) or {}).get("mode", "auto")
        except Exception:
            ingest_mode = "auto"

    src_counts = Counter(e.get("source", "unknown") for e in events)
    src_summary = ", ".join(f"{k}:{v}" for k, v in src_counts.most_common()) if src_counts else "—"

    return render_template(
        "report_export.html",
        report_id=report_id,
        generated_at=generated_at,
        top_attackers=top_attackers,
        top_sudo=top_sudo,
        critical_alerts=critical_alerts,
        all_alerts=all_alerts,
        total_events=len(events),
        total_alerts=len(alerts),
        unique_ips=unique_ips,
        severity_breakdown=severity_breakdown,
        event_type_breakdown=event_type_breakdown,
        location_breakdown=location_breakdown,
        risk_score_summary=risk_score_summary,
        mitre_tactic_freq=mitre_tactic_freq,
        max_severity=max_sev,
        ingest_mode=ingest_mode,
        src_summary=src_summary,
    )


# ── Legacy page redirects (routes replaced by unified /intelligence) ──────────

@app.route("/dna")
def dna_view():
    return redirect(url_for("intelligence"))


@app.route("/simulator")
def simulator():
    return redirect(url_for("intelligence"))


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """
    🆕 API endpoint for What-If simulator.
    Accepts: {technique_id, target_user, target_ip, event_count}
    Returns: list of alerts that WOULD be generated.
    """
    data         = request.get_json() or {}
    technique_id = data.get("technique_id", "T1110")
    target_user  = data.get("target_user", "victim_user")
    target_ip    = data.get("target_ip", "198.51.100.99")
    event_count  = min(int(data.get("event_count", 5)), 20)

    from parser.log_parser import parse_log
    from collections import defaultdict

    # Build synthetic log lines matching the technique
    technique_map = {
        "T1110":     [f"Jan 27 14:00:{i:02d} sim sshd[9999]: Failed password for invalid user {target_user} from {target_ip} port 22" for i in range(event_count)],
        "T1078":     [f"Jan 27 14:01:00 sim sshd[9999]: Accepted password for {target_user} from {target_ip} port 22"],
        "T1548":     [f"Jan 27 14:02:00 sim sudo: {target_user} : TTY=pts/0 ; COMMAND=/bin/bash"],
        "T1078.003": [f"Jan 27 14:03:00 sim sshd[9999]: Accepted password for root from {target_ip} port 22"],
        "T1021":     [f"Jan 27 14:04:00 sim sshd[9999]: Accepted password for {target_user} from {target_ip} port 22"],
        # T1110 → T1078 full chain
        "T1110+T1078": (
            [f"Jan 27 14:00:{i:02d} sim sshd[9999]: Failed password for invalid user {target_user} from {target_ip} port 22" for i in range(5)]
            + [f"Jan 27 14:01:00 sim sshd[9999]: Accepted password for {target_user} from {target_ip} port 22"]
        ),
    }
    synthetic_lines = technique_map.get(technique_id, [])

    # Stateful simulation: share counters across all events in the run
    sim_failed   = defaultdict(int)
    sim_baseline = defaultdict(set)
    fired_alerts = []

    from analyzer.detection_engine import (
        _enrich_alert, BUSINESS_HOURS, _parse_hour, MITRE_TACTICS
    )

    for line in synthetic_lines:
        event = parse_log(line)
        if not event:
            continue

        if event["event_type"] == "FAILED_LOGIN":
            sim_failed[event["ip"]] += 1
            if sim_failed[event["ip"]] >= 3:
                a = _enrich_alert({
                    "type":      "BRUTE_FORCE",
                    "message":   f"[SIM] Multiple failed logins from {event['ip']}",
                    "severity":  "HIGH",
                    "entity_ip": event["ip"],
                }, event)
                fired_alerts.append(a)

        if event["event_type"] == "SUCCESS_LOGIN":
            if sim_failed[event["ip"]] >= 3:
                a = _enrich_alert({
                    "type":      "COMPROMISED_ACCOUNT",
                    "message":   f"[SIM] Successful login after failures from {event['ip']}",
                    "severity":  "CRITICAL",
                    "entity_ip": event["ip"],
                }, event)
                fired_alerts.append(a)

            user = event.get("username")
            ip   = event.get("ip")
            if user and ip:
                known = sim_baseline.get(user, set())
                if known and ip not in known:
                    a = _enrich_alert({
                        "type":        "NEW_IP_FOR_USER",
                        "message":     f"[SIM] User {user} from new IP {ip}",
                        "severity":    "MEDIUM",
                        "entity_user": user,
                        "entity_ip":   ip,
                    }, event)
                    fired_alerts.append(a)
                sim_baseline[user].add(ip)

            hour = _parse_hour(event.get("timestamp", ""))
            if hour is not None and not (BUSINESS_HOURS[0] <= hour < BUSINESS_HOURS[1]):
                a = _enrich_alert({
                    "type":    "AFTER_HOURS_LOGIN",
                    "message": f"[SIM] Login outside business hours at {hour:02d}:xx",
                    "severity":"MEDIUM",
                    "entity_user": event.get("username"),
                    "entity_ip":   ip,
                }, event)
                fired_alerts.append(a)

        if event["event_type"] == "SUDO_USAGE":
            a = _enrich_alert({
                "type":        "PRIV_ESC",
                "message":     f"[SIM] Sudo used by {event['username']}",
                "severity":    "HIGH",
                "entity_user": event["username"],
            }, event)
            fired_alerts.append(a)

        if event["event_type"] == "SUCCESS_LOGIN" and event.get("username") == "root":
            a = _enrich_alert({
                "type":      "ROOT_LOGIN",
                "message":   f"[SIM] Root login from {event['ip']}",
                "severity":  "CRITICAL",
                "entity_ip": event["ip"],
            }, event)
            fired_alerts.append(a)

    # Serialize to JSON-safe dicts
    out_alerts = []
    for a in fired_alerts:
        out_alerts.append({
            "type":            a.get("type", ""),
            "severity":        a.get("severity", ""),
            "message":         a.get("message", ""),
            "mitre_tactic":    a.get("mitre_tactic", ""),
            "mitre_technique": a.get("mitre_technique", ""),
            "risk_score":      a.get("risk_score", 0),
            "explanation":     a.get("explanation", {}),
        })

    return jsonify({
        "technique_id":   technique_id,
        "target_user":    target_user,
        "target_ip":      target_ip,
        "events_tested":  len(synthetic_lines),
        "alerts_fired":   len(out_alerts),
        "would_detect":   len(out_alerts) > 0,
        "alerts":         out_alerts,
    })


@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    """
    🆕 API endpoint for Analyst Feedback Loop.
    Accepts: {alert_id, dna, verdict}
    verdict: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_INVESTIGATION
    """
    data     = request.get_json() or {}
    alert_id = str(data.get("alert_id", ""))
    dna      = data.get("dna", "")
    verdict  = data.get("verdict", "")

    if not all([alert_id, verdict]):
        return jsonify({"success": False, "error": "Missing alert_id or verdict"}), 400

    success = record_feedback(alert_id, dna, verdict)
    label   = get_verdict_label(verdict)
    return jsonify({"success": success, "label": label})


# ── Real Log Ingestion Routes ─────────────────────────────────────────────────

@app.route("/live-logs")
def live_logs():
    """
    Real-log ingestion dashboard: shows system auth events from macOS,
    syslog listener status, and lets analyst choose log source.
    """
    # Load last collected real events for preview
    real_events = []
    if os.path.exists(REAL_LOG_FILE):
        from collector.log_collector import collect_logs
        from parser.log_parser import parse_log as pl
        for line in collect_logs(REAL_LOG_FILE):
            ev = pl(line)
            if ev:
                real_events.append(ev)

    source_counts = Counter(e.get("source", "unknown") for e in real_events)
    event_type_counts = Counter(e.get("event_type", "unknown") for e in real_events)
    syslog_st = syslog_status()
    ingest_cfg = {}
    current_mode = "real_only"
    if os.path.exists(INGEST_CONFIG_FILE):
        try:
            with open(INGEST_CONFIG_FILE) as f:
                ingest_cfg = json.load(f) or {}
            current_mode = ingest_cfg.get("mode", "real_only")
        except Exception:
            ingest_cfg = {}
            current_mode = "real_only"

    active_events = load_events()
    active_source_counts = Counter(e.get("source", "unknown") for e in active_events)

    return render_template(
        "live_logs.html",
        real_events=real_events[-200:],   # last 200
        total_real=len(real_events),
        source_counts=dict(source_counts),
        event_type_counts=dict(event_type_counts),
        syslog_status=syslog_st,
        real_log_exists=os.path.exists(REAL_LOG_FILE),
        simulated_log_exists=os.path.exists(SIM_LOG_FILE) and os.path.getsize(SIM_LOG_FILE) > 0,
        syslog_log_exists=os.path.exists(SYSLOG_LOG_FILE) and os.path.getsize(SYSLOG_LOG_FILE) > 0,
        current_mode=current_mode,
        current_lookback=int(ingest_cfg.get("lookback_hours", 168)),
        active_event_count=len(active_events),
        active_source_counts=dict(active_source_counts),
    )


@app.route("/seed-demo", methods=["POST"])
def seed_demo():
    """
    Create/overwrite a stable simulated dataset for mentor demos,
    set mode=simulated_only, rebuild active log, and run the pipeline.
    """
    try:
        _seed_simulated_demo(overwrite=True)

        mode = "simulated_only"
        lookback_hours = int(request.form.get("lookback_hours", 168))
        Path(os.path.dirname(INGEST_CONFIG_FILE)).mkdir(parents=True, exist_ok=True)
        with open(INGEST_CONFIG_FILE, "w") as f:
            json.dump({"mode": mode, "lookback_hours": lookback_hours}, f, indent=2)

        _write_active_log(mode)
        subprocess.run([sys.executable, "-m", "main"], cwd=PROJECT_ROOT, check=False)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    return redirect(url_for("live_logs"))


@app.route("/ingest-real", methods=["POST"])
def ingest_real():
    """
    Collect real macOS auth logs and run the full SIEM pipeline on them.
    mode: 'real_only' | 'combined' | 'simulated_only'
    """
    mode = request.form.get("mode", "combined")
    lookback_hours = int(request.form.get("lookback_hours", 168))

    try:
        # Persist selection so syslog batches can rebuild the active log correctly
        Path(os.path.dirname(INGEST_CONFIG_FILE)).mkdir(parents=True, exist_ok=True)
        with open(INGEST_CONFIG_FILE, "w") as f:
            json.dump({"mode": mode, "lookback_hours": lookback_hours}, f, indent=2)

        if mode in ("real_only", "combined"):
            # Collect real logs from macOS
            write_real_logs_to_file(REAL_LOG_FILE, lookback_hours=lookback_hours)

        # Always rebuild the active pipeline input log from selected sources
        _write_active_log(mode)

        # Run pipeline
        subprocess.run([sys.executable, "-m", "main"], cwd=PROJECT_ROOT, check=False)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    return redirect(url_for("live_logs"))


@app.route("/api/syslog-listener", methods=["POST"])
def api_syslog_listener():
    """
    Start or stop the UDP syslog listener.
    action: 'start' | 'stop'
    """
    action = (request.get_json() or {}).get("action", "start")
    if action == "start":
        def _pipeline_callback():
            # Rebuild active log based on last selected ingest mode, then rerun pipeline.
            mode = "combined"
            if os.path.exists(INGEST_CONFIG_FILE):
                try:
                    with open(INGEST_CONFIG_FILE) as f:
                        mode = (json.load(f) or {}).get("mode", "combined")
                except Exception:
                    mode = "combined"
            _write_active_log(mode)
            subprocess.run([sys.executable, "-m", "main"], cwd=PROJECT_ROOT, check=False)
        # Network syslog should never pollute the demo corpus.
        start_listener_thread(SYSLOG_LOG_FILE, on_batch_callback=_pipeline_callback)
    else:
        stop_listener()
    return jsonify(syslog_status())


@app.route("/api/syslog-status")
def api_syslog_status():
    return jsonify(syslog_status())


@app.route("/api/dashboard-stats")
def api_dashboard_stats():
    """
    JSON stats for the home-page live counter tiles.
    Called by the home page JS every 30 s to keep metrics current.
    """
    events = load_events()
    alerts = load_alerts()
    return jsonify({
        "total_events":      len(events),
        "total_alerts":      len(alerts),
        "failed_logins":     sum(1 for e in events if e.get("event_type") == "FAILED_LOGIN"),
        "success_logins":    sum(1 for e in events if e.get("event_type") == "SUCCESS_LOGIN"),
        "sudo_usage":        sum(1 for e in events if e.get("event_type") == "SUDO_USAGE"),
        "high_and_critical": sum(1 for e in events if e.get("severity") in ("HIGH", "CRITICAL")),
        "unique_ips":        len({e["ip"] for e in events if e.get("ip")}),
        "critical_alerts":   sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
        "high_alerts":       sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "last_timestamp":    events[-1].get("timestamp") if events else None,
    })


@app.route("/api/recent-alerts")
def api_recent_alerts():
    """Return the N most-recent alerts for the dashboard feed."""
    alerts = load_alerts()
    # Sort newest-first, return last 20
    alerts_sorted = sorted(
        alerts,
        key=lambda a: a.get("timestamp", ""),
        reverse=True,
    )
    safe = []
    for a in alerts_sorted[:20]:
        safe.append({
            "type":      a.get("type", ""),
            "message":   a.get("message", ""),
            "severity":  a.get("severity", "LOW"),
            "timestamp": a.get("timestamp", ""),
            "risk_score": a.get("risk_score", 0),
        })
    return jsonify(safe)


@app.route("/api/top-attackers")
def api_top_attackers():
    """Return top 5 source IPs by failed-login count."""
    events = load_events()
    counter = Counter(
        e["ip"] for e in events
        if e.get("event_type") == "FAILED_LOGIN" and e.get("ip")
    )
    return jsonify(counter.most_common(5))


@app.route("/api/atrs-top")
def api_atrs_top():
    """Compute and return top 5 ATRS entity scores for the dashboard widget."""
    alerts      = load_alerts()
    velocity    = load_velocity()
    entropy     = load_entropy()
    predictions = load_predictions()
    tbf         = load_tbf()
    rep_data    = get_reputation()
    feedback    = load_feedback_data()

    scores = compute_all_atrs(
        velocity_data   = velocity,
        entropy_data    = entropy,
        reputation_data = rep_data,
        tbf_data        = tbf,
        predictions     = predictions,
        alerts          = alerts,
        feedback_data   = feedback,
    )
    # Serialize (strip large explanation for the widget)
    result = []
    for r in scores[:5]:
        result.append({
            "entity":     r["entity"],
            "atrs_score": r["atrs_score"],
            "risk_label": r["risk_label"],
            "color":      r["color"],
        })
    return jsonify(result)


@app.route("/api/srtc-top")
def api_srtc_top():
    """Return top 5 SRTC entities for dashboard widgets."""
    srtc = load_srtc()
    rows = sorted(srtc.values(), key=lambda x: x.get("srtc_score", 0), reverse=True)[:5]
    return jsonify(rows)


# ── Startup: auto-collect real macOS logs in background ──────────────────────

def _startup_auto_collect():
    """
    Collect real macOS system logs when the dashboard starts.
    Skipped if real_auth.log already exists and is less than 30 minutes old.
    Runs in a daemon thread — never blocks Flask startup.
    """
    stale = True
    try:
        age = time.time() - os.path.getmtime(REAL_LOG_FILE)
        stale = age > 1800          # re-collect if > 30 min old
    except OSError:
        pass                        # file absent → definitely stale

    if stale:
        try:
            n = write_real_logs_to_file(REAL_LOG_FILE, lookback_hours=168)
            if n > 0:
                subprocess.run(
                    [sys.executable, "-m", "main"],
                    cwd=PROJECT_ROOT,
                    check=False,
                )
        except Exception:
            pass                    # silently ignore — user can trigger manually


_collector_thread = threading.Thread(
    target=_startup_auto_collect, daemon=True, name="siem-startup-collect"
)
_collector_thread.start()


if __name__ == "__main__":
    app.run(debug=True, port=5001)
