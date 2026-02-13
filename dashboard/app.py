from flask import Flask, render_template, redirect, url_for, request, Response
import csv
import io
import json
import os
import random
import subprocess
import sys
from collections import Counter

# Ensure the project root (one level up from this file) is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

app = Flask(__name__)

EVENT_FILE = os.path.join(PROJECT_ROOT, "storage", "events.json")
ALERTS_FILE = os.path.join(PROJECT_ROOT, "storage", "alerts.json")
LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "simulated_auth.log")


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


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/logs")
def logs():
    events = load_events()
    return render_template("logs.html", events=events)


@app.route("/analysis")
def analysis():
    events = load_events()
    severity_count = Counter(e["severity"] for e in events)

    stats = {
        "total_events": len(events),
        "failed_logins": sum(1 for e in events if e["event_type"] == "FAILED_LOGIN"),
        "success_logins": sum(1 for e in events if e["event_type"] == "SUCCESS_LOGIN"),
        "sudo_usage": sum(1 for e in events if e["event_type"] == "SUDO_USAGE"),
        "high_and_critical": sum(
            1 for e in events if e["severity"] in ("HIGH", "CRITICAL")
        ),
        "unique_ips": len({e["ip"] for e in events if e.get("ip")}),
        "last_timestamp": events[-1]["timestamp"] if events else None,
    }

    return render_template(
        "analysis.html",
        severity=severity_count,
        stats=stats,
    )


@app.route("/alerts")
def alerts():
    """Show persisted alerts from the last pipeline run."""
    persisted = load_alerts()
    for idx, a in enumerate(persisted, start=1):
        a["id"] = idx
    return render_template("alerts.html", alerts=persisted)


@app.route("/run-analysis")
def run_analysis():
    subprocess.run(
        ["python3", "-m", "main"],
        cwd=PROJECT_ROOT,
        check=False,
    )
    return redirect(url_for("analysis"))


@app.route("/correlation")
def correlation():
    """Attack chain / correlation view: group events by IP or user, show timeline."""
    events = load_events()
    ips = sorted({e["ip"] for e in events if e.get("ip")})
    users = sorted({e["username"] for e in events if e.get("username")})
    entity = request.args.get("entity", "").strip()

    chains = []
    if entity:
        if entity in ips:
            filtered = [e for e in events if e.get("ip") == entity]
            group_by = "ip"
        elif entity in users:
            filtered = [e for e in events if e.get("username") == entity]
            group_by = "user"
        else:
            filtered = []
            group_by = None
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
    """Append random sample log lines and re-run pipeline (demo feature)."""
    samples = [
        "Jan 27 11:00:01 kali sshd[3333]: Failed password for invalid user hacker from 203.0.113.42 port 22",
        "Jan 27 11:00:05 kali sshd[3333]: Failed password for invalid user root from 203.0.113.42 port 22",
        "Jan 27 11:00:10 kali sshd[3333]: Failed password for invalid user admin from 203.0.113.42 port 22",
        "Jan 27 11:00:15 kali sshd[3333]: Accepted password for backup from 203.0.113.42 port 22",
        "Jan 27 11:01:00 kali sudo: backup : TTY=pts/1 ; COMMAND=/usr/bin/id",
        "Jan 27 12:00:01 kali sshd[4444]: Accepted password for developer from 172.16.0.99 port 22",
        "Jan 27 12:05:00 kali sshd[4444]: Accepted password for developer from 10.20.30.40 port 22",  # NEW_IP_FOR_USER
        "Jan 27 12:01:00 kali sudo: developer : TTY=pts/2 ; COMMAND=/bin/cat /etc/shadow",
    ]
    to_append = random.sample(samples, min(3, len(samples)))
    with open(LOG_FILE, "a") as f:
        for line in to_append:
            f.write(line + "\n")

    subprocess.run(
        ["python3", "-m", "main"],
        cwd=PROJECT_ROOT,
        check=False,
    )
    return redirect(url_for("analysis"))


@app.route("/export/events")
def export_events():
    """Export events to CSV."""
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


@app.route("/compliance")
def compliance():
    """Compliance report: audit-ready summary for failed logins, sudo, critical events."""
    events = load_events()
    alerts = load_alerts()

    failed_by_ip = Counter(e["ip"] for e in events if e.get("event_type") == "FAILED_LOGIN" and e.get("ip"))
    sudo_by_user = Counter(e["username"] for e in events if e.get("event_type") == "SUDO_USAGE" and e.get("username"))
    critical_events = [e for e in events if e.get("severity") in ("HIGH", "CRITICAL")]
    critical_alerts = [a for a in alerts if a.get("severity") in ("HIGH", "CRITICAL")]

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
    """Export compliance report as plain text."""
    events = load_events()
    alerts = load_alerts()

    failed_by_ip = Counter(e["ip"] for e in events if e.get("event_type") == "FAILED_LOGIN" and e.get("ip"))
    sudo_by_user = Counter(e["username"] for e in events if e.get("event_type") == "SUDO_USAGE" and e.get("username"))
    critical = [a for a in alerts if a.get("severity") in ("HIGH", "CRITICAL")]

    lines = [
        "=== SIEM COMPLIANCE REPORT ===",
        "",
        "1. AUTHENTICATION FAILURES (by source IP)",
        "-" * 40,
    ]
    for ip, count in failed_by_ip.most_common():
        lines.append(f"  {ip}: {count} failed attempts")
    lines.extend(["", "2. PRIVILEGE ESCALATION (sudo usage by user)", "-" * 40])
    for user, count in Counter(e["username"] for e in events if e.get("event_type") == "SUDO_USAGE").most_common():
        lines.append(f"  {user}: {count} sudo commands")
    lines.extend(["", "3. CRITICAL ALERTS", "-" * 40])
    for a in critical:
        lines.append(f"  [{a.get('severity')}] {a.get('type')}: {a.get('message')}")
    lines.append("")

    return Response(
        "\n".join(lines),
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=compliance-report.txt"},
    )


@app.route("/export/alerts")
def export_alerts():
    """Export persisted alerts to CSV."""
    alerts = load_alerts()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "type", "severity", "message", "event_context"])
    for idx, a in enumerate(alerts, start=1):
        ev = a.get("event") or {}
        ctx = f"{ev.get('event_type','')} | {ev.get('username','')} | {ev.get('ip','')}"
        writer.writerow([
            idx,
            a.get("timestamp", ""),
            a.get("type", ""),
            a.get("severity", ""),
            a.get("message", ""),
            ctx,
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem-alerts.csv"},
    )


if __name__ == "__main__":
    app.run(debug=True)
