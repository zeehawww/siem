# 🛡 Sentinel SIEM Mini

> A production-grade Security Information and Event Management (SIEM) platform built from scratch in Python + Flask — ingesting **real macOS system events** and applying five novel detection-engineering engines not found in any commercial SIEM product today.

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat&logo=flask)
![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey?style=flat&logo=apple)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## 📋 Table of Contents

- [What Is This?](#what-is-this)
- [What Makes It Different?](#what-makes-it-different)
- [Features](#features)
- [Architecture](#architecture)
- [Novel Algorithms](#novel-algorithms)
- [Tech Stack](#tech-stack)
- [Installation & Running](#installation--running)
- [Dashboard Pages](#dashboard-pages)
- [Comparison with Commercial SIEMs](#comparison-with-commercial-siems)
- [Project Structure](#project-structure)

---

## What Is This?

Sentinel SIEM Mini is a fully functional Security Operations Centre (SOC) platform that:

1. **Automatically collects** real authentication events from your macOS machine (ASL database, login history, Unified Log, and network syslog)
2. **Parses and normalises** every raw log line into a structured JSON event schema
3. **Detects threats** using MITRE ATT&CK-mapped detection rules with built-in explainability
4. **Enriches findings** with behavioral DNA fingerprinting and entity reputation heat scores
5. **Generates plain-English incident stories** automatically — no analyst writing required
6. **Presents everything** in a dark-themed, professional analyst dashboard

This is a research prototype demonstrating five novel detection-engineering features that identify and fill real gaps in today's SIEM landscape.

---

## What Makes It Different?

Commercial SIEMs (Splunk Enterprise Security, IBM QRadar, Microsoft Sentinel) all follow the same design from the 2000s:

> **Collect logs → match rules → fire alert → leave the analyst alone with a list.**

This leads to:
- **Alert fatigue** — SOC teams receive 1,000–10,000 alerts/day; 45%+ go uninvestigated
- **No transparency** — analysts cannot explain *why* a rule fired without reading source code
- **Stale queues** — old alerts remain at full risk score forever unless manually closed
- **Manual reporting** — analysts spend hours writing incident summaries after every attack

Sentinel addresses all four pain points with purpose-built engines.

---

## Features

### 🔴 Feature 1 — Alert Explainability Engine (XAI)

Every alert ships with a built-in **"Why?" panel** containing:
- **Evidence factors** — the exact conditions that triggered the rule, with importance weights (HIGH / MEDIUM)
- **Counterfactuals** — what hasn't happened yet, and what the *next event* would do to severity
- **Severity rationale** — a plain-English justification for the assigned score

> No commercial SIEM implements structured per-alert explainability. Analysts currently reverse-engineer alerts by reading detection rule source code.

---

### 📉 Feature 2 — Confidence Decay Engine

Alert risk scores **decay automatically over time** using exponential decay with a 1-hour half-life:

```
Risk(t) = BaseScore × 0.5 ^ (elapsed_seconds / 3600)
```

A HIGH alert with no follow-up activity is automatically de-prioritised mathematically. Queues stay clean without human intervention.

> No SIEM ages stale alerts automatically. Every existing tool treats a week-old alert identically to a brand-new one.

---

### 📖 Feature 3 — Threat Narrative Generator

Groups all alerts by entity (IP / user) and synthesises a **plain-English incident story**:

> *"The IP 127.0.0.1 was involved in 2 security events. At Oct 2 at 17:22, this entity authenticated outside business hours (40 occurrences). At Mar 2 at 00:47, this entity logged in directly as root."*

Also detects known MITRE kill chains from the alert sequence:

> *"Full attack chain detected: credential access → initial access → privilege escalation."*

> Analysts currently write these summaries manually after incidents. This engine produces them in milliseconds.

---

### 🧬 Feature 4 — Behavioral DNA Fingerprinting

Every alert receives a **behavioral hash** computed from its attack pattern — deliberately *excluding* entity identity (no IP, no username):

```
fingerprint = SHA-256({
    alert_type, severity, mitre_tactic,
    event_type, time_of_day, origin
})[:8]
```

Two completely different attackers using the same technique at the same time of day receive **identical DNA**. This enables cross-entity campaign detection impossible in standard SIEMs.

---

### 🔥 Feature 5 — Entity Reputation Heat Scoring

Builds a **persistent, self-growing reputation score** for every IP address and username purely from observed alert history — no external threat intelligence feeds required:

```
Score += severity_weight + type_weight   (per alert)
Score  = Score × 0.85                    (decay per pipeline run)
Score  = min(Score, 1000)                (cap)
```

Scores accumulate across sessions. An entity that attacked last week retains an elevated score today.

---

### ✅ Feature 6 — Analyst Feedback Loop

Analysts can mark any alert: **True Positive / False Positive / Investigate**. Verdicts are linked to the alert's DNA fingerprint and automatically adjust confidence for all future matching alerts — with zero code changes and zero retraining.

---

### 🎯 Feature 7 — MITRE ATT&CK Detection Rules

Six rule types, each mapped to a specific ATT&CK technique:

| Rule | MITRE | Trigger |
|------|-------|---------|
| `BRUTE_FORCE` | T1110 | ≥ 3 failed logins from same IP |
| `COMPROMISED_ACCOUNT` | T1078 | Success after brute-force chain |
| `NEW_IP_FOR_USER` | T1021 | User authenticates from unknown IP |
| `AFTER_HOURS_LOGIN` | T1078 | Login outside 09:00–17:00 |
| `PRIV_ESC` | T1548 | sudo command executed |
| `ROOT_LOGIN` | T1078.003 | Direct root login |

---

### 🧪 Feature 8 — What-If Attack Simulator

Test whether the detection engine would catch a specific MITRE ATT&CK technique against synthetic target data — without waiting for a real attack. Useful for validating detection coverage before deployment.

---

### 📊 Feature 9 — Real-Time Ingestion from macOS

On startup the platform automatically collects the last 7 days of authentication events from:

| Source | Command | Events captured |
|--------|---------|-----------------|
| Apple System Logger (ASL) | `syslog -k Facility auth` | Login decisions, terminal sessions |
| Login history (wtmp) | `last -w` | Console logins, TTY sessions, reboots |
| Unified Log | `log show --predicate '...'` | sudo events, auth policy decisions |
| Network syslog (UDP) | RFC 3164 on port 514 | Forwarded logs from any LAN device |

---

### 📄 Feature 10 — Compliance & Audit Reporting

Generates an audit-ready compliance report including:
- Authentication failure breakdown by source IP
- Privilege escalation (sudo) usage by user with risk classification
- Critical and HIGH alerts requiring documented analyst response
- Exportable as PDF and plain-text for audit documentation

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES                             │
│  macOS ASL │ wtmp/last │ Unified Log │ Network UDP Syslog       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                    [COLLECT]
              collector/macos_log_collector.py
              collector/syslog_listener.py
                         │
                    [PARSE]
              parser/log_parser.py
              → {timestamp, user, IP, event_type, severity, source}
                         │
                    [DETECT]
              analyzer/detection_engine.py
              → Alerts with XAI + confidence decay
                         │
                    [ENRICH]
              analyzer/dna_engine.py         → behavioral fingerprint
              analyzer/reputation_engine.py  → heat scores
              analyzer/narrative_engine.py   → incident stories
              analyzer/feedback_engine.py    → analyst verdicts
                         │
                    [PERSIST]
              storage/events.json
              storage/alerts.json
              storage/reputation.json
              storage/feedback.json
                         │
                    [PRESENT]
              dashboard/app.py   (Flask)
              dashboard/templates/*.html
              dashboard/static/style.css
```

---

## Novel Algorithms

| Algorithm | Applied To | Source Field |
|-----------|-----------|-------------|
| Exponential decay (`0.5^t`) | Alert confidence scoring | Nuclear physics / mathematics |
| SHA-256 behavioral hashing | DNA fingerprinting | Cryptography (novel application) |
| Weighted additive scoring + decay | Entity reputation | Credit scoring theory |
| Subsequence pattern matching | MITRE kill-chain detection | Formal language theory |
| Counterfactual XAI | Per-alert explainability | AI explainability research |

> The individual mathematical building blocks are established. The contribution is applying them — in combination — to the specific unsolved problems of SIEM alert fatigue, explainability, and stale noise. None of these five applications exist in any commercial or open-source SIEM.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.9+, Flask 3.x |
| Real-time collection | `subprocess`, `threading`, `socket` (UDP) |
| Detection engine | Custom rule engine with stateful UEBA |
| Frontend | Vanilla HTML5, CSS3 (Inter font, dark theme, CSS Grid) |
| Charts | Chart.js (CDN) |
| Storage | JSON flat files (no database dependency) |
| Log sources | macOS ASL, wtmp, Unified Log, UDP syslog RFC 3164 |

> No external APIs. No cloud. No ML training datasets. Runs fully offline on any macOS machine.

---

## Installation & Running

```bash
# 1. Clone the repository
git clone https://github.com/zeehawww/siem.git
cd siem

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the dashboard
python dashboard/app.py

# 5. Open in browser
open http://127.0.0.1:5001
```

On first start, the system **automatically collects real macOS logs** in the background and runs the full pipeline. No manual setup needed.

---

## Dashboard Pages

| Page | URL | Purpose |
|------|-----|---------|
| Overview | `/` | Live stats, pipeline stages, feature showcase |
| Live Data | `/live-logs` | Real-time ingestion control panel |
| Log Explorer | `/logs` | Searchable, filterable event table + CSV export |
| Analysis | `/analysis` | Severity distribution chart, top attackers, detection rules |
| Alerts | `/alerts` | Alert queue with XAI panel, decay meters, feedback |
| Attack Chain | `/correlation` | Multi-step kill-chain timeline per entity |
| Narratives | `/narrative` | Auto-generated incident stories per threat actor |
| Reputation | `/reputation` | Entity heat score leaderboard |
| DNA | `/dna` | Behavioral pattern fingerprint groups |
| Simulator | `/simulator` | What-If MITRE attack simulation |
| Compliance | `/compliance` | Audit-ready report + export |
| Full Report | `/export/report` | Printable security report with all findings |

---

## Comparison with Commercial SIEMs

| Capability | Splunk ES | IBM QRadar | MS Sentinel | **This Project** |
|-----------|----------|------------|-------------|-----------------|
| Real-time log ingestion | ✅ | ✅ | ✅ | ✅ |
| MITRE ATT&CK mapping | ✅ | ✅ | ✅ | ✅ |
| GeoIP enrichment | ✅ | ✅ | ✅ | ✅ |
| Compliance reporting | ✅ | ✅ | ✅ | ✅ |
| Alert Explainability (XAI) | ❌ | ❌ | ❌ | ✅ **Novel** |
| Confidence Decay Engine | ❌ | ❌ | ❌ | ✅ **Novel** |
| Auto Threat Narrative Gen. | ❌ | ❌ | ❌ | ✅ **Novel** |
| Behavioral DNA Fingerprint | ❌ | ❌ | ❌ | ✅ **Novel** |
| Feedback Loop (no retrain) | ❌ | ❌ | ❌ | ✅ **Novel** |
| What-If Attack Simulator | ❌ | ❌ | ❌ | ✅ |
| Requires external TI feeds | ✅ (paid) | ✅ (paid) | ✅ (paid) | ❌ Self-builds |
| Approximate cost | £150K+/yr | £80K+/yr | Pay-per-GB | Free / open |

---

## Project Structure

```
siem-mini/
│
├── main.py                          # Pipeline entry point
├── requirements.txt
│
├── collector/
│   ├── macos_log_collector.py       # Real macOS log ingestion (ASL, wtmp, Unified)
│   ├── syslog_listener.py           # UDP network syslog receiver
│   └── log_collector.py             # File-based collector (fallback)
│
├── parser/
│   └── log_parser.py                # Multi-format log normaliser
│
├── analyzer/
│   ├── detection_engine.py          # Rule engine + XAI + confidence decay
│   ├── dna_engine.py                # Behavioral DNA fingerprinting
│   ├── reputation_engine.py         # Entity heat score system
│   ├── narrative_engine.py          # Threat narrative generator (NLG)
│   └── feedback_engine.py           # Analyst feedback loop
│
├── alerts/
│   └── alert_manager.py             # Alert persistence layer
│
├── dashboard/
│   ├── app.py                       # Flask application + all routes
│   ├── static/style.css             # Dark-theme design system
│   └── templates/
│       ├── home.html                # Overview / SOC dashboard
│       ├── live_logs.html           # Live data ingestion
│       ├── logs.html                # Log Explorer
│       ├── analysis.html            # Detection analytics
│       ├── alerts.html              # Alert queue (XAI + feedback)
│       ├── correlation.html         # Attack chain timeline
│       ├── narrative.html           # Threat narratives
│       ├── reputation.html          # Entity reputation
│       ├── dna.html                 # DNA fingerprint groups
│       ├── simulator.html           # What-If simulator
│       ├── compliance.html          # Compliance report
│       ├── report_export.html       # Full printable report
│       └── _navbar.html             # Shared navigation
│
├── logs/
│   ├── real_auth.log                # Live macOS events (auto-collected)
│   └── simulated_auth.log           # Fallback simulation dataset
│
└── storage/
    ├── events.json                  # Normalised event store
    ├── alerts.json                  # Persisted alerts
    ├── reputation.json              # Entity reputation scores
    └── feedback.json                # Analyst verdict history
```

---

## License

MIT — free to use, study, and extend.

---

*Built as a research prototype demonstrating the next generation of SIEM design — where every alert explains itself, stale threats expire automatically, and incident reports write themselves.*
