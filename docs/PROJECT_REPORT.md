# Aegis SIEM Mini — Full Project Report

## Overview

Aegis SIEM Mini is a Security Information and Event Management platform built from scratch in Python and Flask. It ingests real macOS system logs, detects threats using MITRE ATT&CK-mapped rules, and presents findings in a professional analyst dashboard — with five detection-engineering features not found in any commercial SIEM today.

---

## The Problem With Existing SIEMs

Commercial SIEMs like Splunk, IBM QRadar, and Microsoft Sentinel all follow the same design from the early 2000s. They collect logs, match rules, fire alerts, and stop there. The analyst is left with a list of hundreds of unexplained alarms they don't have time to read.

This causes three well-documented industry problems:

- **Alert fatigue** — SOC teams receive 1,000–10,000 alerts per day; over 45% go uninvestigated (IBM X-Force, 2023)
- **No transparency** — analysts cannot explain why a rule fired without reading detection source code
- **Stale queues** — old alerts stay at full risk score until a human manually closes them

This project was built to address all three with novel engineering.

---

## What It Does

### Pipeline (6 Stages)

```
macOS ASL + wtmp + Unified Log + UDP Syslog
           ↓
    [1] COLLECT   → Pull auth events from system logs
           ↓
    [2] PARSE     → Normalize every line to structured JSON
           ↓
    [3] DETECT    → Fire MITRE-mapped alerts with XAI + decay
           ↓
    [4] ENRICH    → DNA fingerprinting + reputation scoring
           ↓
    [5] NARRATE   → Auto-generate plain-English incident stories
           ↓
    [6] PRESENT   → Flask dashboard with analyst feedback loop
```

### Real Data Sources

| Source | Command | What It Captures |
|--------|---------|-----------------|
| Apple System Logger (ASL) | `syslog -k Facility auth` | Login decisions, terminal sessions |
| Login history (wtmp) | `last -w` | Console logins, TTY sessions, reboots |
| Unified Log | `log show --predicate` | sudo events, auth policy |
| Network syslog (UDP) | RFC 3164, port 514 | Forwarded logs from any LAN device |

---

## Five Novel Features

### 1. Alert Explainability Engine (XAI)

Every alert has a built-in "Why?" panel:
- **Factors** — the exact evidence that triggered it, with importance weights (HIGH / MEDIUM)
- **Counterfactuals** — what hasn't happened yet, and what the next event would do to severity
- **Severity rationale** — plain-English explanation for the assigned score

No commercial SIEM implements structured per-alert explainability. Analysts currently reverse-engineer alerts by reading detection source code.

### 2. Confidence Decay Engine

Risk scores decay automatically over time:

```
Risk(t) = BaseScore × 0.5 ^ (elapsed_seconds / 3600)
```

A HIGH alert with no follow-up after 2 hours is at 25% of its original score. Queues stay clean without human intervention.

No SIEM ages alerts automatically. Every existing tool treats a week-old alert the same as a brand-new one.

### 3. Threat Narrative Generator

Groups all alerts by entity and synthesises a plain-English incident story:

> *"The IP 127.0.0.1 was involved in 2 security events. At Oct 2 at 17:22, this entity authenticated outside business hours (40 occurrences). At Mar 2 at 00:47, this entity logged in directly as root."*

Also detects known MITRE kill chains:

> *"Full attack chain: credential access → initial access → privilege escalation."*

Analysts write these summaries manually after incidents — taking hours. This engine produces them in milliseconds.

### 4. Behavioral DNA Fingerprinting

Every alert gets a hash of its behavioral pattern — with entity identity deliberately excluded:

```
fingerprint = SHA-256({
    alert_type, severity, mitre_tactic,
    event_type, time_of_day, origin  ← NO IP, NO USERNAME
})[:8]
```

Two different attackers using the same technique at the same time of day share identical DNA. This enables cross-entity campaign detection that is impossible in standard SIEMs.

### 5. Analyst Feedback Loop

Analysts mark any alert as True Positive / False Positive / Investigate. Verdicts link to the alert's DNA fingerprint and adjust confidence for all future matching alerts — zero code changes, zero retraining.

---

## Detection Rules

| Rule | MITRE Technique | Trigger |
|------|----------------|---------|
| BRUTE_FORCE | T1110 Credential Access | 3+ failed logins from same IP |
| COMPROMISED_ACCOUNT | T1078 Initial Access | Success after brute-force chain |
| NEW_IP_FOR_USER | T1021 Lateral Movement | User logs in from unknown IP |
| AFTER_HOURS_LOGIN | T1078 Initial Access | Login outside 09:00–17:00 |
| PRIV_ESC | T1548 Privilege Escalation | sudo command executed |
| ROOT_LOGIN | T1078.003 | Direct root login |

---

## Dashboard Pages

| Page | Purpose |
|------|---------|
| Overview `/` | Live stats, pipeline diagram, feature showcase |
| Live Data `/live-logs` | One-click real macOS log ingestion |
| Log Explorer `/logs` | Searchable, filterable event table + CSV export |
| Analysis `/analysis` | Severity distribution chart, top attackers, detection rules |
| Alerts `/alerts` | Alert queue with XAI panel, decay meters, feedback |
| Attack Chain `/correlation` | Kill-chain timeline per entity |
| Narratives `/narrative` | Auto-generated incident stories |
| Reputation `/reputation` | Entity heat score leaderboard |
| DNA `/dna` | Behavioral pattern fingerprint groups |
| Simulator `/simulator` | What-If MITRE attack simulation |
| Compliance `/compliance` | Audit-ready report + export |
| Full Report `/export/report` | Printable security report |

---

## Algorithms Used

| Algorithm | Applied To | Origin Field |
|-----------|-----------|-------------|
| Exponential decay `0.5^t` | Alert confidence scoring | Nuclear physics / mathematics |
| SHA-256 behavioral hashing | DNA fingerprinting | Cryptography (novel application) |
| Weighted additive scoring + decay | Entity reputation | Credit scoring theory |
| Subsequence pattern matching | MITRE kill-chain detection | Formal language theory |
| Counterfactual XAI | Per-alert explainability | AI explainability research |

The individual mathematical building blocks are established. The contribution is applying them — in combination — to the specific unsolved problems of SIEM alert fatigue, explainability, and stale noise. None of these five applications exist in any commercial or open-source SIEM.

---

## Comparison with Commercial SIEMs

| Capability | Splunk ES | IBM QRadar | MS Sentinel | This Project |
|-----------|----------|------------|-------------|-------------|
| Real-time log ingestion | ✅ | ✅ | ✅ | ✅ |
| MITRE ATT&CK mapping | ✅ | ✅ | ✅ | ✅ |
| GeoIP enrichment | ✅ | ✅ | ✅ | ✅ |
| Compliance reporting | ✅ | ✅ | ✅ | ✅ |
| Alert Explainability (XAI) | ❌ | ❌ | ❌ | ✅ Novel |
| Confidence Decay Engine | ❌ | ❌ | ❌ | ✅ Novel |
| Auto Threat Narrative Gen. | ❌ | ❌ | ❌ | ✅ Novel |
| Behavioral DNA Fingerprint | ❌ | ❌ | ❌ | ✅ Novel |
| Feedback Loop (no retrain) | ❌ | ❌ | ❌ | ✅ Novel |
| What-If Attack Simulator | ❌ | ❌ | ❌ | ✅ |
| External TI feeds required | ✅ paid | ✅ paid | ✅ paid | ❌ Self-builds |
| Cost | £150K+/yr | £80K+/yr | Pay-per-GB | Free |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.9+, Flask 3.x |
| Real-time collection | subprocess, threading, socket (UDP) |
| Detection engine | Custom rule engine with stateful UEBA |
| Frontend | HTML5, CSS3 (Inter font, dark theme, CSS Grid) |
| Charts | Chart.js |
| Storage | JSON flat files — no database dependency |
| Log sources | macOS ASL, wtmp, Unified Log, UDP syslog RFC 3164 |

No external APIs. No cloud. No ML training datasets. Runs fully offline on any macOS machine.

---

## Project Structure

```
siem-mini/
├── main.py                          # Pipeline entry point
├── requirements.txt
├── collector/
│   ├── macos_log_collector.py       # Real macOS ingestion
│   └── syslog_listener.py           # UDP network syslog
├── parser/
│   └── log_parser.py                # Multi-format normaliser
├── analyzer/
│   ├── detection_engine.py          # Rules + XAI + decay
│   ├── dna_engine.py                # DNA fingerprinting
│   ├── reputation_engine.py         # Heat scoring
│   ├── narrative_engine.py          # Narrative generator
│   └── feedback_engine.py           # Analyst feedback
├── alerts/
│   └── alert_manager.py
├── dashboard/
│   ├── app.py                       # Flask app + all routes
│   ├── static/style.css
│   └── templates/                   # 12 dashboard pages
├── logs/
│   ├── real_auth.log                # Auto-collected
│   └── simulated_auth.log           # Fallback dataset
└── storage/
    ├── events.json
    ├── alerts.json
    ├── reputation.json
    └── feedback.json
```

---

*This document is the full technical reference. See [README.md](../README.md) for quick-start instructions.*
