# 🛡 Sentinel SIEM Mini

A real-time Security Information and Event Management (SIEM) platform — built in Python and Flask — that ingests live macOS system logs and detects threats with five novel engines not found in commercial tools.

> **GitHub:** [github.com/zeehawww/siem](https://github.com/zeehawww/siem)  
> **Full technical report:** [docs/PROJECT_REPORT.md](docs/PROJECT_REPORT.md)

---

## What It Does

- Collects real authentication events from your Mac (ASL, wtmp, Unified Log, UDP syslog)
- Parses every log line into a clean JSON event schema
- Runs MITRE ATT&CK-mapped detection rules to raise alerts
- Explains every alert in plain English — no guesswork for the analyst
- Builds a persistent reputation score for every IP and user it has ever seen
- Automatically writes plain-English incident reports — no manual work

---

## Five Novel Features

| Feature | What It Does |
|---------|-------------|
| **Alert Explainability (XAI)** | Every alert has a "Why?" panel with exact evidence and counterfactuals |
| **Confidence Decay Engine** | Risk scores halve every hour with no follow-up — queues stay clean automatically |
| **Threat Narrative Generator** | Auto-writes plain-English attack stories per entity — no analyst needed |
| **Behavioral DNA Fingerprinting** | Groups attacks by *pattern*, not identity — catches cross-entity campaigns |
| **Analyst Feedback Loop** | Mark True/False Positive → confidence adjusts instantly, no code changes |

---

## Quick Start

```bash
git clone https://github.com/zeehawww/siem.git
cd siem
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python dashboard/app.py
```

Open **http://127.0.0.1:5001** — real logs are collected automatically on first start.

---

## Tech Stack

Python 3.9 · Flask · Vanilla HTML/CSS · Chart.js · No external APIs · Fully offline

---

## Dashboard Pages

`Overview` · `Live Data` · `Log Explorer` · `Analysis` · `Alerts` · `Attack Chain` · `Narratives` · `Reputation` · `DNA` · `Simulator` · `Compliance` · `Full Report`

---

For the full technical breakdown — algorithms, architecture, commercial SIEM comparison — see **[docs/PROJECT_REPORT.md](docs/PROJECT_REPORT.md)**.
