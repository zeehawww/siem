# Mini SIEM – Auth Log Detection Demo

A small, educational SIEM‑style project that:

- **Collects** SSH authentication logs from `logs/simulated_auth.log`
- **Parses & normalizes** them into structured JSON events
- **Runs rule‑based detections** (brute force, compromised account, sudo usage, root login)
- **Displays dashboards** for events, analysis metrics and alerts via a Flask UI

Perfect as a **mini project / portfolio piece** to explain end‑to‑end security monitoring.

---

## 1. Tech stack

- **Language**: Python 3.11+
- **Backend**: Flask (simple routes, no DB)
- **Frontend**: HTML + CSS + Chart.js (via CDN)
- **Storage**: JSON file (`storage/events.json`)

---

## 2. Project structure (high level)

- `main.py` – orchestrates the SIEM pipeline:
  - reads raw log file
  - parses lines into events
  - runs detection rules
  - appends events to `storage/events.json`
- `collector/log_collector.py` – reads raw logs
- `parser/log_parser.py` – regex‑based parser for auth logs
- `analyzer/detection_engine.py` – detection rules
- `alerts/alert_manager.py` – prints alerts to console
- `dashboard/app.py` – Flask web app (logs, analysis, alerts)
- `dashboard/templates/*.html` – UI pages
- `dashboard/static/style.css` – modern dark dashboard UI

---

## 3. Setup & installation

From the project root (`siem-mini`):

```bash
python3 -m venv .venv
source .venv/bin/activate  # on macOS / Linux
# .venv\Scripts\activate   # on Windows (PowerShell / cmd)

pip install -r requirements.txt
```

---

## 4. Running the pipeline + dashboard

### Step 1 – Run the SIEM pipeline once

This ingests `logs/simulated_auth.log` and populates `storage/events.json`:

```bash
python3 main.py
```

### Step 2 – Start the Flask dashboard

You can run the dashboard in **either** of these ways:

**Option A – From the project root (recommended)**

```bash
python3 -m dashboard.app
```

**Option B – From inside the `dashboard` folder**

```bash
cd dashboard
python3 app.py
```

In both cases Flask runs on `http://127.0.0.1:5000`. Open this in the browser.

> You can re‑run `python3 main.py` any time you change the sample log file
> or want to re‑ingest events. The dashboard reads from `storage/events.json`.

---

## 5. Pages in the dashboard

- **Overview (`/`)**
  - High‑level explanation of the SIEM pipeline
  - Quick buttons to jump to Logs and Analysis
  - “How to showcase” card (great for interviews / demos)

- **Logs (`/logs`)**
  - Normalized events table (timestamp, user, IP, event type, severity)
  - Client‑side **search** (user/IP/event type)
  - **Severity filter** (Low / Medium / High / Critical)
  - Raw log snippet with hover tooltip

- **Analysis (`/analysis`)**
  - Summary metrics (total events, failed logins, success logins, sudo usage, high/critical count, unique IPs, last timestamp)
  - Chart.js bar chart of severity distribution
  - Explanation of each detection rule
  - “Re‑run pipeline” button that triggers `main.py` again

- **Alerts (`/alerts`)**
  - Replays events through `analyzer.detection_engine.analyze_event`
  - Shows an ordered list of alerts with type, severity and message

---

## 6. How to explain this as a mini project

When presenting:

1. **Architecture**: Walk through the pipeline modules:
   - `collector` → `parser` → `analyzer` → `alerts` + `dashboard`.
2. **Data flow**: Point to the sample log file and show how it becomes JSON events.
3. **Detection logic**: Explain each rule and why it matters (e.g. brute force, compromised account).
4. **UI demo**:
   - Show the **Logs** page, search by IP, filter by severity.
   - Show the **Analysis** page and highlight severity distribution + metrics.
   - Show the **Alerts** page and pick one alert to explain the scenario.
5. **Extension ideas** (optional):
   - Add more log sources (web server logs, OS logs).
   - Store events in a database instead of JSON.
   - Add correlation rules across multiple hosts.

This gives you a clear story: *“I built a mini SIEM that simulates a real SOC pipeline from raw logs all the way to an analyst‑friendly dashboard.”*

