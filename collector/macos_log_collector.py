"""
macOS Real Log Collector
=========================
Collects real authentication events from macOS system sources:

  Source 1 — ASL database (syslog command)
    Captures: loginwindow USER_PROCESS / DEAD_PROCESS, terminal logins
    Command:  syslog -k Facility auth

  Source 2 — wtmp / last command
    Captures: console logins, TTY sessions, reboots, shutdowns
    Command:  last -w

  Source 3 — macOS Unified Log (log show)
    Captures: sudo events, screensaver lock/unlock, auth policy decisions
    Command:  log show --predicate '...' --style syslog

All events are normalized into syslog-compatible lines so the existing
log_parser can understand them.
"""

import subprocess
import re
from datetime import datetime, timezone
from typing import List, Optional

# ── month abbreviation → number map ──────────────────────────────────────────
_MONTHS = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12,
}

_CURRENT_YEAR = datetime.now(timezone.utc).year


def _run(cmd: List[str], timeout: int = 15) -> List[str]:
    """Run a command, return stdout lines. Silently fail on error."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.splitlines()
    except Exception:
        return []


# ── Source 1: ASL auth events (syslog) ───────────────────────────────────────

def collect_asl_events() -> List[str]:
    """
    Collect all auth-facility events from the ASL database.
    Returns normalized syslog-format lines.
    """
    raw_lines = _run(["syslog", "-k", "Facility", "auth"])
    events = []

    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("ASL Module"):
            continue

        # ASL format: "Apr 13 08:57:27 hostname process[pid] <Level>: message"
        m = re.match(
            r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+)\s+<\w+>:\s+(.*)", line
        )
        if m:
            ts, proc, msg = m.group(1), m.group(2), m.group(3)
            events.append(f"{ts} realsys {proc}: {msg}")

    return events


# ── Source 2: wtmp / last entries ─────────────────────────────────────────────

def collect_wtmp_events() -> List[str]:
    """
    Collect login/logout sessions from wtmp via the `last` command.
    Converts each entry into a syslog-style line the parser can read.
    """
    raw_lines = _run(["last", "-w"])
    events = []

    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("wtmp") or line.startswith("reboot") or line.startswith("shutdown"):
            continue

        # Format: "azam  console  Mon Apr 13 08:57  still logged in"
        # OR:     "azam  ttys007  Mon Apr 13 08:57 - 09:00  (00:02)"
        m = re.match(
            r"^(\S+)\s+(\S+)\s+(?:\S+\s+)?(\w+)\s+(\w+)\s+(\d+)\s+(\d+:\d+)",
            line
        )
        if m:
            user     = m.group(1)
            tty      = m.group(2)
            month    = m.group(3)   # e.g. "Apr"
            day      = m.group(4)   # but sometimes it's the weekday → skip
            day_num  = m.group(5)
            time_str = m.group(6)

            # Skip if month is actually a weekday name
            if month not in _MONTHS:
                # Try next group
                m2 = re.match(
                    r"^(\S+)\s+(\S+)\s+\S+\s+(\w+)\s+(\d+)\s+(\d+:\d+)", line
                )
                if m2:
                    user, tty = m2.group(1), m2.group(2)
                    month, day_num, time_str = m2.group(3), m2.group(4), m2.group(5)
                else:
                    continue

            if month not in _MONTHS:
                continue

            ts = f"{month} {day_num} {time_str}:00"
            # Translate to syslog-like auth line
            if "console" in tty:
                # Console login = system login (like SSH success from local)
                events.append(
                    f"{ts} localsys sshd[0]: Accepted password for {user} from 127.0.0.1 port 0"
                )
            else:
                # TTY session
                events.append(
                    f"{ts} localsys login[0]: USER_PROCESS: {user} on {tty}"
                )

    return events


# ── Source 3: macOS Unified Log (sudo + screensaver) ─────────────────────────

def collect_unified_log_events(lookback_hours: int = 168) -> List[str]:
    """
    Read real sudo and authorization events from macOS Unified Log.
    lookback_hours: how far back to look (default 7 days = 168h)
    """
    raw_lines = _run([
        "log", "show",
        "--last", f"{lookback_hours}h",
        "--predicate",
        'process == "sudo" OR subsystem == "com.apple.authorization" '
        'OR eventMessage CONTAINS "sudo" OR eventMessage CONTAINS "Authentication"',
        "--style", "syslog",
    ], timeout=20)

    events = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("Filtering"):
            continue
        # Unified log syslog style: "Apr 13 08:57:27.123456+0530 hostname proc[pid] <level>: msg"
        m = re.match(
            r"(\w+\s+\d+\s+\d+:\d+:\d+)[\.\d+\-+:]*\s+\S+\s+(\S+)\s+<\w+>:\s+(.*)", line
        )
        if m:
            ts, proc, msg = m.group(1), m.group(2), m.group(3)
            if any(kw in msg.lower() for kw in ["sudo", "auth", "password", "login", "fail", "denied"]):
                events.append(f"{ts} realsys {proc}: {msg}")

    return events


# ── Combined collector ─────────────────────────────────────────────────────────

def collect_real_logs(lookback_hours: int = 168) -> List[str]:
    """
    Collect and merge all real macOS auth events.
    Returns de-duplicated list of syslog-format strings.
    """
    all_events: List[str] = []

    all_events += collect_asl_events()
    all_events += collect_wtmp_events()
    all_events += collect_unified_log_events(lookback_hours)

    # De-duplicate
    seen = set()
    unique = []
    for e in all_events:
        if e not in seen:
            seen.add(e)
            unique.append(e)

    return unique


# ── One-shot: write real events to the log file for pipeline ingestion ─────────

def write_real_logs_to_file(output_path: str, lookback_hours: int = 168) -> int:
    """
    Collect real logs and write them to output_path in syslog format
    (compatible with the existing simulated_auth.log parser).
    Returns the number of events written.
    """
    events = collect_real_logs(lookback_hours)
    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        for line in events:
            f.write(line + "\n")
    return len(events)
