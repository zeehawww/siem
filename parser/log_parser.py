"""
Log Parser
===========
Normalizes log lines from multiple real and simulated sources:

  Format A — Simulated auth log (original):
    "Jan 27 11:00:01 kali sshd[3333]: Failed password for invalid user hacker from 10.0.0.1 port 22"

  Format B — macOS ASL / syslog (real system logs):
    "Apr 13 08:57:27 MOHAMMEDs-MacBook-Pro loginwindow[590] <Notice>: USER_PROCESS: 590 console"
    "Apr 13 09:00:00 localsys sshd[0]: Accepted password for azam from 127.0.0.1 port 0"

  Format C — macOS last/wtmp translated (via macos_log_collector):
    "Apr 13 08:57:00 localsys sshd[0]: Accepted password for azam from 127.0.0.1 port 0"

  Format D — Network syslog (RFC 3164, from listener):
    "<34>Apr 13 12:00:01 server sshd[1234]: Failed password for root from 10.0.0.1 port 22"

All formats are normalized to the same event schema used throughout the pipeline.
"""

import re
from datetime import datetime
from typing import Optional

# Extended GeoIP mock mapping by IP prefix
_GEOIP_MAP = [
    (("10.", "172.16.", "192.168.", "127."),  "Internal"),
    (("203.0.",),                              "Russia"),
    (("198.51.",),                             "China"),
    (("45.33.",),                              "United States"),
    (("8.8.", "8.8.4."),                       "United States"),
    (("1.1.1.", "1.0.0."),                     "Australia"),
    (("91.108.", "149.154."),                  "Germany"),
    (("185.220.",),                            "Netherlands"),
    (("104.244.",),                            "United States"),
    (("2.16.",),                               "United Kingdom"),
]


def get_geoip(ip: str) -> str:
    """Mock GeoIP lookup based on IP prefix for demo purposes."""
    if not ip:
        return "Unknown"
    for prefixes, country in _GEOIP_MAP:
        if any(ip.startswith(p) for p in prefixes):
            return country
    return "Unknown"


# ── Regex patterns for each log format ───────────────────────────────────────

# Timestamp pattern (shared): "Apr 13 08:57:27" or "Jan 27 11:00:01"
_TS_RE = r"(\w+\s+\d+\s+\d+:\d+:\d+)"

# Format A/B/C/D: standard sshd failed password
_SSH_FAILED = re.compile(
    _TS_RE + r".*?sshd.*?Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"
)
# sshd accepted password
_SSH_ACCEPT = re.compile(
    _TS_RE + r".*?sshd.*?Accepted (?:password|publickey) for (\w+) from (\d+\.\d+\.\d+\.\d+)"
)
# sudo usage
_SUDO = re.compile(
    _TS_RE + r".*?sudo[:\[].*?(\w+)\s*:.*?COMMAND=(.*?)(?:\s*$)"
)
# sudo alternative (simpler)
_SUDO_ALT = re.compile(
    _TS_RE + r".*?sudo:\s+(\w+)"
)
# macOS USER_PROCESS (console login = local login session started)
_MACOS_USER_PROC = re.compile(
    _TS_RE + r".*?(?:loginwindow|login)\[.*?USER_PROCESS.*?(\w+)(?:\s+\w+)?"
)
# macOS DEAD_PROCESS (logout)
_MACOS_DEAD_PROC = re.compile(
    _TS_RE + r".*?(?:loginwindow|login)\[.*?DEAD_PROCESS"
)
# macOS screensaver / lock
_MACOS_LOCK = re.compile(
    _TS_RE + r".*?(?:ScreenSaverEngine|screensaver|CGSession).*?(?:lock|active|deactivate)", re.I
)
# macOS Touch ID / biometric
_MACOS_BIOMETRIC = re.compile(
    _TS_RE + r".*?(?:biometrickitd|LocalAuthentication|TouchID).*?(?:auth|success|fail)", re.I
)


def _make_event(
    timestamp: str,
    event_type: str,
    username: Optional[str],
    ip: Optional[str],
    severity: str,
    raw_log: str,
    source: str = "simulated",
) -> dict:
    """Build a normalized event dict."""
    # Extract hour for anomaly detection
    hour: Optional[int] = None
    try:
        parts = timestamp.strip().split()
        hour = int(parts[2].split(":")[0])
    except (IndexError, ValueError):
        pass

    return {
        "timestamp": timestamp,
        "hour":      hour,
        "event_type":event_type,
        "username":  username,
        "ip":        ip or "0.0.0.0",
        "location":  get_geoip(ip) if ip else "Local",
        "severity":  severity,
        "raw_log":   raw_log.strip(),
        "source":    source,   # "simulated" | "real_asl" | "real_wtmp" | "network_syslog"
    }


def parse_log(line: str) -> Optional[dict]:
    """
    Parse a single log line from any supported format.
    Returns a normalized event dict, or None if unrecognized.
    """
    line = line.strip()
    if not line:
        return None

    # Strip RFC 3164 PRI header if present
    if line.startswith("<") and ">" in line[:6]:
        line = re.sub(r"^<\d+>", "", line).strip()
        source_tag = "network_syslog"
    elif "localsys" in line or "MOHAMMEDs-MacBook-Pro" in line or "realsys" in line:
        source_tag = "real_system"
    else:
        source_tag = "simulated"

    # ── Failed SSH login ──────────────────────────────────────────────────────
    m = _SSH_FAILED.search(line)
    if m:
        return _make_event(
            timestamp  = m.group(1),
            event_type = "FAILED_LOGIN",
            username   = m.group(2),
            ip         = m.group(3),
            severity   = "MEDIUM",
            raw_log    = line,
            source     = source_tag,
        )

    # ── Successful SSH / password login ──────────────────────────────────────
    m = _SSH_ACCEPT.search(line)
    if m:
        return _make_event(
            timestamp  = m.group(1),
            event_type = "SUCCESS_LOGIN",
            username   = m.group(2),
            ip         = m.group(3),
            severity   = "LOW",
            raw_log    = line,
            source     = source_tag,
        )

    # ── sudo usage ────────────────────────────────────────────────────────────
    m = _SUDO.search(line)
    if m:
        return _make_event(
            timestamp  = m.group(1),
            event_type = "SUDO_USAGE",
            username   = m.group(2),
            ip         = None,
            severity   = "HIGH",
            raw_log    = line,
            source     = source_tag,
        )

    m = _SUDO_ALT.search(line)
    if m:
        return _make_event(
            timestamp  = m.group(1),
            event_type = "SUDO_USAGE",
            username   = m.group(2),
            ip         = None,
            severity   = "HIGH",
            raw_log    = line,
            source     = source_tag,
        )

    # ── macOS console / GUI login ─────────────────────────────────────────────
    m = _MACOS_USER_PROC.search(line)
    if m:
        ts   = m.group(1)
        user = m.group(2) if m.lastindex >= 2 else "unknown"
        return _make_event(
            timestamp  = ts,
            event_type = "SUCCESS_LOGIN",
            username   = user,
            ip         = "127.0.0.1",
            severity   = "LOW",
            raw_log    = line,
            source     = "real_system",
        )

    # ── macOS logout ──────────────────────────────────────────────────────────
    m = _MACOS_DEAD_PROC.search(line)
    if m:
        return _make_event(
            timestamp  = m.group(1),
            event_type = "LOGOUT",
            username   = None,
            ip         = "127.0.0.1",
            severity   = "LOW",
            raw_log    = line,
            source     = "real_system",
        )

    # ── macOS screen lock ─────────────────────────────────────────────────────
    m = _MACOS_LOCK.search(line)
    if m:
        return _make_event(
            timestamp  = m.group(1),
            event_type = "SCREEN_LOCK",
            username   = None,
            ip         = "127.0.0.1",
            severity   = "LOW",
            raw_log    = line,
            source     = "real_system",
        )

    # ── macOS biometric auth ──────────────────────────────────────────────────
    m = _MACOS_BIOMETRIC.search(line)
    if m:
        return _make_event(
            timestamp  = m.group(1),
            event_type = "BIOMETRIC_AUTH",
            username   = None,
            ip         = "127.0.0.1",
            severity   = "LOW",
            raw_log    = line,
            source     = "real_system",
        )

    return None
