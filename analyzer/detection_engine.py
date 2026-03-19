from collections import defaultdict

failed_attempts = defaultdict(int)
# Behavior analytics: user -> set of IPs we've seen for successful logins
user_ip_baseline = defaultdict(set)

# MITRE ATT&CK tactic mapping per alert type
MITRE_TACTICS = {
    "BRUTE_FORCE":          {"tactic": "Credential Access",   "technique": "T1110"},
    "COMPROMISED_ACCOUNT":  {"tactic": "Initial Access",      "technique": "T1078"},
    "NEW_IP_FOR_USER":      {"tactic": "Lateral Movement",    "technique": "T1021"},
    "PRIV_ESC":             {"tactic": "Privilege Escalation","technique": "T1548"},
    "ROOT_LOGIN":           {"tactic": "Privilege Escalation","technique": "T1078.003"},
    "AFTER_HOURS_LOGIN":    {"tactic": "Initial Access",      "technique": "T1078"},
}

# Risk scores per severity tier (0-100)
RISK_SCORES = {
    "CRITICAL": 90,
    "HIGH":     70,
    "MEDIUM":   45,
    "LOW":      15,
}

# Business hours window (24h format, inclusive)
BUSINESS_HOURS = (9, 17)  # 9 AM – 5 PM


def _parse_hour(timestamp: str) -> int | None:
    """Extract the hour from timestamps like 'Jan 27 11:00:01'."""
    try:
        parts = timestamp.strip().split()
        # Format: Month Day HH:MM:SS
        time_part = parts[2]
        return int(time_part.split(":")[0])
    except (IndexError, ValueError):
        return None


def _enrich_alert(alert: dict) -> dict:
    """Attach MITRE tactic info and a numeric risk score to an alert."""
    alert_type = alert.get("type", "")
    mitre = MITRE_TACTICS.get(alert_type, {"tactic": "Unknown", "technique": "N/A"})
    alert["mitre_tactic"] = mitre["tactic"]
    alert["mitre_technique"] = mitre["technique"]
    alert["risk_score"] = RISK_SCORES.get(alert.get("severity", "LOW"), 15)
    return alert


def analyze_event(event):
    alerts = []

    if event["event_type"] == "FAILED_LOGIN":
        failed_attempts[event["ip"]] += 1
        if failed_attempts[event["ip"]] >= 3:
            alerts.append(_enrich_alert({
                "type": "BRUTE_FORCE",
                "message": f"Multiple failed logins from {event['ip']}",
                "severity": "HIGH",
                "entity_ip": event["ip"],
            }))

    if event["event_type"] == "SUCCESS_LOGIN":
        if failed_attempts[event["ip"]] >= 3:
            alerts.append(_enrich_alert({
                "type": "COMPROMISED_ACCOUNT",
                "message": f"Successful login after failures from {event['ip']}",
                "severity": "CRITICAL",
                "entity_ip": event["ip"],
            }))

        # Behavior analytics: flag login from new IP for this user
        user = event.get("username")
        ip = event.get("ip")
        if user and ip:
            known_ips = user_ip_baseline[user]
            if known_ips and ip not in known_ips:
                alerts.append(_enrich_alert({
                    "type": "NEW_IP_FOR_USER",
                    "message": f"User {user} logged in from new IP {ip} (previously seen: {', '.join(sorted(known_ips))})",
                    "severity": "MEDIUM",
                    "entity_user": user,
                    "entity_ip": ip,
                }))
            user_ip_baseline[user].add(ip)

        # Off-hours anomaly: flag logins outside business hours
        ts = event.get("timestamp", "")
        hour = _parse_hour(ts) if ts else None
        if hour is not None and not (BUSINESS_HOURS[0] <= hour < BUSINESS_HOURS[1]):
            alerts.append(_enrich_alert({
                "type": "AFTER_HOURS_LOGIN",
                "message": f"Login by {event.get('username', 'unknown')} from {ip} at hour {hour:02d}:xx (outside business hours)",
                "severity": "MEDIUM",
                "entity_user": event.get("username"),
                "entity_ip": ip,
            }))

    if event["event_type"] == "SUDO_USAGE":
        alerts.append(_enrich_alert({
            "type": "PRIV_ESC",
            "message": f"Sudo used by {event['username']}",
            "severity": "HIGH",
            "entity_user": event["username"],
        }))

    if event["event_type"] == "SUCCESS_LOGIN" and event["username"] == "root":
        alerts.append(_enrich_alert({
            "type": "ROOT_LOGIN",
            "message": f"Root login detected from {event['ip']}",
            "severity": "CRITICAL",
            "entity_ip": event["ip"],
        }))

    return alerts
