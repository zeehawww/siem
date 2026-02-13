from collections import defaultdict

failed_attempts = defaultdict(int)
# Behavior analytics: user -> set of IPs we've seen for successful logins
user_ip_baseline = defaultdict(set)


def analyze_event(event):
    alerts = []

    if event["event_type"] == "FAILED_LOGIN":
        failed_attempts[event["ip"]] += 1
        if failed_attempts[event["ip"]] >= 3:
            alerts.append({
                "type": "BRUTE_FORCE",
                "message": f"Multiple failed logins from {event['ip']}",
                "severity": "HIGH",
                "entity_ip": event["ip"],
            })

    if event["event_type"] == "SUCCESS_LOGIN":
        if failed_attempts[event["ip"]] >= 3:
            alerts.append({
                "type": "COMPROMISED_ACCOUNT",
                "message": f"Successful login after failures from {event['ip']}",
                "severity": "CRITICAL",
                "entity_ip": event["ip"],
            })

        # Behavior analytics: flag login from new IP for this user
        user = event.get("username")
        ip = event.get("ip")
        if user and ip:
            known_ips = user_ip_baseline[user]
            if known_ips and ip not in known_ips:
                alerts.append({
                    "type": "NEW_IP_FOR_USER",
                    "message": f"User {user} logged in from new IP {ip} (previously seen: {', '.join(sorted(known_ips))})",
                    "severity": "MEDIUM",
                    "entity_user": user,
                    "entity_ip": ip,
                })
            user_ip_baseline[user].add(ip)

    if event["event_type"] == "SUDO_USAGE":
        alerts.append({
            "type": "PRIV_ESC",
            "message": f"Sudo used by {event['username']}",
            "severity": "HIGH",
            "entity_user": event["username"],
        })

    if event["event_type"] == "SUCCESS_LOGIN" and event["username"] == "root":
        alerts.append({
            "type": "ROOT_LOGIN",
            "message": f"Root login detected from {event['ip']}",
            "severity": "CRITICAL",
            "entity_ip": event["ip"],
        })

    return alerts
