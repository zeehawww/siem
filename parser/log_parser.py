import re
from datetime import datetime

def parse_log(line):
    event = {
        "timestamp": None,
        "event_type": None,
        "username": None,
        "ip": None,
        "severity": None,
        "raw_log": line.strip()
    }

    time_match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
    if time_match:
        event["timestamp"] = time_match.group(1)

    failed = re.search(r"Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)", line)
    success = re.search(r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)", line)
    sudo = re.search(r"sudo: (\w+)", line)

    if failed:
        event["event_type"] = "FAILED_LOGIN"
        event["username"] = failed.group(2)
        event["ip"] = failed.group(3)
        event["severity"] = "MEDIUM"

    elif success:
        event["event_type"] = "SUCCESS_LOGIN"
        event["username"] = success.group(1)
        event["ip"] = success.group(2)
        event["severity"] = "LOW"

    elif sudo:
        event["event_type"] = "SUDO_USAGE"
        event["username"] = sudo.group(1)
        event["severity"] = "HIGH"

    else:
        return None

    return event
