import re
from datetime import datetime

# Extended GeoIP mock mapping by IP prefix
_GEOIP_MAP = [
    (("10.", "172.16.", "192.168."),            "Internal"),
    (("203.0.",),                               "Russia"),
    (("198.51.",),                              "China"),
    (("45.33.",),                               "United States"),
    (("8.8.", "8.8.4."),                        "United States"),
    (("1.1.1.", "1.0.0."),                      "Australia"),
    (("91.108.", "149.154."),                   "Germany"),
    (("185.220.",),                             "Netherlands"),
    (("104.244.",),                             "United States"),
    (("2.16.",),                                "United Kingdom"),
]


def get_geoip(ip: str) -> str:
    """Mock GeoIP lookup based on IP prefix for demo purposes."""
    if not ip:
        return "Unknown"
    for prefixes, country in _GEOIP_MAP:
        if any(ip.startswith(p) for p in prefixes):
            return country
    return "Unknown"


def parse_log(line: str) -> dict | None:
    event = {
        "timestamp": None,
        "hour": None,          # int hour-of-day for anomaly detection
        "event_type": None,
        "username": None,
        "ip": None,
        "location": None,
        "severity": None,
        "raw_log": line.strip(),
    }

    time_match = re.match(r"(\w+\s+\d+\s+(\d+):\d+:\d+)", line)
    if time_match:
        event["timestamp"] = time_match.group(1)
        try:
            event["hour"] = int(time_match.group(2))
        except ValueError:
            event["hour"] = None

    failed  = re.search(r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)", line)
    success = re.search(r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)", line)
    sudo    = re.search(r"sudo:\s+(\w+)", line)

    if failed:
        event["event_type"] = "FAILED_LOGIN"
        event["username"]   = failed.group(1)
        event["ip"]         = failed.group(2)
        event["location"]   = get_geoip(event["ip"])
        event["severity"]   = "MEDIUM"

    elif success:
        event["event_type"] = "SUCCESS_LOGIN"
        event["username"]   = success.group(1)
        event["ip"]         = success.group(2)
        event["location"]   = get_geoip(event["ip"])
        event["severity"]   = "LOW"

    elif sudo:
        event["event_type"] = "SUDO_USAGE"
        event["username"]   = sudo.group(1)
        event["location"]   = "Local"
        event["severity"]   = "HIGH"

    else:
        return None

    return event
