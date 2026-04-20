"""
Syslog Listener
================
Novel Feature — Live Log Ingestion via UDP Syslog (RFC 3164)

Listens on UDP port 5140 (non-privileged) for incoming syslog messages
from any device on the local network. Any machine can be configured to
forward logs here:

  Linux:  /etc/rsyslog.conf → add:  *.* @<this-ip>:5140
  macOS:  newsyslog / logger command
  Router: syslog forwarding setting

Received messages are appended to a configured log file in real time (e.g. network_syslog.log) and
the pipeline is re-run automatically after a batch window.

Usage (standalone):
    python3 -m collector.syslog_listener

Usage (from Flask via background thread):
    from collector.syslog_listener import start_listener_thread
    start_listener_thread(log_file, on_new_events_callback)
"""

import socket
import threading
import time
import os
import re
from datetime import datetime

# Default port — 514 requires root, 5140 is user-accessible
SYSLOG_PORT = 5140
SYSLOG_HOST = "0.0.0.0"

# Batch window: collect messages for N seconds before triggering pipeline
BATCH_WINDOW_SECONDS = 5

_listener_active = False
_listener_thread = None


def _parse_rfc3164(raw: str) -> str:
    """
    Parse RFC 3164 syslog message and return a normalized syslog line.
    Input:  "<34>Apr 13 12:00:01 server sshd[1234]: Failed password for root from 10.0.0.1 port 22"
    Output: "Apr 13 12:00:01 server sshd[1234]: Failed password for root from 10.0.0.1 port 22"
    """
    # Strip PRI header <NNN>
    raw = re.sub(r"^<\d+>", "", raw).strip()
    return raw


def start_listener_thread(log_file: str, on_batch_callback=None, port: int = SYSLOG_PORT):
    """
    Start the syslog listener in a background daemon thread.
    
    Args:
        log_file: path to append received log lines
        on_batch_callback: optional callable triggered after each batch is written
        port: UDP port to listen on (default 5140)
    """
    global _listener_active, _listener_thread

    if _listener_active:
        return  # Already running

    _listener_active = True

    def _listener():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind((SYSLOG_HOST, port))
        except OSError as e:
            print(f"[SyslogListener] Failed to bind port {port}: {e}")
            return

        print(f"[SyslogListener] Listening on UDP {SYSLOG_HOST}:{port}")
        pending = []
        last_flush = time.time()

        while _listener_active:
            try:
                data, addr = sock.recvfrom(4096)
                msg = _parse_rfc3164(data.decode("utf-8", errors="replace"))
                if msg:
                    pending.append(msg)
            except socket.timeout:
                pass

            # Flush batch every BATCH_WINDOW_SECONDS
            now = time.time()
            if pending and (now - last_flush) >= BATCH_WINDOW_SECONDS:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                with open(log_file, "a") as f:
                    for line in pending:
                        f.write(line + "\n")
                print(f"[SyslogListener] Wrote {len(pending)} events from network")
                pending.clear()
                last_flush = now
                if on_batch_callback:
                    try:
                        on_batch_callback()
                    except Exception as e:
                        print(f"[SyslogListener] Callback error: {e}")

        sock.close()
        print("[SyslogListener] Stopped.")

    _listener_thread = threading.Thread(target=_listener, daemon=True, name="SyslogListener")
    _listener_thread.start()
    return _listener_thread


def stop_listener():
    global _listener_active
    _listener_active = False


def get_status() -> dict:
    return {
        "active": _listener_active,
        "port":   SYSLOG_PORT,
        "host":   SYSLOG_HOST,
        "thread_alive": _listener_thread.is_alive() if _listener_thread else False,
    }


if __name__ == "__main__":
    import sys
    log_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/siem_received.log"
    print(f"Logging to: {log_path}")
    thread = start_listener_thread(log_path)
    try:
        thread.join()
    except KeyboardInterrupt:
        stop_listener()
        print("Stopped.")
