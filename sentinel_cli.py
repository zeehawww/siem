"""
sentinel_cli.py — Command-line interface for Sentinel SIEM tool

Install:  pip install -e .
Usage:    sentinel <command>

Commands:
  collect   — Pull real system logs (macOS ASL, wtmp, Unified Log)
  analyze   — Run the full detection pipeline
  predict   — Show Markov next-step attack predictions (terminal output)
  status    — Print current alerts and their confidence-decayed scores
  serve     — Launch the web dashboard at http://127.0.0.1:5001
  help      — Show this help
"""

import argparse
import json
import os
import sys

# Ensure project root is importable from anywhere
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── ANSI colour helpers (no external deps) ───────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
PURPLE = "\033[95m"
WHITE  = "\033[97m"

def _col(text, colour):   return f"{colour}{text}{RESET}"
def _bold(text):          return f"{BOLD}{text}{RESET}"
def _ok(msg):             print(f"  {GREEN}✓{RESET}  {msg}")
def _warn(msg):           print(f"  {YELLOW}!{RESET}  {msg}")
def _err(msg):            print(f"  {RED}✗{RESET}  {msg}", file=sys.stderr)
def _info(msg):           print(f"  {DIM}·{RESET}  {msg}")
def _section(title):      print(f"\n{BOLD}{WHITE}{title}{RESET}\n" + "─" * 52)

def _severity_colour(sev):
    return {
        "CRITICAL": RED,
        "HIGH":     YELLOW,
        "MEDIUM":   CYAN,
        "LOW":      GREEN,
    }.get(sev, WHITE)


# ── Storage helpers ──────────────────────────────────────────────────────────

def _load_json(filename):
    path = os.path.join(_ROOT, "storage", filename)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


# ── Commands ─────────────────────────────────────────────────────────────────

def cmd_collect(args):
    """Collect real system logs into logs/real_auth.log."""
    _section("Sentinel — Collect")
    try:
        from collector.macos_log_collector import write_real_logs_to_file
        log_path = os.path.join(_ROOT, "logs", "real_auth.log")
        events = write_real_logs_to_file(log_path)
        _ok(f"Collected {events} events  →  logs/real_auth.log")
    except Exception as exc:
        _err(f"Collection failed: {exc}")
        sys.exit(1)


def cmd_analyze(args):
    """Run the full detection pipeline and print results."""
    _section("Sentinel — Analyze")
    print(f"  {DIM}Running pipeline: collect → parse → detect → enrich …{RESET}")
    try:
        import main as pipeline
        pipeline.run_pipeline()
    except Exception as exc:
        _err(f"Pipeline error: {exc}")
        sys.exit(1)

    # Print summary
    alerts = _load_json("alerts.json") or []
    events = _load_json("events.json") or []
    _ok(f"{len(events)} events processed")

    if alerts:
        print()
        print(f"  {BOLD}Alerts detected:{RESET}")
        for a in alerts:
            sev    = a.get("severity", "LOW")
            colour = _severity_colour(sev)
            atype  = a.get("type", "")
            msg    = a.get("message", "")
            score  = a.get("risk_score", 0)
            dna    = a.get("dna", "")
            print(
                f"    [{_col(sev, colour)}]"
                f"  {_col(atype, BLUE)}"
                f"  {DIM}{msg[:60]}{RESET}"
                f"  {DIM}risk={score}  dna={dna}{RESET}"
            )
    else:
        _ok("No alerts detected.")


def cmd_predict(args):
    """Print Markov next-step predictions for all active threat entities."""
    _section("Sentinel — Threat Prediction (Markov)")
    preds   = _load_json("predictions.json")
    entropy = _load_json("entropy.json") or {}
    velocity = _load_json("velocity.json") or {}

    if not preds:
        _warn("No predictions yet. Run:  sentinel analyze")
        return

    for entity, pred in preds.items():
        risk  = pred.get("risk_label", "")
        last  = pred.get("last_observed", "")
        risk_colour = RED if risk == "IMMINENT" else YELLOW if risk == "LIKELY" else BLUE

        print(f"\n  {BOLD}{entity}{RESET}  {_col(risk, risk_colour)}")
        print(f"    {DIM}Last observed: {last}{RESET}")

        for p in pred.get("predictions", []):
            pct   = int(p["probability"] * 100)
            bar   = "█" * (pct // 10) + "░" * (10 - pct // 10)
            print(
                f"    → {_col(p['next_type'], YELLOW):<30} "
                f"{_col(bar, DIM)}  {_bold(str(pct) + '%'):<5} "
                f"{DIM}{p['mitre']}{RESET}"
            )

        ent = entropy.get(entity)
        vel = velocity.get(entity)
        if ent:
            elabel  = ent.get("entropy_label", "")
            ecolour = RED if elabel == "ANOMALOUS" else YELLOW if elabel == "ELEVATED" else GREEN
            _info(f"Entropy: {_col(elabel, ecolour)}  H={ent['entropy']}b")
        if vel:
            vp      = vel.get("profile", "")
            vcolour = RED if vp == "ESCALATING" else YELLOW if vp == "SUSTAINED" else GREEN
            _info(f"Velocity: {_col(vp, vcolour)}  score={vel['velocity_score']}")


def cmd_status(args):
    """Print current alert queue with decayed risk scores."""
    _section("Sentinel — Status")
    alerts = _load_json("alerts.json")
    events = _load_json("events.json") or []

    if alerts is None:
        _warn("No data. Run:  sentinel analyze")
        return

    print(f"  Events in store : {_bold(str(len(events)))}")
    print(f"  Alerts in queue : {_bold(str(len(alerts)))}")
    print()

    if not alerts:
        _ok("Queue empty — no active threats.")
        return

    crit = [a for a in alerts if a.get("severity") == "CRITICAL"]
    high = [a for a in alerts if a.get("severity") == "HIGH"]
    if crit: _warn(f"{len(crit)} CRITICAL alert(s)")
    if high: _info(f"{len(high)} HIGH alert(s)")

    print()
    header = f"  {'TYPE':<30} {'SEV':<10} {'RISK':>6}  {'MITRE':<12}  MESSAGE"
    print(_col(header, DIM))
    print("  " + "─" * 78)

    for a in sorted(alerts, key=lambda x: -x.get("risk_score", 0)):
        sev    = a.get("severity", "LOW")
        colour = _severity_colour(sev)
        atype  = f"{a.get('type',''):<30}"
        msg    = a.get("message", "")[:40]
        score  = str(a.get("risk_score", 0))
        mit    = a.get("mitre_technique", "—")
        print(
            f"  {_col(atype, colour)}"
            f" {_col(sev, colour):<10}"
            f" {score:>6}"
            f"  {_col(mit, DIM):<12}"
            f"  {DIM}{msg}{RESET}"
        )


def cmd_serve(args):
    """Start the web dashboard."""
    _section("Sentinel — Dashboard")
    _ok("Starting on http://127.0.0.1:5001")
    _info("Press Ctrl+C to stop")
    print()
    app_path = os.path.join(_ROOT, "dashboard", "app.py")
    os.execv(sys.executable, [sys.executable, app_path])


def cmd_help(args):
    print(f"""
{BOLD}{WHITE}Sentinel SIEM — Command-line Tool{RESET}

{BOLD}Usage:{RESET}
  sentinel <command>

{BOLD}Commands:{RESET}
  {_col('collect', GREEN)}   Collect real system logs from macOS (ASL, wtmp, Unified Log)
  {_col('analyze', GREEN)}   Run the full detection pipeline (parse, detect, enrich, predict)
  {_col('predict', YELLOW)}   Show Markov next-step attack predictions per threat entity
  {_col('status',  CYAN)}    Print current alert queue with decayed risk scores
  {_col('serve',   BLUE)}    Launch the web dashboard at http://127.0.0.1:5001

{BOLD}Novel Algorithms:{RESET}
  {_col('Markov Next-Step Prediction', PURPLE)}   — Predicts attacker's next move from MITRE ATT&CK kill-chain model
  {_col('Behavioral Entropy (Shannon H)', PURPLE)} — Flags compromised accounts via event-type distribution entropy
  {_col('Attack Velocity Profiling', PURPLE)}     — Computes rate-of-change and acceleration of attack intensity
  {_col('Confidence Decay Engine', PURPLE)}       — Alert risk scores halve every hour with no follow-up activity

{BOLD}Examples:{RESET}
  sentinel collect && sentinel analyze
  sentinel predict
  sentinel status
  sentinel serve
""")


# ── Entry point ──────────────────────────────────────────────────────────────

_COMMANDS = {
    "collect": cmd_collect,
    "analyze": cmd_analyze,
    "predict": cmd_predict,
    "status":  cmd_status,
    "serve":   cmd_serve,
    "help":    cmd_help,
}


def main():
    print(f"\n{BOLD}{WHITE}🛡  Sentinel SIEM{RESET}  {DIM}v1.0{RESET}\n")

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel SIEM — novel security monitoring tool",
        add_help=False,
    )
    parser.add_argument("command", nargs="?", default="help",
                        choices=list(_COMMANDS), metavar="command")
    parser.add_argument("rest", nargs=argparse.REMAINDER)

    args = parser.parse_args()
    _COMMANDS.get(args.command, cmd_help)(args)
    print()


if __name__ == "__main__":
    main()
