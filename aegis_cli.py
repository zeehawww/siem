"""
aegis_cli.py — Command-line interface for Aegis SIEM tool

Install:  pip install -e .
Usage:    aegis <command>

Commands:
  collect   — Pull real system logs (macOS ASL, wtmp, Unified Log)
  analyze   — Run the full detection pipeline
  atrs      — Show ATRS entity risk scores (patent algorithm)
  srtc      — Show SRTC sequence-resonance risk scores (new algorithm)
  predict   — Show Markov next-step attack predictions
  status    — Print current alerts with decayed risk scores
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
    _section("Aegis — Collect")
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
    _section("Aegis — Analyze")
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
    _section("Aegis — Threat Prediction (Markov + TBF)")
    preds    = _load_json("predictions.json")
    entropy  = _load_json("entropy.json")  or {}
    velocity = _load_json("velocity.json") or {}
    tbf      = _load_json("tbf.json")      or {}

    if not preds:
        _warn("No predictions yet. Run:  aegis analyze")
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
        t   = tbf.get(entity)
        if ent:
            elabel  = ent.get("entropy_label", "")
            ecolour = RED if elabel == "ANOMALOUS" else YELLOW if elabel == "ELEVATED" else GREEN
            _info(f"Entropy: {_col(elabel, ecolour)}  H={ent['entropy']}b")
        if vel:
            vp      = vel.get("profile", "")
            vcolour = RED if vp == "ESCALATING" else YELLOW if vp == "SUSTAINED" else GREEN
            _info(f"Velocity: {_col(vp, vcolour)}  score={vel['velocity_score']}")
        if t:
            actor   = t.get("actor_type", "")
            acolour = RED if "AUTOMATED" in actor else YELLOW if "STEALTHY" in actor else CYAN
            tbfp    = t.get("tbf_fingerprint", "")
            cadence = t.get("dominant_cadence", "")
            _info(f"Actor type: {_col(actor, acolour)}  cadence={cadence}  TBF={tbfp}")


def cmd_atrs(args):
    """Compute and display ATRS entity risk scores (patent algorithm)."""
    _section("Aegis — ATRS (Adaptive Threat Risk Score)")
    print(f"  {DIM}Fusing: Velocity · Entropy · Reputation · Temporal · Prediction{RESET}")
    print(f"  {DIM}Adjustments: time-decay × feedback × cluster-boost{RESET}")
    print()

    try:
        from analyzer.atrs_engine import compute_all_atrs
        from analyzer.reputation_engine import get_reputation

        velocity    = _load_json("velocity.json") or {}
        entropy     = _load_json("entropy.json") or {}
        predictions = _load_json("predictions.json") or {}
        tbf         = _load_json("tbf.json") or {}
        alerts      = _load_json("alerts.json") or []
        rep_data    = get_reputation()

        scores = compute_all_atrs(
            velocity_data=velocity,
            entropy_data=entropy,
            reputation_data=rep_data,
            tbf_data=tbf,
            predictions=predictions,
            alerts=alerts,
            feedback_data=[],
        )

        if not scores:
            _warn("No entity data yet. Run:  aegis analyze")
            return

        # Header
        header = f"  {'#':>3}  {'ENTITY':<25} {'ATRS':>6}  {'RISK':<10}  {'V':>4} {'E':>4} {'R':>4} {'T':>4} {'P':>4}  MODIFIERS"
        print(_col(header, DIM))
        print("  " + "─" * 96)

        for i, r in enumerate(scores, 1):
            sev = r["risk_label"]
            colour = _severity_colour(sev)
            c = r["components"]
            m = r["modifiers"]
            mods = []
            if m["decay"] < 0.9:
                mods.append(f"decay={m['decay']}")
            if m["feedback_mod"] != 1.0:
                mods.append(f"fb={m['feedback_mod']}")
            if m["cluster_boost"] > 1.0:
                mods.append(f"cluster={m['cluster_boost']}")
            mod_str = "  ".join(mods) if mods else "—"

            print(
                f"  {_col(str(i), DIM):>3}"
                f"  {r['entity']:<25}"
                f" {_col(str(r['atrs_score']), colour):>6}"
                f"  {_col(sev, colour):<10}"
                f"  {c['V']:>4.0f} {c['E']:>4.0f} {c['R']:>4.0f} {c['T']:>4.0f} {c['P']:>4.0f}"
                f"  {DIM}{mod_str}{RESET}"
            )

        print()
        print(f"  {DIM}Components: V=Velocity  E=Entropy  R=Reputation  T=Temporal  P=Prediction{RESET}")
        print(f"  {DIM}Formula: ATRS = (0.25V + 0.20E + 0.25R + 0.15T + 0.15P) × decay × fb × cluster{RESET}")
        _ok(f"{len(scores)} entities scored.")

    except Exception as exc:
        _err(f"ATRS computation failed: {exc}")
        sys.exit(1)


def cmd_srtc(args):
    """Display SRTC (Sequence Resonance Threat Coefficient) scores."""
    _section("Aegis — SRTC (Sequence Resonance Threat Coefficient)")
    srtc = _load_json("srtc.json")
    if not srtc:
        _warn("No SRTC data yet. Run:  aegis analyze")
        return

    rows = sorted(srtc.values(), key=lambda r: r.get("srtc_score", 0), reverse=True)
    header = f"  {'#':>3}  {'ENTITY':<25} {'SRTC':>6}  {'LABEL':<10}  {'SMR':>5} {'TRR':>5} {'TSD':>5}  EVENTS"
    print(_col(header, DIM))
    print("  " + "─" * 92)
    for i, r in enumerate(rows, 1):
        label = r.get("label", "LOW")
        colour = _severity_colour(label)
        print(
            f"  {_col(str(i), DIM):>3}  "
            f"{r.get('entity',''):<25} "
            f"{_col(str(r.get('srtc_score',0)), colour):>6}  "
            f"{_col(label, colour):<10}  "
            f"{r.get('smr',0):>5} {r.get('trr',0):>5} {r.get('tsd',0):>5}  "
            f"{r.get('event_count',0)}"
        )
    print()
    _info("Formula: 100*(0.45*SMR + 0.25*TRR + 0.30*TSD)")
    _info("SMR=Sequence Motif Resonance, TRR=Temporal Rhythm Regularity, TSD=Transition Surprise Divergence")


def cmd_status(args):
    """Print current alert queue with decayed risk scores."""
    _section("Aegis — Status")
    alerts = _load_json("alerts.json")
    events = _load_json("events.json") or []

    if alerts is None:
        _warn("No data. Run:  aegis analyze")
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
    _section("Aegis — Dashboard")
    _ok("Starting on http://127.0.0.1:5001")
    _info("Press Ctrl+C to stop")
    print()
    app_path = os.path.join(_ROOT, "dashboard", "app.py")
    os.execv(sys.executable, [sys.executable, app_path])


def cmd_help(args):
    print(f"""
{BOLD}{WHITE}Aegis SIEM — Security Monitoring Tool{RESET}

{BOLD}Usage:{RESET}
  aegis <command>

{BOLD}Commands:{RESET}
  {_col('collect', GREEN)}   Collect real system logs from macOS (ASL, wtmp, Unified Log)
  {_col('analyze', GREEN)}   Run the full detection pipeline (parse, detect, enrich, predict)
  {_col('atrs',    PURPLE)}      Compute ATRS entity risk scores (★ novel patent algorithm)
  {_col('srtc',    PURPLE)}      Compute SRTC sequence-resonance scores (★ original algorithm)
  {_col('predict', YELLOW)}   Show Markov next-step attack predictions per threat entity
  {_col('status',  CYAN)}    Print current alert queue with decayed risk scores
  {_col('serve',   BLUE)}    Launch the web dashboard at http://127.0.0.1:5001

{BOLD}Patent Algorithm — ATRS (Adaptive Threat Risk Score):{RESET}
  Fuses 5 behavioral dimensions per entity into a single auditable score:
  {PURPLE}V{RESET}elocity · {PURPLE}E{RESET}ntropy · {PURPLE}R{RESET}eputation · {PURPLE}T{RESET}emporal anomaly · {PURPLE}P{RESET}rediction
  Adjusted by: exponential time-decay × analyst feedback × DNA cluster boost

{BOLD}Examples:{RESET}
  aegis collect && aegis analyze   {DIM}# ingest + process logs{RESET}
  aegis atrs                          {DIM}# view ATRS entity scores{RESET}
  aegis predict                       {DIM}# view Markov predictions{RESET}
  aegis status                        {DIM}# view alert queue{RESET}
  aegis serve                         {DIM}# open web dashboard{RESET}
""")


# ── Entry point ──────────────────────────────────────────────────────────────

_COMMANDS = {
    "collect": cmd_collect,
    "analyze": cmd_analyze,
    "atrs":    cmd_atrs,
    "srtc":    cmd_srtc,
    "predict": cmd_predict,
    "status":  cmd_status,
    "serve":   cmd_serve,
    "help":    cmd_help,
}


def main():
    print(f"\n{BOLD}{WHITE}🛡  Aegis SIEM{RESET}  {DIM}v1.0{RESET}\n")

    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis SIEM — novel security monitoring tool",
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
