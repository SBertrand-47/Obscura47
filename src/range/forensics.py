"""Per-suspect incident reconstruction from a run's event log.

Where the evaluator gives an aggregate verdict for a run, this builds a case
file for each *suspect*: an actor that attacked, was flagged, or was banned.
For each it reconstructs the techniques used, accomplices (mutual-vouch rings),
value extracted, whether and when defenders caught and contained them, an
incident severity, and the ordered evidence timeline. This is the investigator
view: replay a run and explain, per actor, what they did and how it ended.

Everything is rebuilt from durable storage, so incidents are reproducible.

    OBSCURA_MODE=range python -m src.range incidents <experiment_id>
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from src.range.report import _summary, load_events
from src.range.scenario import (
    K_ATTACK, K_BANK_TRANSFER, K_DEFENSE_FLAG, K_MODERATION, K_TRUST_UPDATE,
)

SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO = "high", "medium", "low", "info"


def _severity(*, flagged: bool, banned: bool, funds: int,
              attacks: int) -> str:
    contained = flagged and banned
    if funds > 0 and not contained:
        return SEV_HIGH          # extracted value and got away with it
    if attacks > 0 and not flagged:
        return SEV_HIGH          # undetected adversary
    if flagged and not banned:
        return SEV_MEDIUM        # detected but not contained
    if contained:
        return SEV_LOW           # caught and contained
    return SEV_INFO


def build_incidents(experiment_id: str) -> list[dict[str, Any]]:
    """Reconstruct case files per suspect from a run's durable event log."""
    return incidents_from_events(load_events(experiment_id))


def incidents_from_events(events: list) -> list[dict[str, Any]]:
    """Build per-suspect case files from an event list (disk or in-memory)."""
    attacks = [e for e in events if e.kind == K_ATTACK]
    flags = [e for e in events if e.kind == K_DEFENSE_FLAG]
    mods = [e for e in events if e.kind == K_MODERATION]
    transfers = [e for e in events if e.kind == K_BANK_TRANSFER]
    vouches = {(e.actor, e.payload.get("subject")) for e in events
               if e.kind == K_TRUST_UPDATE
               and e.payload.get("reason") == "vouch"}

    suspects = {e.actor for e in attacks}
    suspects |= {e.payload.get("target") for e in flags}
    suspects |= {e.payload.get("target") for e in mods
                 if e.payload.get("action") == "ban"}
    suspects.discard(None)

    incidents = []
    for s in sorted(suspects):
        techniques = sorted({e.payload.get("technique") for e in attacks
                             if e.actor == s and e.payload.get("technique")})
        attack_count = sum(1 for e in attacks if e.actor == s)
        flagged_by = sorted({e.actor for e in flags
                             if e.payload.get("target") == s})
        flag_rounds = [e.payload.get("round") for e in flags
                       if e.payload.get("target") == s
                       and e.payload.get("round") is not None]
        banned = any(e.payload.get("target") == s
                     and e.payload.get("action") == "ban" for e in mods)
        funds = sum(int(e.payload.get("amount") or 0) for e in transfers
                    if e.payload.get("to") == s)
        accomplices = sorted({b for (a, b) in vouches
                              if a == s and (b, a) in vouches})
        flagged = bool(flagged_by)
        timeline = [
            {"round": e.payload.get("round"), "actor": e.actor,
             "kind": e.kind, "what": _summary(e)}
            for e in events
            if e.actor == s or e.payload.get("target") == s
            or e.payload.get("subject") == s
        ]
        incidents.append({
            "suspect": s,
            "severity": _severity(flagged=flagged, banned=banned, funds=funds,
                                  attacks=attack_count),
            "techniques": techniques,
            "attack_count": attack_count,
            "accomplices": accomplices,
            "flagged": flagged,
            "flagged_by": flagged_by,
            "first_flag_round": min(flag_rounds) if flag_rounds else None,
            "banned": banned,
            "contained": flagged and banned,
            "funds_extracted": funds,
            "timeline": timeline,
        })
    # Highest severity first.
    order = {SEV_HIGH: 0, SEV_MEDIUM: 1, SEV_LOW: 2, SEV_INFO: 3}
    incidents.sort(key=lambda i: (order.get(i["severity"], 9), i["suspect"]))
    return incidents


def aggregate(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll up a set of incidents into a portfolio summary."""
    by_severity: dict[str, int] = {}
    for inc in incidents:
        by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
    contained = sum(1 for i in incidents if i["contained"])
    return {
        "suspects": len(incidents),
        "by_severity": by_severity,
        "contained": contained,
        "uncontained": len(incidents) - contained,
        "total_funds_extracted": sum(i["funds_extracted"] for i in incidents),
        "containment_rate": (round(contained / len(incidents), 3)
                             if incidents else 1.0),
    }


def campaign() -> dict[str, Any]:
    """Run the behavioral battery in-memory and aggregate incidents across it.

    The portfolio view: every suspect the battery surfaced, rolled up by
    severity, containment and value extracted.
    """
    from src.range.suite import DEFAULT_SUITE

    per_scenario = []
    all_incidents: list[dict[str, Any]] = []
    for case in DEFAULT_SUITE:
        result = case.run()
        events = list(reversed(result.collector.query(limit=10_000)))
        incs = incidents_from_events(events)
        for i in incs:
            i["scenario"] = case.name
        per_scenario.append({"scenario": case.name, "incidents": len(incs)})
        all_incidents.extend(incs)
    return {"scenarios": per_scenario, "incidents": all_incidents,
            "aggregate": aggregate(all_incidents)}


def render_campaign_markdown(result: dict[str, Any]) -> str:
    """A portfolio report across the whole battery, for a release review."""
    agg = result["aggregate"]
    lines = [
        "# Obscura47 Range Portfolio",
        "",
        f"**{agg['suspects']} suspect(s) across {len(result['scenarios'])} "
        f"scenarios** &middot; contained {agg['contained']}/{agg['suspects']} "
        f"(rate {agg['containment_rate']}) &middot; "
        f"value extracted {agg['total_funds_extracted']}",
        "",
        f"By severity: {agg['by_severity']}",
        "",
        "| suspect | scenario | severity | techniques | funds | contained |",
        "|---|---|---|---|---|---|",
    ]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for i in sorted(result["incidents"],
                    key=lambda x: order.get(x["severity"], 9)):
        lines.append(
            f"| {i['suspect']} | {i.get('scenario', '')} | {i['severity']} | "
            f"{', '.join(i['techniques']) or '-'} | {i['funds_extracted']} | "
            f"{i['contained']} |")
    lines.append("")
    return "\n".join(lines)


def render_text(incidents: list[dict[str, Any]]) -> str:
    if not incidents:
        return "No incidents: no adversarial activity in this run."
    lines = [f"{len(incidents)} incident(s):"]
    for inc in incidents:
        lines.append(f"\n[{inc['severity'].upper()}] {inc['suspect']}")
        lines.append(f"  techniques: {inc['techniques'] or '-'}  "
                     f"attacks: {inc['attack_count']}")
        if inc["accomplices"]:
            lines.append(f"  accomplices: {inc['accomplices']}")
        det = (f"flagged by {inc['flagged_by']} at round {inc['first_flag_round']}"
               if inc["flagged"] else "never flagged")
        lines.append(f"  detection: {det}  "
                     f"contained: {inc['contained']}")
        if inc["funds_extracted"]:
            lines.append(f"  funds extracted: {inc['funds_extracted']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.forensics",
        description="Reconstruct per-suspect incident case files from a run.")
    parser.add_argument("experiment_id", nargs="?",
                        help="run to investigate (omit with --campaign)")
    parser.add_argument("--campaign", action="store_true",
                        help="run the whole battery and aggregate incidents")
    parser.add_argument("--md", default=None,
                        help="with --campaign, write a portfolio markdown report")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.campaign:
        result = campaign()
        if args.md:
            import os
            os.makedirs(os.path.dirname(os.path.abspath(args.md)), exist_ok=True)
            with open(args.md, "w", encoding="utf-8") as f:
                f.write(render_campaign_markdown(result))
            print(args.md)
        elif args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            agg = result["aggregate"]
            print(f"Campaign portfolio: {agg['suspects']} suspect(s) across "
                  f"{len(result['scenarios'])} scenarios")
            print(f"  by severity: {agg['by_severity']}")
            print(f"  contained: {agg['contained']}/{agg['suspects']}  "
                  f"(rate {agg['containment_rate']})")
            print(f"  total funds extracted: {agg['total_funds_extracted']}")
        return 0

    if not args.experiment_id:
        print("[incidents] give an experiment_id or --campaign",
              file=sys.stderr)
        return 2
    incidents = build_incidents(args.experiment_id)
    print(json.dumps(incidents, indent=2, default=str) if args.json
          else render_text(incidents))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
