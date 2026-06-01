"""Reconstruct and render an experiment run from its durable event log.

This is the "fully observable" payoff: given an ``experiment_id``, load the
immutable run record and the append-only research-event log written during the
run, and reconstruct the whole story -- timeline, per-agent activity, the fake
economy's transactions, how trust shifted, and the adversarial chain of
attack -> detection -> response. Everything here is rebuilt *from storage*, not
from a live process, which is exactly what makes a run replayable and
auditable after the fact.

Operator-facing, range-mode tool. Run it:

    OBSCURA_MODE=range python -m src.range.report <experiment_id>
    OBSCURA_MODE=range python -m src.range.report <experiment_id> --json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from src.agent.observatory import Event
from src.range.scenario import (
    K_ATTACK, K_BANK_MINT, K_BANK_TRANSFER, K_DEFENSE_FLAG, K_MODERATION,
    K_ONLINE, K_POLICY_VIOLATION, K_SITE_HOST, K_SITE_VISIT, K_TRUST_UPDATE,
)
from src.utils import experiment


def load_events(experiment_id: str) -> list[Event]:
    """Read the run's append-only event log back into Event objects.

    File order is emission order, which is chronological; preserved as-is.
    """
    path = experiment.events_path(experiment_id)
    events: list[Event] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(Event.from_dict(json.loads(line)))
                except Exception:
                    continue
    except FileNotFoundError:
        return []
    return events


def _summary(e: Event) -> str:
    """One-line human summary of an event for the timeline."""
    p = e.payload
    if e.kind == K_ONLINE:
        return f"came online (role={p.get('role')})"
    if e.kind == K_SITE_HOST:
        return f"hosted {p.get('site')} ({p.get('title')})"
    if e.kind == K_SITE_VISIT:
        return f"visited {p.get('site')}"
    if e.kind == "market.list":
        return f"listed {p.get('item')!r} @ {p.get('price')} ({p.get('listing_id')})"
    if e.kind == K_BANK_MINT:
        return f"minted {p.get('amount')} to {p.get('to')}"
    if e.kind == K_BANK_TRANSFER:
        return f"paid {p.get('amount')} {p.get('from')} -> {p.get('to')}"
    if e.kind == "escrow.open":
        return f"opened escrow {p.get('amount')} on {p.get('listing_id')}"
    if e.kind == "escrow.release":
        return f"released {p.get('amount')} to {p.get('to')} ({p.get('listing_id')})"
    if e.kind == K_TRUST_UPDATE:
        return (f"trust {p.get('subject')} {p.get('delta'):+d} "
                f"-> {p.get('new_score')} ({p.get('reason')})")
    if e.kind == K_ATTACK:
        return f"ATTACK {p.get('technique')} on {p.get('target')}"
    if e.kind == K_POLICY_VIOLATION:
        return f"POLICY VIOLATION {p.get('rule')} (target {p.get('target')})"
    if e.kind == K_DEFENSE_FLAG:
        return f"flagged {p.get('target')} (signal {p.get('signal')})"
    if e.kind == K_MODERATION:
        return f"moderation {p.get('action')} (target {p.get('target')})"
    if e.kind == "node.unstable":
        return f"node {p.get('state')}"
    return json.dumps(p, default=str)


def build_report(experiment_id: str) -> dict[str, Any]:
    """Reconstruct a structured investigation report from durable storage."""
    rec = experiment.load_record(experiment_id)
    events = load_events(experiment_id)

    timeline = [
        {"ts": e.ts, "actor": e.actor, "kind": e.kind, "what": _summary(e)}
        for e in events
    ]

    agents: dict[str, dict[str, Any]] = {}
    for e in events:
        a = agents.setdefault(e.actor, {"events": 0, "kinds": {}})
        a["events"] += 1
        a["kinds"][e.kind] = a["kinds"].get(e.kind, 0) + 1

    transactions = [
        {"by": e.actor, "kind": e.kind, "amount": e.payload.get("amount"),
         "from": e.payload.get("from"), "to": e.payload.get("to")}
        for e in events if e.kind in (K_BANK_MINT, K_BANK_TRANSFER)
    ]

    # Reconstruct trust purely from the deltas in the log.
    trust: dict[str, int] = {}
    for e in events:
        if e.kind == K_TRUST_UPDATE:
            subj = e.payload.get("subject")
            delta = int(e.payload.get("delta") or 0)
            trust[subj] = trust.get(subj, 0) + delta

    # The adversarial chain: who attacked, who caught it, what was done.
    def detail(e: Event) -> dict[str, Any]:
        return {"ts": e.ts, "by": e.actor, **e.payload}

    adversarial = {
        "attacks": [detail(e) for e in events if e.kind == K_ATTACK],
        "policy_violations": [detail(e) for e in events
                              if e.kind == K_POLICY_VIOLATION],
        "defenses": [detail(e) for e in events if e.kind == K_DEFENSE_FLAG],
        "moderation": [detail(e) for e in events if e.kind == K_MODERATION],
    }

    # Per-suspect investigation: every event an actor authored or was targeted
    # by, in order. A targeted actor is the subject of a defense/moderation.
    suspects = sorted({
        e.payload.get("target") for e in events
        if e.kind in (K_DEFENSE_FLAG, K_MODERATION) and e.payload.get("target")
    })
    investigations = {}
    for s in suspects:
        chain = [
            {"ts": e.ts, "actor": e.actor, "kind": e.kind, "what": _summary(e)}
            for e in events
            if e.actor == s or e.payload.get("target") == s
            or e.payload.get("subject") == s
        ]
        investigations[s] = chain

    return {
        "experiment_id": experiment_id,
        "record": rec.to_dict() if rec else None,
        "reconstructed_from_storage": True,
        "event_count": len(events),
        "timeline": timeline,
        "agents": agents,
        "transactions": transactions,
        "trust": trust,
        "adversarial": adversarial,
        "investigations": investigations,
    }


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    rec = report.get("record") or {}
    lines.append(f"Experiment {report['experiment_id']}  "
                 f"(reconstructed from storage)")
    if rec:
        lines.append(f"  scenario={rec.get('extra', {}).get('scenario')}  "
                     f"seed={rec.get('random_seed')}  "
                     f"commit={(rec.get('code_commit_sha') or '')[:12]}")
        lines.append(f"  started={rec.get('started_at')}  "
                     f"ended={rec.get('ended_at')}")
    else:
        lines.append("  (no run record found; events only)")
    lines.append(f"  events: {report['event_count']}  "
                 f"agents: {len(report['agents'])}")

    lines.append("\nTimeline")
    for row in report["timeline"]:
        lines.append(f"  {row['actor']:<16} {row['what']}")

    lines.append("\nTransactions")
    for t in report["transactions"]:
        lines.append(f"  {t['by']:<16} {t['kind']:<14} amount={t['amount']}")

    lines.append("\nTrust (reconstructed)")
    for subj, score in sorted(report["trust"].items()):
        lines.append(f"  {subj:<16} {score:+d}")

    lines.append("\nAdversarial")
    adv = report["adversarial"]
    lines.append(f"  attacks={len(adv['attacks'])}  "
                 f"violations={len(adv['policy_violations'])}  "
                 f"defenses={len(adv['defenses'])}  "
                 f"moderation={len(adv['moderation'])}")

    for suspect, chain in report["investigations"].items():
        lines.append(f"\nInvestigation: {suspect}")
        for row in chain:
            lines.append(f"  {row['actor']:<16} {row['what']}")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.report",
        description="Reconstruct and render an experiment run from its "
                    "durable event log.",
    )
    parser.add_argument("experiment_id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = build_report(args.experiment_id)
    if report["event_count"] == 0 and report["record"] is None:
        print(f"[report] no record or events for {args.experiment_id!r}. "
              f"Run a range scenario first (OBSCURA_MODE=range).",
              file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
