"""Export a run as a portable evidence package (markdown + JSON).

The dashboard is an interactive HTML view; this is the artifact a safety team
archives or attaches to a model-release review: a self-contained report with
the verdict, scores, findings, and -- foregrounded -- the reproducibility
provenance (commit, model, policy version, seed) and a one-line command to
reproduce the exact run. Markdown for humans, JSON for machines / CI artifacts.

    OBSCURA_MODE=range python -m src.range evidence <experiment_id>
    OBSCURA_MODE=range python -m src.range evidence <id> --md report.md --json report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from src.range.evaluate import evaluate_run
from src.range.report import load_events
from src.range.scenario import K_DECISION
from src.utils import experiment


def _llm_cost(experiment_id: str) -> dict[str, int]:
    """Sum LLM token usage from the run's decision log (zero for scripted runs)."""
    cost = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
    for e in load_events(experiment_id):
        if e.kind != K_DECISION:
            continue
        usage = e.payload.get("usage")
        if isinstance(usage, dict):
            cost["calls"] += 1
            cost["input_tokens"] += int(usage.get("input_tokens", 0) or 0)
            cost["output_tokens"] += int(usage.get("output_tokens", 0) or 0)
    return cost

# Maps the recorded scenario tag to the command that reproduces its kind.
_SCENARIO_KIND = {
    "readiness_gate": "readiness",
    "adaptive_adversary": "adaptive",
    "agent_world": "agents",
}


def build_evidence(experiment_id: str) -> dict[str, Any]:
    """Assemble the evidence bundle from durable storage."""
    ev = evaluate_run(experiment_id)
    rec = experiment.load_record(experiment_id)
    extra = (rec.extra if rec else {}) or {}
    scenario = extra.get("scenario")
    config = ev.get("config") or {}

    seed = config.get("random_seed")
    kind = _SCENARIO_KIND.get(scenario)
    if kind is not None:
        reproduce = (f"OBSCURA_MODE=range python -m src.range run "
                     f"--kind {kind}")
    else:
        reproduce = (f"OBSCURA_MODE=range OBSCURA_EXPERIMENT_ID={experiment_id} "
                     f"python -m src.range run")

    return {
        "experiment_id": experiment_id,
        "generated_from": "durable storage",
        "scenario": scenario,
        "verdict": ev["verdict"],
        "scores": ev["scores"],
        "adversarial": ev["adversarial"],
        "executive_summary": ev["executive_summary"],
        "findings": ev["findings"],
        "config": config,
        "event_count": ev.get("event_count", 0),
        "llm_cost": _llm_cost(experiment_id),
        "reproduce": reproduce,
        "seed": seed,
    }


def render_markdown(ev: dict[str, Any]) -> str:
    s = ev["scores"]
    adv = ev["adversarial"]
    cfg = ev.get("config") or {}
    lines = [
        f"# Obscura47 Range Evaluation",
        f"",
        f"**Experiment:** `{ev['experiment_id']}`  ",
        f"**Scenario:** {ev.get('scenario')}  ",
        f"**Verdict:** **{ev['verdict']}**",
        f"",
        f"{ev['executive_summary']}",
        f"",
        f"## Scores",
        f"",
        f"| metric | value |",
        f"|---|---|",
        f"| threat level | {s['threat_level']} / 100 |",
        f"| defense efficacy | {s['defense_efficacy']} / 100 |",
        f"| residual risk | {s['residual_risk']} / 100 |",
        f"",
        f"## Adversarial activity",
        f"",
        f"- attacks: {adv.get('attacks')} from {adv.get('attackers')} actor(s)",
        f"- detection rate: {adv.get('detection_rate')}  "
        f"containment rate: {adv.get('containment_rate')}",
        f"- tool misuse: {adv.get('tool_misuse', 0)}  "
        f"prompt-injection exposed: {adv.get('prompt_injection_exposed', 0)}",
        f"",
        f"## Findings",
        f"",
    ]
    if ev["findings"]:
        for f in ev["findings"]:
            lines.append(f"- **[{f['severity'].upper()}]** {f['title']} - "
                         f"{f['detail']}")
    else:
        lines.append("- none")
    cost = ev.get("llm_cost") or {}
    if cost.get("calls"):
        lines += [
            "",
            "## Model cost",
            "",
            f"- model calls: {cost['calls']}",
            f"- input tokens: {cost['input_tokens']}",
            f"- output tokens: {cost['output_tokens']}",
        ]
    lines += [
        f"",
        f"## Reproducibility",
        f"",
        f"- commit: `{cfg.get('code_commit_sha')}`",
        f"- model: `{cfg.get('model_id')}`",
        f"- policy version: `{cfg.get('policy_version')}`",
        f"- random seed: `{ev.get('seed')}`",
        f"- events captured: {ev.get('event_count')}",
        f"",
        f"```",
        f"{ev['reproduce']}",
        f"```",
        f"",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.evidence",
        description="Export a run as a portable evidence package "
                    "(markdown + JSON).")
    parser.add_argument("experiment_id")
    parser.add_argument("--md", default=None, help="write markdown to this path")
    parser.add_argument("--json", default=None, help="write JSON to this path")
    args = parser.parse_args(argv)

    rec = experiment.load_record(args.experiment_id)
    if rec is None and not os.path.exists(
            experiment.events_path(args.experiment_id)):
        print(f"[evidence] no record or events for {args.experiment_id!r}.",
              file=sys.stderr)
        return 1

    ev = build_evidence(args.experiment_id)
    md = render_markdown(ev)

    if args.md:
        os.makedirs(os.path.dirname(os.path.abspath(args.md)), exist_ok=True)
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(md)
        print(args.md)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(ev, f, indent=2, default=str)
        print(args.json)
    if not args.md and not args.json:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
