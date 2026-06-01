"""Behavioral regression suite: a battery of scenarios with expected outcomes.

The gate decides on one run; the suite runs a curated battery and checks each
scenario against the outcome we *expect* of it. That catches regressions in
both directions:

* a scenario that should be defended (readiness, a competent defender) starts
  failing the safety gate -> the defensive posture regressed;
* a known-vulnerable demonstration (the prompt-injection cast) unexpectedly
  passes -> the vulnerability modeling broke, so the demo no longer demonstrates.

The whole battery is deterministic, so the expected outcomes are a stable
baseline. The suite exits nonzero if any scenario deviates from expectation,
which makes it a one-command behavioral guard for CI.

    python -m src.range suite
    python -m src.range suite --json
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from typing import Any, Callable

from src.range.adaptive import DEFENDERS, run_adaptive
from src.range.agents import (
    collusion_cast, defended_collusion_cast, defended_injection_cast,
    forum_moderation_cast, honeypot_cast, injection_cast, run_world,
    scam_escrow_cast,
)
from src.range.evaluate import build_evaluation
from src.range.gate import check_gate
from src.range.scenario import run_scenario


@dataclass
class SuiteCase:
    name: str
    run: Callable[[], Any]
    expect_pass: bool  # do we expect this scenario to pass the safety gate?
    family: str = "baseline"  # threat family, for the coverage view


# The battery. Each entry is deterministic; ``expect_pass`` is the baseline.
DEFAULT_SUITE: list[SuiteCase] = [
    SuiteCase("readiness",
              lambda: run_scenario(seed=47), expect_pass=True,
              family="baseline"),
    SuiteCase("adaptive-strong",
              lambda: run_adaptive(rounds=8, defender=DEFENDERS["strong"]),
              expect_pass=True, family="adaptive"),
    SuiteCase("adaptive-weak",
              lambda: run_adaptive(rounds=12, defender=DEFENDERS["weak"]),
              expect_pass=True, family="adaptive"),
    SuiteCase("prompt-injection",
              lambda: run_world(injection_cast(), rounds=3),
              expect_pass=False, family="prompt_injection"),
    SuiteCase("prompt-injection-defended",
              lambda: run_world(defended_injection_cast(), rounds=3),
              expect_pass=True, family="prompt_injection"),
    SuiteCase("collusion",
              lambda: run_world(collusion_cast(), rounds=4),
              expect_pass=False, family="collusion"),
    SuiteCase("collusion-defended",
              lambda: run_world(defended_collusion_cast(), rounds=4),
              expect_pass=True, family="collusion"),
    SuiteCase("honeypot",
              lambda: run_world(honeypot_cast(), rounds=3),
              expect_pass=True, family="honeypot"),
    SuiteCase("scam-escrow",
              lambda: run_world(scam_escrow_cast(), rounds=3),
              expect_pass=True, family="scam"),
    SuiteCase("forum-moderation",
              lambda: run_world(forum_moderation_cast(), rounds=2),
              expect_pass=True, family="abuse"),
]


def _evaluate(result) -> dict[str, Any]:
    events = list(reversed(result.collector.query(limit=10_000)))
    return build_evaluation(events)


def run_suite(suite: list[SuiteCase] | None = None,
              policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run the battery and check each scenario against its expected outcome."""
    suite = suite if suite is not None else DEFAULT_SUITE
    cases = []
    for case in suite:
        ev = _evaluate(case.run())
        gate = check_gate(ev, policy)
        ok = gate["passed"] == case.expect_pass
        cases.append({
            "name": case.name,
            "family": case.family,
            "verdict": ev["verdict"],
            "residual_risk": ev["scores"]["residual_risk"],
            "gate_passed": gate["passed"],
            "expected_pass": case.expect_pass,
            "ok": ok,
        })
    matched = sum(1 for c in cases if c["ok"])
    # A family is "defended" when every scenario in it that is expected to pass
    # the gate actually does (a defended demonstration that holds).
    families: dict[str, bool] = {}
    for c in cases:
        if c["family"] == "baseline":
            continue
        defended = c["gate_passed"] if c["expected_pass"] else True
        families[c["family"]] = families.get(c["family"], True) and defended
    return {"cases": cases, "n": len(cases), "matched": matched,
            "passed": matched == len(cases), "families": families,
            "families_defended": sum(1 for v in families.values() if v)}


def render_text(result: dict[str, Any]) -> str:
    head = "PASS" if result["passed"] else "FAIL"
    fam = result.get("families", {})
    lines = [f"Behavioral suite {head}  "
             f"({result['matched']}/{result['n']} as expected)",
             f"  threat families defended: {result.get('families_defended', 0)}"
             f"/{len(fam)}  {sorted(fam)}",
             f"  {'scenario':<28}{'verdict':<16}{'gate':>6}{'expect':>8}{'':>7}"]
    for c in result["cases"]:
        mark = "ok" if c["ok"] else "DRIFT"
        lines.append(f"  {c['name']:<28}{c['verdict']:<16}"
                     f"{('pass' if c['gate_passed'] else 'fail'):>6}"
                     f"{('pass' if c['expected_pass'] else 'fail'):>8}{mark:>7}")
    return "\n".join(lines)


def render_markdown(result: dict[str, Any]) -> str:
    """A shareable scorecard: how the configuration did across the battery."""
    head = "PASS" if result["passed"] else "FAIL"
    lines = [
        "# Obscura47 Range Security Scorecard",
        "",
        f"**Result: {head}**  ({result['matched']}/{result['n']} scenarios "
        f"behaved as expected)",
        "",
        f"**Threat families defended: {result.get('families_defended', 0)}"
        f"/{len(result.get('families', {}))}** "
        f"({', '.join(sorted(result.get('families', {})))})",
        "",
        "Each scenario is run, scored, gated against a safety policy, and "
        "checked against its expected outcome. Known-vulnerable demonstrations "
        "are *expected* to fail the gate; their defended counterparts are "
        "expected to pass, which is how a control's efficacy is shown.",
        "",
        "| scenario | verdict | gate | expected | status |",
        "|---|---|---|---|---|",
    ]
    for c in result["cases"]:
        lines.append(
            f"| {c['name']} | {c['verdict']} | "
            f"{'pass' if c['gate_passed'] else 'fail'} | "
            f"{'pass' if c['expected_pass'] else 'fail'} | "
            f"{'ok' if c['ok'] else '**DRIFT**'} |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.suite",
        description="Run the behavioral regression battery; exit 1 if any "
                    "scenario deviates from its expected outcome.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--md", default=None,
                        help="write a markdown scorecard to this path")
    args = parser.parse_args(argv)

    result = run_suite()
    if args.md:
        os.makedirs(os.path.dirname(os.path.abspath(args.md)), exist_ok=True)
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(render_markdown(result))
        print(args.md)
    elif args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(render_text(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
