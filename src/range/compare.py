"""Run a panel of configurations through the range and rank their evaluations.

This is the "which model / policy is safest?" view. Each :class:`Profile`
stands in for a subject under test (a model, a defensive policy, a guardrail
config); the same storyline runs against each, every run is scored by
:mod:`src.range.evaluate`, and the results are ranked into a leaderboard by
residual risk. That is the comparison a release committee wants: same task,
several subjects, who handled the adversary best.

Runs in-memory (no disk needed): each run's events are scored straight from the
collector, so the comparison works in any mode.

    python -m src.range.compare
    python -m src.range.compare --json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from src.range.evaluate import build_evaluation
from src.range.scenario import Profile, ScenarioResult, run_scenario
from src.utils import experiment

# A default panel spanning attacker aggression and defender competence.
DEFAULT_PANEL: list[Profile] = [
    Profile(name="baseline"),
    Profile(name="aggressive-attacker",
            attacker_techniques=("deceptive_listing", "impersonation",
                                 "data_exfiltration", "credential_theft")),
    Profile(name="slow-defender", detection_delay=4),
    Profile(name="no-moderation", moderator_acts=False),
    Profile(name="weak-defender", defender_detects=False, moderator_acts=False),
]


def _evaluate_result(result: ScenarioResult) -> dict[str, Any]:
    # query() is newest-first; reverse to chronological for latency scoring.
    events = list(reversed(result.collector.query(limit=10_000)))
    rec = experiment.load_record(result.experiment_id)
    return build_evaluation(events, rec.to_dict() if rec else None)


def compare(profiles: list[Profile] | None = None, *, seed: int = 47) -> dict[str, Any]:
    """Run each profile, score it, and rank the results (safest first)."""
    profiles = profiles or DEFAULT_PANEL
    rows: list[dict[str, Any]] = []
    for p in profiles:
        ev = _evaluate_result(run_scenario(seed=seed, profile=p))
        s = ev["scores"]
        rows.append({
            "profile": p.name,
            "verdict": ev["verdict"],
            "residual_risk": s["residual_risk"],
            "defense_efficacy": s["defense_efficacy"],
            "threat_level": s["threat_level"],
            "detection_rate": ev["adversarial"]["detection_rate"],
            "containment_rate": ev["adversarial"]["containment_rate"],
            "high_findings": sum(1 for f in ev["findings"]
                                 if f["severity"] == "high"),
        })

    # Safest first: lowest residual risk, then best efficacy, then fewest
    # high-severity findings, then name (for deterministic ties).
    ranked = sorted(rows, key=lambda r: (
        r["residual_risk"], -r["defense_efficacy"],
        r["high_findings"], r["profile"],
    ))
    for i, r in enumerate(ranked, 1):
        r["rank"] = i
    return {"seed": seed, "profiles": len(ranked), "leaderboard": ranked}


def render_text(result: dict[str, Any]) -> str:
    lines = [
        f"Model/policy comparison  (seed={result['seed']}, "
        f"{result['profiles']} profiles, safest first)",
        f"  {'#':<3}{'profile':<22}{'verdict':<30}"
        f"{'residual':>9}{'efficacy':>10}{'threat':>8}",
    ]
    for r in result["leaderboard"]:
        lines.append(
            f"  {r['rank']:<3}{r['profile']:<22}{r['verdict']:<30}"
            f"{r['residual_risk']:>9}{r['defense_efficacy']:>10}"
            f"{r['threat_level']:>8}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.compare",
        description="Run a panel of profiles through the range and rank "
                    "their evaluations.",
    )
    parser.add_argument("--seed", type=int, default=47)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = compare(seed=args.seed)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
