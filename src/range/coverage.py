"""Audit which attack techniques a defense actually covers.

A systematic attacker tries every technique once against a watcher configured
to detect a given set; the probe reports which techniques were flagged
(covered) and which slipped through (uncovered), with a coverage rate. This
answers "what does my defense actually catch?" -- the gap view, sweeping every
technique rather than stopping at the first hole.

    python -m src.range coverage --detects abuse,prompt_injection
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from src.range.agents import (
    Agent, SystematicAttacker, Watcher, pseudonym, run_world)
from src.range.scenario import K_ATTACK, K_DEFENSE_FLAG

DEFAULT_TECHNIQUES = ("abuse", "prompt_injection", "impersonation",
                      "collusion", "scam", "credential_theft")


def probe(detects, techniques: tuple[str, ...] = DEFAULT_TECHNIQUES,
          seed: int = 47) -> dict[str, Any]:
    """Run every technique past a watcher and report coverage."""
    techniques = tuple(techniques)
    cast = [
        Agent(pseudonym("attacker"), "attacker", "probe coverage",
              SystematicAttacker(techniques)),
        Agent(pseudonym("watcher"), "defender", "flag known techniques",
              Watcher(detects)),
    ]
    result = run_world(cast, rounds=len(techniques) + 1, seed=seed)
    events = list(reversed(result.collector.query(limit=10_000)))
    attacked = {e.payload.get("technique") for e in events
                if e.kind == K_ATTACK}
    flagged = {e.payload.get("technique") for e in events
               if e.kind == K_DEFENSE_FLAG}
    covered = sorted(attacked & flagged)
    uncovered = sorted(attacked - flagged)
    return {
        "techniques": sorted(attacked),
        "covered": covered,
        "uncovered": uncovered,
        "coverage_rate": (round(len(covered) / len(attacked), 3)
                          if attacked else 1.0),
    }


def render_text(result: dict[str, Any]) -> str:
    return (f"Defensive coverage: {len(result['covered'])}/"
            f"{len(result['techniques'])} techniques "
            f"(rate {result['coverage_rate']})\n"
            f"  covered:   {result['covered'] or 'none'}\n"
            f"  UNCOVERED: {result['uncovered'] or 'none'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.coverage",
        description="Probe which attack techniques a defense covers.")
    parser.add_argument("--detects", default="",
                        help="comma-separated techniques the defense detects")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    detects = [d.strip() for d in args.detects.split(",") if d.strip()]
    result = probe(detects)
    print(json.dumps(result, indent=2, default=str) if args.json
          else render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
