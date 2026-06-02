"""Control-efficacy ablation: how much does each defense actually reduce risk?

For each threat with a defended and undefended variant, run both and report the
drop in residual risk and exposure the control buys. This is the "does this
safeguard actually help, and by how much?" measurement -- the defensive ROI
view, distinct from a single run's score.

    python -m src.range ablation
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from src.range.agents import (
    collusion_cast, defended_collusion_cast, defended_injection_cast,
    injection_cast, run_world)
from src.range.evaluate import build_evaluation

# (threat, undefended cast, defended cast, rounds)
PAIRS = [
    ("prompt_injection", injection_cast, defended_injection_cast, 3),
    ("collusion", collusion_cast, defended_collusion_cast, 4),
]


def _score(cast, rounds: int) -> dict[str, Any]:
    events = list(reversed(run_world(cast, rounds=rounds)
                           .collector.query(limit=10_000)))
    ev = build_evaluation(events)
    return {"verdict": ev["verdict"],
            "residual_risk": ev["scores"]["residual_risk"],
            "exposed": ev["adversarial"].get("prompt_injection_exposed", 0)
            + (0 if ev["adversarial"].get("collusion_detected") else
               ev["adversarial"].get("collusion_rings", 0))}


def measure() -> list[dict[str, Any]]:
    """For each defended/undefended pair, the risk reduction the control buys."""
    rows = []
    for threat, undef, deff, rounds in PAIRS:
        u = _score(undef(), rounds)
        d = _score(deff(), rounds)
        rows.append({
            "threat": threat,
            "undefended": u,
            "defended": d,
            "residual_reduction": round(u["residual_risk"]
                                        - d["residual_risk"], 1),
            "exposure_reduction": u["exposed"] - d["exposed"],
        })
    return rows


def render_text(rows: list[dict[str, Any]]) -> str:
    lines = ["Control efficacy (undefended -> defended):",
             f"  {'threat':<18}{'residual':>20}{'reduction':>12}"]
    for r in rows:
        ud = f"{r['undefended']['residual_risk']} -> " \
             f"{r['defended']['residual_risk']}"
        lines.append(f"  {r['threat']:<18}{ud:>20}"
                     f"{r['residual_reduction']:>12}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.ablation",
        description="Measure how much each defense reduces risk.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rows = measure()
    print(json.dumps(rows, indent=2, default=str) if args.json
          else render_text(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
