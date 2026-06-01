"""Risk surface: defender model x attacker repertoire.

The 1D leaderboards rank defenders against one fixed attacker. This sweeps two
axes at once and exposes the interaction that matters most for safety: a
defender is only as strong as the attack surface it already knows. As the
attacker's repertoire grows past what the defender has seen, even a "strong"
defender starts taking breaches. The output is a grid of breach counts, the
kind of risk surface a safety team reads to find where a policy falls off.

Deterministic. Run:

    python -m src.range.matrix
    python -m src.range.matrix --rounds 12 --json
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from src.range.adaptive import (
    DEFAULT_REPERTOIRE, DEFENDERS, AttackerModel, run_adaptive,
)

# The default repertoire plus novel techniques no stock defender knows, so the
# surface includes the regime where every defender is eventually exposed.
EXTENDED_REPERTOIRE = DEFAULT_REPERTOIRE + (
    "zero_day_a", "zero_day_b", "zero_day_c",
)
DEFAULT_DEFENDERS = ("strong", "learning", "weak", "passive")
DEFAULT_SIZES = (2, 4, 6, 8)


def risk_matrix(
    *, defender_names: tuple[str, ...] = DEFAULT_DEFENDERS,
    repertoire_sizes: tuple[int, ...] = DEFAULT_SIZES,
    rounds: int = 12, seed: int = 47,
) -> dict[str, Any]:
    """Run every (defender, attacker-repertoire-size) pair and tabulate breaches."""
    rows = []
    for dname in defender_names:
        defender = DEFENDERS[dname]
        cells = []
        for k in repertoire_sizes:
            attacker = AttackerModel(repertoire=EXTENDED_REPERTOIRE[:k])
            summary = run_adaptive(rounds=rounds, seed=seed,
                                   attacker=attacker, defender=defender).summary
            cells.append({
                "repertoire": k,
                "breaches": summary["breaches"],
                "final_state": summary["final_state"],
            })
        rows.append({"defender": dname, "cells": cells})
    return {"rounds": rounds, "seed": seed,
            "repertoire_sizes": list(repertoire_sizes), "rows": rows}


def render_text(matrix: dict[str, Any]) -> str:
    sizes = matrix["repertoire_sizes"]
    lines = [
        f"Risk surface: breaches by defender x attacker repertoire  "
        f"(rounds={matrix['rounds']})",
        "  " + f"{'defender \\ techniques':<24}"
        + "".join(f"{k:>5}" for k in sizes),
    ]
    for row in matrix["rows"]:
        contained = all(c["final_state"] == "contained" for c in row["cells"])
        note = "" if contained else "  (uncontained somewhere)"
        lines.append("  " + f"{row['defender']:<24}"
                     + "".join(f"{c['breaches']:>5}" for c in row["cells"])
                     + note)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.matrix",
        description="Sweep defender model x attacker repertoire and print the "
                    "breach risk surface.")
    parser.add_argument("--rounds", type=int, default=12)
    parser.add_argument("--seed", type=int, default=47)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    matrix = risk_matrix(rounds=args.rounds, seed=args.seed)
    print(json.dumps(matrix, indent=2, default=str) if args.json
          else render_text(matrix))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
