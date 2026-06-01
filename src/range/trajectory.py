"""Per-round trajectory of a run: how the network evolved over time.

The evaluator gives a per-run verdict and forensics gives a per-suspect case
file; this is the temporal lens. For each round it reconstructs the activity --
attacks, defensive flags, moderations, transactions and volume, forum posts,
net trust change, and how many agents were active -- so you can see escalation,
adaptation, and when defenses kicked in across the run.

Rebuilt from the durable event log, deterministic.

    OBSCURA_MODE=range python -m src.range trajectory <experiment_id>
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from src.range.report import load_events
from src.range.scenario import (
    K_ATTACK, K_BANK_TRANSFER, K_DEFENSE_FLAG, K_MODERATION, K_POST,
    K_TRUST_UPDATE,
)


def build_trajectory(experiment_id: str) -> list[dict[str, Any]]:
    """Per-round activity metrics, in round order (setup events are skipped)."""
    rounds: dict[int, dict[str, Any]] = {}
    for e in load_events(experiment_id):
        r = e.payload.get("round")
        if r is None:
            continue  # online/mint setup events have no round
        b = rounds.setdefault(r, {
            "round": r, "attacks": 0, "defenses": 0, "moderations": 0,
            "transfers": 0, "volume": 0, "posts": 0, "trust_delta": 0,
            "_actors": set()})
        b["_actors"].add(e.actor)
        if e.kind == K_ATTACK:
            b["attacks"] += 1
        elif e.kind == K_DEFENSE_FLAG:
            b["defenses"] += 1
        elif e.kind == K_MODERATION:
            b["moderations"] += 1
        elif e.kind == K_BANK_TRANSFER:
            b["transfers"] += 1
            b["volume"] += int(e.payload.get("amount") or 0)
        elif e.kind == K_POST:
            b["posts"] += 1
        elif e.kind == K_TRUST_UPDATE:
            b["trust_delta"] += int(e.payload.get("delta") or 0)
    out = []
    for r in sorted(rounds):
        b = rounds[r]
        b["active_agents"] = len(b.pop("_actors"))
        out.append(b)
    return out


def under_defended_rounds(trajectory: list[dict[str, Any]]) -> list[int]:
    """Rounds where attacks outpaced the defensive response (a breach window):
    more attacks than defensive flags that round."""
    return [b["round"] for b in trajectory if b["attacks"] > b["defenses"]]


def render_text(trajectory: list[dict[str, Any]]) -> str:
    if not trajectory:
        return "No per-round activity (no run, or setup-only)."
    cols = ["round", "active_agents", "attacks", "defenses", "moderations",
            "transfers", "volume", "posts", "trust_delta"]
    lines = ["  " + "".join(f"{c:>14}" for c in cols)]
    for b in trajectory:
        lines.append("  " + "".join(f"{b.get(c, 0):>14}" for c in cols))
    breaches = under_defended_rounds(trajectory)
    lines.append(f"\n  under-defended rounds (attacks > defenses): "
                 f"{breaches or 'none'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.trajectory",
        description="Reconstruct a run's per-round activity trajectory.")
    parser.add_argument("experiment_id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    traj = build_trajectory(args.experiment_id)
    print(json.dumps(traj, indent=2, default=str) if args.json
          else render_text(traj))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
