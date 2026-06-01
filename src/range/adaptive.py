"""Multi-round adaptive adversary scenario.

The single-round readiness storyline shows the plumbing; this shows the part
of the vision that actually makes the network worth studying: agents that
*adapt over time*. An attacker works through a repertoire of techniques; a
defender starts with some known signatures and learns new ones after each
successful intrusion. The interesting dynamics are emergent from two simple
rules:

  * Attacker: keep using the current technique while it works; the moment it is
    detected, escalate to the next novel technique.
  * Defender: detect any attack whose technique it already knows; after a
    technique slips through undetected once, learn it (post-incident analysis)
    so it is caught next time.

The result is a cat-and-mouse run: a weak defender suffers a string of breaches
before the attacker exhausts its repertoire and gets contained; a strong
defender that already knows the repertoire contains everything from round one.
Every round emits the same research-plane event kinds as the scripted scenario,
so `report`, `evaluate` and `compare` all work on adaptive runs unchanged. The
run is fully deterministic given the models.

    OBSCURA_MODE=range python -m src.range.adaptive --rounds 10 --defender weak
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any

from src.range.scenario import (
    K_ATTACK, K_DEFENSE_FLAG, K_MODERATION, K_ONLINE, K_POLICY_VIOLATION,
    K_TRUST_UPDATE, ScenarioResult, World, pseudonym, setup_world,
)
from src.utils import experiment

TARGET = "market.obscura"
DEFAULT_REPERTOIRE = (
    "phishing", "deceptive_listing", "impersonation",
    "credential_theft", "data_exfiltration",
)


@dataclass(frozen=True)
class AttackerModel:
    name: str = "adaptive-attacker"
    repertoire: tuple[str, ...] = DEFAULT_REPERTOIRE


@dataclass(frozen=True)
class DefenderModel:
    name: str = "learning-defender"
    initial_known: frozenset[str] = frozenset()
    learns: bool = True   # learn a technique after it first slips through
    contains: bool = True  # ban the attacker on detection


# Convenience defenders for the CLI / panels.
DEFENDERS = {
    "weak": DefenderModel(name="weak-defender", initial_known=frozenset(),
                          learns=True, contains=True),
    "learning": DefenderModel(name="learning-defender",
                              initial_known=frozenset({"phishing"}),
                              learns=True, contains=True),
    "strong": DefenderModel(name="strong-defender",
                            initial_known=frozenset(DEFAULT_REPERTOIRE),
                            learns=True, contains=True),
    "passive": DefenderModel(name="passive-defender", initial_known=frozenset(),
                             learns=False, contains=False),
}


@dataclass
class AdaptiveResult:
    experiment_id: str
    seed: int
    rounds_log: list[dict] = field(default_factory=list)
    collector: Any = None
    summary: dict = field(default_factory=dict)


def run_adaptive(
    *, rounds: int = 10, seed: int = 47, experiment_id: str | None = None,
    attacker: AttackerModel | None = None,
    defender: DefenderModel | None = None,
) -> AdaptiveResult:
    """Run the cat-and-mouse storyline for ``rounds`` rounds, deterministically."""
    attacker = attacker or AttackerModel()
    defender = defender or DefenderModel()

    world, eid = setup_world(
        seed=seed, experiment_id=experiment_id, scenario="adaptive_adversary",
        attacker=attacker.name, defender=defender.name, rounds=rounds,
    )

    atk = pseudonym("attacker")
    dfn = pseudonym("defender")
    mod = pseudonym("moderator")
    for role in ("attacker", "defender", "moderator"):
        world.emit(pseudonym(role), K_ONLINE, role=role)

    known: set[str] = set(defender.initial_known)
    repertoire = attacker.repertoire
    cur = 0  # index of the technique the attacker is currently using
    log: list[dict] = []
    breaches = 0

    for r in range(1, rounds + 1):
        # Attacker exhausted novel techniques -> falls back to its last one,
        # which the defender now knows, so it just keeps getting caught.
        tech = repertoire[cur] if cur < len(repertoire) else repertoire[-1]
        world.emit(atk, K_ATTACK, technique=tech, target=TARGET, round=r)

        detected = tech in known
        if detected:
            world.emit(dfn, K_DEFENSE_FLAG, target=atk, technique=tech,
                       signal="known_signature", round=r)
            world.trust[atk] = world.trust.get(atk, 0) - 5
            world.emit(dfn, K_TRUST_UPDATE, subject=atk, delta=-5,
                       reason="caught", new_score=world.trust[atk], round=r)
            if defender.contains:
                world.emit(mod, K_MODERATION, action="ban", target=atk,
                           technique=tech, round=r)
            cur += 1  # escalate to the next novel technique
            outcome = "detected"
        else:
            breaches += 1
            world.emit(atk, K_POLICY_VIOLATION, rule="undetected_intrusion",
                       technique=tech, target=TARGET, round=r)
            if defender.learns:
                known.add(tech)  # post-incident: signature learned for next time
            outcome = "breach"

        log.append({"round": r, "technique": tech, "outcome": outcome,
                    "defender_known": len(known)})

    experiment.finish_experiment(eid)

    breach_rounds = [e["round"] for e in log if e["outcome"] == "breach"]
    summary = {
        "rounds": rounds,
        "attacker": attacker.name,
        "defender": defender.name,
        "attacks": len(log),
        "breaches": breaches,
        "detections": sum(1 for e in log if e["outcome"] == "detected"),
        "first_breach_round": breach_rounds[0] if breach_rounds else None,
        "last_breach_round": breach_rounds[-1] if breach_rounds else None,
        "contained_from_round": (breach_rounds[-1] + 1) if breach_rounds else 1,
        "techniques_used": [e["technique"] for e in log],
        "defender_known_final": sorted(known),
        "final_state": "contained" if log and log[-1]["outcome"] == "detected"
                       else "active_breach",
    }
    return AdaptiveResult(experiment_id=eid, seed=seed, rounds_log=log,
                          collector=world.collector, summary=summary)


def compare_defenders(
    defenders: list[DefenderModel] | None = None, *,
    rounds: int = 10, seed: int = 47,
) -> dict[str, Any]:
    """Run each defender model against the adaptive attacker and rank them.

    The "which defensive policy held up best over time?" view: ranked by total
    breaches suffered, then whether the attacker was ever contained, then how
    quickly. Deterministic.
    """
    if defenders is None:
        defenders = [DEFENDERS["strong"], DEFENDERS["learning"],
                     DEFENDERS["weak"], DEFENDERS["passive"]]
    rows: list[dict[str, Any]] = []
    for d in defenders:
        s = run_adaptive(rounds=rounds, seed=seed, defender=d).summary
        rows.append({
            "defender": d.name,
            "breaches": s["breaches"],
            "breach_rate": round(s["breaches"] / s["rounds"], 3),
            "detections": s["detections"],
            "final_state": s["final_state"],
            "ever_contained": s["final_state"] == "contained",
            "contained_from_round": s["contained_from_round"],
        })
    # Best defender first: fewest breaches, contained over active, earliest
    # containment, then name (deterministic ties).
    ranked = sorted(rows, key=lambda r: (
        r["breaches"], 0 if r["ever_contained"] else 1,
        r["contained_from_round"], r["defender"],
    ))
    for i, r in enumerate(ranked, 1):
        r["rank"] = i
    return {"rounds": rounds, "seed": seed, "defenders": len(ranked),
            "leaderboard": ranked}


def render_compare(result: dict[str, Any]) -> str:
    lines = [
        f"Defender comparison  (rounds={result['rounds']}, seed={result['seed']}"
        f", best first)",
        f"  {'#':<3}{'defender':<20}{'breaches':>9}{'breach_rate':>13}"
        f"{'final_state':>16}{'contained@':>12}",
    ]
    for r in result["leaderboard"]:
        lines.append(
            f"  {r['rank']:<3}{r['defender']:<20}{r['breaches']:>9}"
            f"{r['breach_rate']:>13}{r['final_state']:>16}"
            f"{r['contained_from_round']:>12}"
        )
    return "\n".join(lines)


def render_text(result: AdaptiveResult) -> str:
    s = result.summary
    lines = [
        f"Adaptive adversary  experiment={result.experiment_id}",
        f"  attacker={s['attacker']}  defender={s['defender']}  "
        f"rounds={s['rounds']}",
        f"  breaches={s['breaches']}  detections={s['detections']}  "
        f"final={s['final_state']}  contained_from_round="
        f"{s['contained_from_round']}",
        "",
        "Round-by-round:",
    ]
    for e in result.rounds_log:
        mark = "BREACH " if e["outcome"] == "breach" else "caught "
        lines.append(f"  r{e['round']:<2} {mark} {e['technique']:<18} "
                     f"(defender knows {e['defender_known']})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.adaptive",
        description="Run a multi-round adaptive attacker vs a learning "
                    "defender and print the cat-and-mouse trajectory.",
    )
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--seed", type=int, default=47)
    parser.add_argument("--defender", choices=sorted(DEFENDERS),
                        default="weak")
    parser.add_argument("--compare", action="store_true",
                        help="rank all defender models instead of one run")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.compare:
        result = compare_defenders(rounds=args.rounds, seed=args.seed)
        print(json.dumps(result, indent=2, default=str) if args.json
              else render_compare(result))
        return 0

    result = run_adaptive(rounds=args.rounds, seed=args.seed,
                          defender=DEFENDERS[args.defender])
    if args.json:
        print(json.dumps({"summary": result.summary,
                          "rounds_log": result.rounds_log}, indent=2,
                         default=str))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
