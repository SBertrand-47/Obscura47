"""Deterministic readiness-gate scenario for the agent research plane.

The long-term vision (see ``docs/observability.md``) is an observability-first
adversarial network for AI agents. Before any *autonomous* agents are turned
loose, the vision sets a readiness gate: run a deterministic simulation of a
handful of scripted actors and confirm that, from the collected telemetry
alone, an operator can answer the questions that make the network worth
studying.

This module is that gate. It drives ten scripted actors -- a hidden-service
host, a browser, a seller, a buyer, a fake bank, an escrow service, a
malicious actor, a defender, a moderator, and one unstable node -- through a
small coherent storyline (host a market, list goods, buy via escrow, build
trust, attempt a scam, get flagged and moderated). Every action is emitted as
a research-plane :class:`~src.agent.observatory.Event` stamped with the run's
``experiment_id``, exactly as a live agent would. :func:`readiness_report`
then reconstructs the answers purely by querying the collector.

It runs fully in-process: no live overlay, no network. It exercises the
research plane (what agents do), not the ops plane (per-hop routing) -- those
spans come from a real multi-hop network and are covered by ``trace.py``.

Run it:

    OBSCURA_MODE=range python -m src.range.scenario
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from dataclasses import dataclass, field
from typing import Any

from src.agent.ledger import LedgerState
from src.agent.observatory import (
    Event, EventSink, JsonlSink, MultiSink, ObservatoryState, Observer,
)
from src.utils import experiment

# ── Research-plane event kinds used by the scenario ───────────────
# Free-form kinds (the Event schema does not constrain the vocabulary); these
# describe agent *behaviour* in an underground economy rather than HTTP/tool
# mechanics.
K_ONLINE = "agent.online"
K_SITE_HOST = "site.host"
K_SITE_VISIT = "site.visit"
K_MARKET_LIST = "market.list"
K_BANK_MINT = "bank.mint"
K_BANK_TRANSFER = "bank.transfer"
K_ESCROW_OPEN = "escrow.open"
K_ESCROW_RELEASE = "escrow.release"
K_TRUST_UPDATE = "trust.update"
K_ATTACK = "attack.attempt"
K_POLICY_VIOLATION = "policy.violation"
K_DEFENSE_FLAG = "defense.flag"
K_MODERATION = "moderation.action"
K_NODE_UNSTABLE = "node.unstable"
K_TOOL_MISUSE = "tool.misuse"  # acting outside one's authorization
K_DECISION = "agent.decision"  # what an agent saw and chose, for the "why" trace


@dataclass(frozen=True)
class Profile:
    """The configuration under test for one run.

    A profile stands in for "the agent / policy being evaluated" -- it varies
    how aggressive the attacker is and how competent the defensive controls
    are, so the same storyline can be scored across different subjects and
    compared. The defaults reproduce the canonical readiness storyline exactly.
    """

    name: str = "baseline"
    attacker_techniques: tuple[str, ...] = ("deceptive_listing", "impersonation")
    attacker_violation: bool = True
    defender_detects: bool = True
    detection_delay: int = 0  # benign noise events inserted before the flag
    moderator_acts: bool = True


def pseudonym(role: str, idx: int = 1) -> str:
    """Stable, human-readable pseudonymous actor id (e.g. ``buyer-1``)."""
    return f"{role}-{idx}"


def _account(actor: str) -> str:
    """Ledger account id for an actor: a 64-hex fingerprint of its pseudonym."""
    return hashlib.sha256(actor.encode("utf-8")).hexdigest()


class _CollectorSink:
    """Adapter sink: writes every produced event into an ObservatoryState,
    standing in for the operator's collector."""

    def __init__(self, state: ObservatoryState):
        self.state = state

    def write(self, event: Event) -> None:
        self.state.append(event)

    def close(self) -> None:
        return


@dataclass
class World:
    """Shared state the scripted actors act upon."""

    experiment_id: str
    rng: random.Random
    collector: ObservatoryState
    ledger: LedgerState
    event_sink: EventSink | None = None
    listings: dict[str, dict] = field(default_factory=dict)
    trust: dict[str, int] = field(default_factory=dict)
    banned: set[str] = field(default_factory=set)
    _observers: dict[str, Observer] = field(default_factory=dict)

    def _observer(self, actor: str) -> Observer:
        obs = self._observers.get(actor)
        if obs is None:
            sinks: list[EventSink] = [_CollectorSink(self.collector)]
            if self.event_sink is not None:
                sinks.append(self.event_sink)
            sink = sinks[0] if len(sinks) == 1 else MultiSink(sinks)
            obs = Observer(actor=actor, sink=sink)
            self._observers[actor] = obs
        return obs

    def emit(self, actor: str, kind: str, **payload: Any) -> Event:
        """Emit a research-plane event for ``actor`` stamped with the run id."""
        return self._observer(actor).emit(
            kind, experiment_id=self.experiment_id, **payload
        )


# ── The storyline ─────────────────────────────────────────────────

ROLES = [
    "host", "browser", "seller", "buyer", "bank",
    "escrow", "attacker", "defender", "moderator", "unstable-node",
]


def _run_storyline(w: World, profile: Profile) -> None:
    host = pseudonym("host")
    browser = pseudonym("browser")
    seller = pseudonym("seller")
    buyer = pseudonym("buyer")
    bank = pseudonym("bank")
    escrow = pseudonym("escrow")
    attacker = pseudonym("attacker")
    defender = pseudonym("defender")
    moderator = pseudonym("moderator")
    unstable = pseudonym("unstable-node")

    # 1. Everyone comes online (fixed order -> deterministic).
    for role in ROLES:
        w.emit(pseudonym(role), K_ONLINE, role=role)

    # 2. Host publishes a marketplace hidden service.
    market = "market.obscura"
    w.listings.setdefault(market, {"listings": {}})
    w.emit(host, K_SITE_HOST, site=market, title="Obscura Market")

    # 3. Seller lists an item.
    w.listings[market]["listings"]["L1"] = {
        "item": "widget", "price": 50, "by": seller,
    }
    w.emit(seller, K_MARKET_LIST, site=market, listing_id="L1",
           item="widget", price=50)

    # 4. A browser window-shops.
    w.emit(browser, K_SITE_VISIT, site=market)

    # 5. The bank mints starting funds for the buyer.
    w.ledger.mint(to_account=_account(buyer), amount=100, memo="faucet")
    w.emit(bank, K_BANK_MINT, to=buyer, amount=100)

    # 6. Buyer visits and opens an escrow against listing L1.
    w.emit(buyer, K_SITE_VISIT, site=market)
    w.ledger.transfer(from_account=_account(buyer), to_account=_account(escrow),
                      amount=50, memo="L1", nonce="buy-L1")
    w.emit(buyer, K_ESCROW_OPEN, listing_id="L1", amount=50, escrow=escrow)
    w.emit(buyer, K_BANK_TRANSFER, **{"from": buyer, "to": escrow,
                                      "amount": 50, "listing_id": "L1"})

    # 7. Escrow releases funds to the seller on delivery.
    w.ledger.transfer(from_account=_account(escrow), to_account=_account(seller),
                      amount=50, memo="L1", nonce="rel-L1")
    w.emit(escrow, K_ESCROW_RELEASE, listing_id="L1", to=seller, amount=50)
    w.emit(escrow, K_BANK_TRANSFER, **{"from": escrow, "to": seller,
                                       "amount": 50, "listing_id": "L1"})

    # 8. Buyer raises the seller's reputation after a clean deal.
    w.trust[seller] = w.trust.get(seller, 0) + 1
    w.emit(buyer, K_TRUST_UPDATE, subject=seller, delta=1,
           reason="successful_purchase", new_score=w.trust[seller])

    # 9. Attacker plants a deceptive listing and runs its techniques.
    w.listings[market]["listings"]["L2"] = {
        "item": "free money", "price": 0, "by": attacker, "deceptive": True,
    }
    w.emit(attacker, K_MARKET_LIST, site=market, listing_id="L2",
           item="free money", price=0)
    targets = {"deceptive_listing": market, "impersonation": seller}
    for tech in profile.attacker_techniques:
        w.emit(attacker, K_ATTACK, technique=tech,
               target=targets.get(tech, seller),
               **({"listing_id": "L2"} if tech == "deceptive_listing" else {}))
    if profile.attacker_violation:
        w.emit(attacker, K_POLICY_VIOLATION, rule="identity_spoofing",
               target=seller)

    # 10. Defender response (the competence under test).
    if profile.defender_detects:
        # Benign noise can delay detection, raising response latency.
        for _ in range(profile.detection_delay):
            w.emit(browser, K_SITE_VISIT, site=market)
        w.emit(defender, K_DEFENSE_FLAG, target=attacker,
               signal="anomalous_listing", listing_id="L2")
        w.trust[attacker] = w.trust.get(attacker, 0) - 5
        w.emit(defender, K_TRUST_UPDATE, subject=attacker, delta=-5,
               reason="flagged_attack", new_score=w.trust[attacker])

        # 11. Moderator contains the attacker.
        if profile.moderator_acts:
            w.listings[market]["listings"].pop("L2", None)
            w.emit(moderator, K_MODERATION, action="remove_listing",
                   listing_id="L2", target=attacker)
            w.banned.add(attacker)
            w.emit(moderator, K_MODERATION, action="ban", target=attacker)

    # 12. An unstable node flaps offline and recovers (cold-node behaviour).
    w.emit(unstable, K_NODE_UNSTABLE, state="degraded")
    w.emit(unstable, K_NODE_UNSTABLE, state="offline")
    w.emit(unstable, K_NODE_UNSTABLE, state="recovered")


@dataclass
class ScenarioResult:
    experiment_id: str
    seed: int
    collector: ObservatoryState
    ledger: LedgerState
    world: World


def run_scenario(
    *, seed: int = 47, experiment_id: str | None = None,
    profile: Profile | None = None,
) -> ScenarioResult:
    """Run the deterministic readiness-gate storyline once.

    ``profile`` selects the configuration under test (attacker aggression,
    defender competence); the default reproduces the canonical storyline.
    Records an experiment (persisted + replayable in range mode) and returns
    the populated collector + ledger for inspection. The ``experiment_id`` is
    stamped on every event regardless of mode, so the run is always groupable.
    """
    profile = profile or Profile()
    world, eid = setup_world(
        seed=seed, experiment_id=experiment_id,
        scenario="readiness_gate", profile=profile.name,
    )
    _run_storyline(world, profile)

    experiment.finish_experiment(eid)
    return ScenarioResult(
        experiment_id=eid, seed=seed,
        collector=world.collector, ledger=world.ledger, world=world,
    )


def setup_world(
    *, seed: int, experiment_id: str | None, scenario: str, **extra: Any,
) -> tuple[World, str]:
    """Start an experiment and build a populated :class:`World` for it.

    Shared by every scenario kind. Persists a durable, replayable event log
    only for real range runs (when a record was persisted); public mode stays
    in-memory so the consumer environment is never written to.
    """
    rec = experiment.start_experiment(
        experiment_id, random_seed=seed, scenario=scenario, **extra,
    )
    eid = rec.experiment_id if rec else (
        experiment_id or experiment.new_experiment_id()
    )
    event_sink: EventSink | None = None
    if rec is not None:
        event_sink = JsonlSink(experiment.events_path(eid), rotate_bytes=None)
    world = World(
        experiment_id=eid,
        rng=random.Random(seed),
        collector=ObservatoryState(),
        ledger=LedgerState(admin_fingerprint=_account(pseudonym("bank"))),
        event_sink=event_sink,
    )
    return world, eid


# ── The readiness gate ────────────────────────────────────────────

# Each question maps to the telemetry that answers it. Network-path questions
# (which route failed, which hop was slow) belong to the ops plane and a live
# multi-hop network; they are explicitly out of scope for this in-process,
# research-plane gate and are reported as such rather than silently omitted.
OPS_PLANE_QUESTIONS = [
    "which routes failed (ops plane: diag / trace on a live network)",
    "which hop caused latency (ops plane: trace spans on a live network)",
]


def readiness_report(result: ScenarioResult) -> dict[str, Any]:
    """Reconstruct the readiness answers purely from collected telemetry."""
    events = result.collector.query(limit=10_000)
    by_kind: dict[str, int] = {}
    by_actor: dict[str, int] = {}
    for e in events:
        by_kind[e.kind] = by_kind.get(e.kind, 0) + 1
        by_actor[e.actor] = by_actor.get(e.actor, 0) + 1

    def of_kind(kind: str) -> list[Event]:
        return [e for e in events if e.kind == kind]

    transfers = of_kind(K_BANK_TRANSFER) + of_kind(K_BANK_MINT)
    # Every event is attributable to an actor and an experiment run.
    attributable = all(e.actor and e.experiment_id == result.experiment_id
                       for e in events)
    replayable = experiment.load_record(result.experiment_id) is not None

    return {
        "experiment_id": result.experiment_id,
        "seed": result.seed,
        "total_events": len(events),
        "by_kind": by_kind,
        # Q: which agents were online?
        "agents_online": sorted({e.actor for e in of_kind(K_ONLINE)}),
        # Q: which services were hosted / visited?
        "services_hosted": sorted({e.payload.get("site")
                                   for e in of_kind(K_SITE_HOST)}),
        "services_visited": [
            {"by": e.actor, "site": e.payload.get("site")}
            for e in of_kind(K_SITE_VISIT)
        ],
        # Q: which transactions occurred?
        "transactions": [
            {"kind": e.kind, "by": e.actor,
             "amount": e.payload.get("amount")}
            for e in transfers
        ],
        "transaction_volume": sum(int(e.payload.get("amount") or 0)
                                  for e in transfers),
        # Q: which guardrails / adversarial events fired?
        "attacks": [e.payload.get("technique") for e in of_kind(K_ATTACK)],
        "policy_violations": [e.payload.get("rule")
                              for e in of_kind(K_POLICY_VIOLATION)],
        "defenses": [e.payload.get("target") for e in of_kind(K_DEFENSE_FLAG)],
        "moderation_actions": [e.payload.get("action")
                               for e in of_kind(K_MODERATION)],
        # Q: how did trust shift?
        "trust_changes": [
            {"subject": e.payload.get("subject"),
             "delta": e.payload.get("delta"),
             "new_score": e.payload.get("new_score")}
            for e in of_kind(K_TRUST_UPDATE)
        ],
        "final_trust": dict(result.world.trust),
        # Q: which agent initiated each action? (every event carries actor)
        "actions_per_actor": by_actor,
        "every_action_attributable": attributable,
        # Q: can the run be replayed / reconstructed?
        "replayable": replayable,
        "ledger_stats": result.ledger.stats(),
        "out_of_scope_here": OPS_PLANE_QUESTIONS,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.scenario",
        description="Run the deterministic readiness-gate agent scenario "
                    "and print the readiness report reconstructed from "
                    "collected telemetry.",
    )
    parser.add_argument("--seed", type=int, default=47)
    parser.add_argument("--experiment-id", default=None)
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON instead of text")
    args = parser.parse_args(argv)

    result = run_scenario(seed=args.seed, experiment_id=args.experiment_id)
    report = readiness_report(result)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    print(f"Readiness scenario  experiment={report['experiment_id']}  "
          f"seed={report['seed']}")
    print(f"  total events:        {report['total_events']}")
    print(f"  agents online:       {len(report['agents_online'])}  "
          f"{report['agents_online']}")
    print(f"  services hosted:     {report['services_hosted']}")
    print(f"  services visited:    {len(report['services_visited'])}")
    print(f"  transactions:        {len(report['transactions'])}  "
          f"(volume {report['transaction_volume']})")
    print(f"  attacks:             {report['attacks']}")
    print(f"  policy violations:   {report['policy_violations']}")
    print(f"  defenses fired:      {len(report['defenses'])}")
    print(f"  moderation actions:  {report['moderation_actions']}")
    print(f"  trust changes:       {report['trust_changes']}")
    print(f"  every action attributable: {report['every_action_attributable']}")
    print(f"  replayable:          {report['replayable']}")
    if not report["replayable"]:
        print("  (replay record requires OBSCURA_MODE=range)")
    print(f"  out of scope here:   {report['out_of_scope_here']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
