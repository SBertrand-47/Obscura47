"""Tests for the decision-loop engine (src/range/agents.py).

The engine must turn observation-driven policy choices into the same
evaluatable telemetry as the scripted scenario, deterministically, and the
LLM policy must be a clean opt-in that never breaks the default path.
"""
import pytest

from src.range import agents as ag
from src.range.agents import Action, Agent, Observation, run_world, default_cast
from src.range.evaluate import build_evaluation
from src.range.scenario import K_TOOL_MISUSE, _account, pseudonym
from src.utils import config


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)


def _events(result):
    return list(reversed(result.collector.query(limit=10_000)))


def test_scripted_world_produces_evaluatable_telemetry():
    result = run_world(default_cast(), rounds=6)
    report = build_evaluation(_events(result))
    assert report["adversarial"]["attacks"] >= 1
    assert report["verdict"] in {
        "contained", "detected_not_fully_contained", "uncontained",
    }


def test_buyer_purchase_settles_ledger():
    result = run_world(default_cast(), rounds=6)
    led = result.ledger
    # Buyer funded 100, buys the 50 listing -> 50 each.
    assert led.balance(_account(pseudonym("buyer"))) == 50
    assert led.balance(_account(pseudonym("seller"))) == 50


def test_attacker_is_contained_and_then_idle():
    result = run_world(default_cast(), rounds=8)
    events = _events(result)
    # Once banned, the attacker stops acting: no attack after the ban round.
    ban_round = next(e.payload["round"] for e in events
                     if e.kind == "moderation.action")
    later_attacks = [e for e in events if e.kind == "attack.attempt"
                     and e.payload["round"] > ban_round]
    assert later_attacks == []


def test_engine_is_deterministic():
    def sig():
        evs = _events(run_world(default_cast(), rounds=6))
        return [(e.actor, e.kind, e.payload.get("round")) for e in evs]
    assert sig() == sig()


def test_policy_factory_swaps_behaviour():
    class Idle:
        def decide(self, obs: Observation) -> Action:
            return Action.idle()

    result = run_world(default_cast(lambda role, goal: Idle()), rounds=5)
    report = build_evaluation(_events(result))
    # Every agent idles -> no adversarial activity at all.
    assert report["adversarial"]["attacks"] == 0
    assert report["verdict"] == "no_adversarial_activity"


def test_observation_hides_bought_listings_and_self():
    # A custom buyer policy captures the observation it is given.
    seen = {}

    class Recorder:
        def __init__(self, role):
            self.role = role

        def decide(self, obs):
            if obs.role == "buyer":
                seen["listings"] = obs.listings
            return Action.idle()

    cast = default_cast(lambda role, goal: Recorder(role))
    # Seed a listing so the buyer has something to observe: use the scripted
    # seller instead for that one role.
    cast = [a if a.role != "seller" else Agent(
        a.actor, a.role, a.goal, ag.ScriptedPolicy()) for a in cast]
    run_world(cast, rounds=3)
    # Listings the buyer sees never expose the private 'deceptive' flag.
    assert all("deceptive" not in l for l in seen.get("listings", []))


def test_llm_policy_is_opt_in_and_gated():
    # No anthropic SDK / key in this environment: construction must fail
    # clearly rather than silently, and must not affect the scripted path.
    with pytest.raises(RuntimeError):
        ag.LLMPolicy(role="attacker", goal="x")


# ── Turnkey runner CLI ────────────────────────────────────────────

def test_cli_scripted_run_succeeds(capsys):
    assert ag.main(["--llm-roles", "none", "--rounds", "4"]) == 0
    out = capsys.readouterr().out
    assert "Agent world" in out
    assert "Evaluation" in out


def test_cli_json_output(capsys):
    import json
    assert ag.main(["--llm-roles", "none", "--rounds", "4", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "verdict" in payload and "scores" in payload


def test_cli_llm_without_key_exits_1(capsys):
    # Requesting a live-model role with no SDK/key fails loudly, no silent
    # fallback to scripted.
    assert ag.main(["--llm-roles", "attacker"]) == 1
    assert "anthropic" in capsys.readouterr().err


def test_cli_rejects_unknown_role():
    assert ag.main(["--llm-roles", "wizard"]) == 2


# ── Tool-misuse enforcement ───────────────────────────────────────

def _events(result):
    return list(reversed(result.collector.query(limit=10_000)))


def test_unauthorized_privilege_is_misuse_and_refused():
    # A seller reaching for moderator powers is recorded as misuse and the
    # effect is refused.
    class Rogue:
        def __init__(self):
            self._done = False

        def decide(self, obs):
            if obs.role == "seller" and not self._done:
                self._done = True
                return Action("moderate", {"action": "ban", "target": "buyer-1"})
            return Action.idle()

    cast = [a if a.role != "seller"
            else Agent(a.actor, a.role, a.goal, Rogue())
            for a in default_cast()]
    result = run_world(cast, rounds=4)
    misuse = [e for e in _events(result) if e.kind == K_TOOL_MISUSE]
    assert any(e.payload["reason"] == "unauthorized_moderate" for e in misuse)
    assert "buyer-1" not in result.world.banned  # effect refused


def test_action_while_banned_is_misuse():
    # An attacker that keeps attacking after being banned trips the
    # acted_while_banned signal.
    class Relentless:
        def decide(self, obs):
            return Action("attack", {"technique": "phishing",
                                     "target": "seller-1"})

    cast = [a if a.role != "attacker"
            else Agent(a.actor, a.role, a.goal, Relentless())
            for a in default_cast()]
    result = run_world(cast, rounds=5)
    reasons = {e.payload.get("reason") for e in _events(result)
               if e.kind == K_TOOL_MISUSE}
    assert "acted_while_banned" in reasons
