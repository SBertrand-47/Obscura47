"""Tests for the readiness-gate scenario (src/range/scenario.py).

The gate's promise: from collected telemetry alone an operator can answer the
questions that make the network worth studying, and the run is deterministic
and replayable. These tests assert exactly that.
"""
import pytest

from src.range import scenario as sc
from src.range.scenario import _account, pseudonym, readiness_report, run_scenario
from src.utils import config, experiment


@pytest.fixture
def rng(monkeypatch, tmp_path):
    """Run scenarios in range mode with isolated experiment storage."""
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)


def test_report_answers_every_readiness_question(rng):
    report = readiness_report(run_scenario(seed=47))

    # Which agents were online? -> all ten roles.
    assert len(report["agents_online"]) == 10
    # Which services were hosted / visited?
    assert report["services_hosted"] == ["market.obscura"]
    assert len(report["services_visited"]) == 2
    # Which transactions occurred? (mint + two escrow legs)
    assert len(report["transactions"]) == 3
    assert report["transaction_volume"] == 200
    # Which adversarial / guardrail events fired?
    assert set(report["attacks"]) == {"deceptive_listing", "impersonation"}
    assert report["policy_violations"] == ["identity_spoofing"]
    assert len(report["defenses"]) == 1
    assert set(report["moderation_actions"]) == {"remove_listing", "ban"}
    # How did trust shift?
    assert report["final_trust"] == {"seller-1": 1, "attacker-1": -5}
    # Which agent initiated each action? Every event is attributable.
    assert report["every_action_attributable"] is True
    # Can the run be replayed?
    assert report["replayable"] is True


def test_every_event_carries_the_experiment_id(rng):
    result = run_scenario(seed=47)
    events = result.collector.query(limit=10_000)
    assert events  # non-empty
    assert all(e.experiment_id == result.experiment_id for e in events)


def test_run_is_deterministic(rng):
    def signature(seed):
        events = run_scenario(seed=seed).collector.query(limit=10_000)
        # query returns newest-first; reverse for chronological order.
        return [(e.actor, e.kind) for e in reversed(events)]

    assert signature(47) == signature(47)


def test_replayable_record_captures_config(rng):
    result = run_scenario(seed=99)
    rec = experiment.load_record(result.experiment_id)
    assert rec is not None
    assert rec.random_seed == 99
    assert rec.extra.get("scenario") == "readiness_gate"
    assert rec.ended_at is not None  # finished


def test_ledger_balances_settle_correctly(rng):
    result = run_scenario(seed=47)
    led = result.ledger
    # Buyer minted 100, paid 50 into escrow -> 50 left.
    assert led.balance(_account(pseudonym("buyer"))) == 50
    # Escrow received 50, released 50 to seller -> 0.
    assert led.balance(_account(pseudonym("escrow"))) == 0
    # Seller received the released 50.
    assert led.balance(_account(pseudonym("seller"))) == 50


def test_public_mode_runs_but_is_not_replayable(monkeypatch):
    """Outside range mode the scenario still produces a fully stamped,
    queryable event stream, but no replay record is persisted."""
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    result = run_scenario(seed=47)
    events = result.collector.query(limit=10_000)
    # Events are still grouped under the run id (passed explicitly).
    assert all(e.experiment_id == result.experiment_id for e in events)
    # But there is no persisted, replayable record in public mode.
    assert readiness_report(result)["replayable"] is False
