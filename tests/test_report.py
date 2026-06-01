"""Tests for run reconstruction (src/range/report.py).

The point of the report is replay: rebuild a run's full story from the durable
event log and record, independent of the live process that produced it.
"""
import pytest

from src.range import report as rp
from src.range.scenario import run_scenario
from src.utils import config, experiment


@pytest.fixture
def rng(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)


def test_event_log_round_trips(rng):
    result = run_scenario(seed=47, experiment_id="run-rt")
    in_memory = result.collector.query(limit=10_000)
    from_disk = rp.load_events("run-rt")
    assert len(from_disk) == len(in_memory)
    # Same chronological sequence of (actor, kind).
    mem_seq = [(e.actor, e.kind) for e in reversed(in_memory)]
    disk_seq = [(e.actor, e.kind) for e in from_disk]
    assert disk_seq == mem_seq


def test_report_reconstructs_the_run(rng):
    run_scenario(seed=47, experiment_id="run-rep")
    report = rp.build_report("run-rep")

    assert report["reconstructed_from_storage"] is True
    assert report["record"] is not None
    assert report["record"]["random_seed"] == 47
    assert report["event_count"] == 31
    assert len(report["agents"]) == 10
    # First thing that happened is the host coming online.
    assert report["timeline"][0]["actor"] == "host-1"
    assert report["timeline"][0]["kind"] == "agent.online"
    # Economy + trust rebuilt from the log alone.
    assert len(report["transactions"]) == 3
    assert report["trust"] == {"seller-1": 1, "attacker-1": -5}
    # Adversarial chain present.
    adv = report["adversarial"]
    assert len(adv["attacks"]) == 2
    assert len(adv["policy_violations"]) == 1
    assert len(adv["moderation"]) == 2


def test_investigation_chains_attack_to_response(rng):
    run_scenario(seed=47, experiment_id="run-inv")
    report = rp.build_report("run-inv")
    chain = report["investigations"]["attacker-1"]
    kinds = [row["kind"] for row in chain]
    # The suspect's own actions and the responses that targeted them appear
    # in one ordered chain: attack -> defensive flag -> moderation/ban.
    assert "attack.attempt" in kinds
    assert "defense.flag" in kinds
    assert "moderation.action" in kinds
    assert kinds.index("attack.attempt") < kinds.index("defense.flag")
    assert kinds.index("defense.flag") < kinds.index("moderation.action")


def test_render_text_is_human_readable(rng):
    run_scenario(seed=47, experiment_id="run-txt")
    text = rp.render_text(rp.build_report("run-txt"))
    assert "Experiment run-txt" in text
    assert "Timeline" in text
    assert "Investigation: attacker-1" in text
    assert "ATTACK" in text


def test_unknown_experiment_is_empty(rng):
    report = rp.build_report("does-not-exist")
    assert report["event_count"] == 0
    assert report["record"] is None
