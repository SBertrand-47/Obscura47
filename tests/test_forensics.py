"""Tests for per-suspect incident reconstruction (src/range/forensics.py)."""
import pytest

from src.range import forensics as fx
from src.range.agents import (
    collusion_cast, injection_cast, run_world, scam_escrow_cast)
from src.range.scenario import run_scenario
from src.utils import config, experiment


@pytest.fixture
def rng(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)


def _one(experiment_id):
    incs = fx.build_incidents(experiment_id)
    return {i["suspect"]: i for i in incs}


# ── Severity logic (unit) ─────────────────────────────────────────

def test_severity_branches():
    assert fx._severity(flagged=False, banned=False, funds=0, attacks=1) == "high"
    assert fx._severity(flagged=False, banned=False, funds=50, attacks=0) == "high"
    assert fx._severity(flagged=True, banned=False, funds=0, attacks=1) == "medium"
    assert fx._severity(flagged=True, banned=True, funds=0, attacks=1) == "low"
    # Extracted funds with full containment is not high.
    assert fx._severity(flagged=True, banned=True, funds=50, attacks=1) == "low"


# ── Reconstruction across threat families ─────────────────────────

def test_undefended_injection_is_high_with_funds_extracted(rng):
    run_world(injection_cast(), rounds=3, experiment_id="inj")
    inc = _one("inj")["attacker-1"]
    assert inc["severity"] == "high"
    assert "prompt_injection" in inc["techniques"]
    assert inc["funds_extracted"] == 50
    assert inc["flagged"] is False and inc["contained"] is False


def test_collusion_links_accomplices(rng):
    run_world(collusion_cast(), rounds=4, experiment_id="col")
    incs = _one("col")
    assert incs["colluder-1"]["accomplices"] == ["colluder-2"]
    assert incs["colluder-2"]["accomplices"] == ["colluder-1"]
    assert incs["colluder-1"]["severity"] == "high"  # undetected


def test_scam_contained_by_escrow_is_low(rng):
    run_world(scam_escrow_cast(), rounds=3, experiment_id="scam")
    inc = _one("scam")["seller-1"]
    assert inc["techniques"] == ["scam"]
    assert inc["contained"] is True
    assert inc["funds_extracted"] == 0       # escrow refunded the buyer
    assert inc["severity"] == "low"


def test_readiness_attacker_is_contained(rng):
    run_scenario(seed=47, experiment_id="rd")
    inc = _one("rd")["attacker-1"]
    assert inc["flagged"] and inc["banned"] and inc["contained"]
    assert inc["severity"] == "low"
    assert inc["timeline"]  # evidence chain present


def test_no_adversarial_activity_yields_no_incidents(rng):
    # An all-honest agents run has no suspects.
    from src.range.agents import Agent, ScriptedPolicy
    from src.range.scenario import pseudonym
    cast = [Agent(pseudonym("host"), "host", "h", ScriptedPolicy()),
            Agent(pseudonym("seller"), "seller", "s", ScriptedPolicy())]
    run_world(cast, rounds=2, experiment_id="clean")
    assert fx.build_incidents("clean") == []


def test_unknown_experiment_is_empty(rng):
    assert fx.build_incidents("nope") == []


def test_incidents_from_events_matches_disk(rng):
    from src.range.report import load_events
    run_world(injection_cast(), rounds=3, experiment_id="mem")
    from_disk = fx.build_incidents("mem")
    in_memory = fx.incidents_from_events(load_events("mem"))
    assert from_disk == in_memory


def test_aggregate_rolls_up():
    incs = [
        {"severity": "high", "contained": False, "funds_extracted": 50},
        {"severity": "low", "contained": True, "funds_extracted": 0},
    ]
    agg = fx.aggregate(incs)
    assert agg["suspects"] == 2
    assert agg["by_severity"] == {"high": 1, "low": 1}
    assert agg["contained"] == 1 and agg["uncontained"] == 1
    assert agg["total_funds_extracted"] == 50
    assert agg["containment_rate"] == 0.5


def test_campaign_portfolio(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)  # in-memory, no disk
    result = fx.campaign()
    agg = result["aggregate"]
    assert agg["suspects"] >= 4
    assert agg["total_funds_extracted"] == 50      # the undefended injection
    assert 0.0 <= agg["containment_rate"] <= 1.0
    assert len(result["scenarios"]) == 9


def test_cli_campaign_and_missing_arg(capsys, monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    assert fx.main(["--campaign"]) == 0
    assert "Campaign portfolio" in capsys.readouterr().out
    assert fx.main([]) == 2          # no experiment_id and no --campaign


def test_render_and_cli(rng, capsys):
    run_world(injection_cast(), rounds=3, experiment_id="r1")
    text = fx.render_text(fx.build_incidents("r1"))
    assert "[HIGH]" in text and "attacker-1" in text
    assert fx.main(["r1"]) == 0
    assert "incident" in capsys.readouterr().out.lower()
