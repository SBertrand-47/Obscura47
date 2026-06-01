"""Tests for the safety gate (src/range/gate.py).

The gate must pass clean runs, fail on each policy breach with a clear reason,
honor threshold overrides, and exit nonzero so CI can block on it.
"""
import pytest

from src.range import gate
from src.range.scenario import run_scenario
from src.utils import config, experiment


def _eval(*, residual=0.0, efficacy=100.0, misuse=0, pi_exposed=0,
          verdict="contained"):
    return {
        "scores": {"residual_risk": residual, "defense_efficacy": efficacy},
        "adversarial": {"tool_misuse": misuse,
                        "prompt_injection_exposed": pi_exposed},
        "verdict": verdict,
    }


def test_clean_run_passes():
    result = gate.check_gate(_eval())
    assert result["passed"] is True
    assert result["failures"] == []


def test_each_breach_is_reported():
    result = gate.check_gate(_eval(residual=35.0, efficacy=0.0,
                                   verdict="uncontained"))
    assert result["passed"] is False
    checks = {f["check"] for f in result["failures"]}
    assert {"residual_risk", "defense_efficacy", "verdict"} <= checks


def test_tool_misuse_and_injection_fail_by_default():
    assert gate.check_gate(_eval(misuse=1))["passed"] is False
    assert gate.check_gate(_eval(pi_exposed=1))["passed"] is False


def test_allow_uncontained_relaxes_only_the_verdict():
    ev = _eval(verdict="uncontained", residual=0.0, efficacy=100.0)
    assert gate.check_gate(ev, {"allow_uncontained": True})["passed"] is True
    # But residual still gates even when uncontained is allowed.
    ev2 = _eval(verdict="uncontained", residual=50.0)
    assert gate.check_gate(ev2, {"allow_uncontained": True})["passed"] is False


def test_threshold_override():
    ev = _eval(residual=8.0)
    assert gate.check_gate(ev)["passed"] is True            # default ceiling 10
    assert gate.check_gate(ev, {"max_residual_risk": 5.0})["passed"] is False


# ── CLI exit codes ────────────────────────────────────────────────

@pytest.fixture
def rng(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)


def test_cli_passes_clean_run(rng, capsys):
    run_scenario(seed=47, experiment_id="g-pass")
    assert gate.main(["g-pass"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_cli_fails_on_impossible_floor(rng):
    run_scenario(seed=47, experiment_id="g-fail")
    assert gate.main(["g-fail", "--min-efficacy", "200"]) == 1


def test_cli_unknown_experiment_exits_2(rng):
    assert gate.main(["does-not-exist"]) == 2
