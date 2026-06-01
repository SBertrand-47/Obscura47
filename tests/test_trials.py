"""Tests for the trial-aggregation harness (src/range/trials.py).

Aggregation must turn many runs into reproducible distribution statistics, and
the injection-success rate must track the buyer's susceptibility.
"""
import pytest

from src.range import trials
from src.range.agents import default_cast, run_world
from src.utils import config


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)


def test_injection_success_rate_tracks_susceptibility():
    assert trials.injection_resistance_trials(
        p_follow=0.0, n_trials=20)["injection_success_rate"] == 0.0
    assert trials.injection_resistance_trials(
        p_follow=1.0, n_trials=20)["injection_success_rate"] == 1.0
    mid = trials.injection_resistance_trials(
        p_follow=0.5, n_trials=20)["injection_success_rate"]
    assert 0.0 < mid < 1.0


def test_trials_are_reproducible():
    a = trials.injection_resistance_trials(p_follow=0.5, n_trials=20)
    b = trials.injection_resistance_trials(p_follow=0.5, n_trials=20)
    assert a == b


def test_aggregate_reports_distribution_fields():
    out = trials.injection_resistance_trials(p_follow=0.5, n_trials=10)
    for key in ("trials", "verdicts", "contained_rate", "uncontained_rate",
                "injection_success_rate", "mean_residual_risk",
                "max_residual_risk", "mean_defense_efficacy"):
        assert key in out
    assert out["trials"] == 10
    assert sum(out["verdicts"].values()) == 10


def test_run_trials_generic_over_scripted_cast():
    # The default scripted cast always contains the attacker, so every trial
    # is "contained" and no injection occurs.
    out = trials.run_trials(
        lambda s: run_world(default_cast(), rounds=6, seed=s), n_trials=5)
    assert out["contained_rate"] == 1.0
    assert out["injection_success_rate"] == 0.0
    assert out["mean_defense_efficacy"] == 100.0


def test_susceptibility_sweep_is_monotonic():
    out = trials.injection_susceptibility_sweep(n_trials=20)
    curve = out["curve"]
    assert [r["p_follow"] for r in curve] == list(trials.DEFAULT_SWEEP)
    rates = [r["injection_success_rate"] for r in curve]
    # Endpoints are pinned; the curve is non-decreasing in susceptibility.
    assert rates[0] == 0.0 and rates[-1] == 1.0
    assert all(b >= a for a, b in zip(rates, rates[1:]))
    # Residual risk rises with susceptibility too.
    residuals = [r["mean_residual_risk"] for r in curve]
    assert residuals[-1] > residuals[0]


def test_cli_sweep_runs(capsys):
    assert trials.main(["--sweep", "--trials", "10"]) == 0
    out = capsys.readouterr().out
    assert "susceptibility sweep" in out
    assert "p_follow" in out


# ── Confidence intervals ──────────────────────────────────────────

def test_wilson_ci_endpoints_are_honest():
    # "Never" and "always" still report uncertainty bounded in [0, 1].
    lo, hi = trials.wilson_ci(0, 20)
    assert lo == 0.0 and 0.0 < hi < 1.0
    lo, hi = trials.wilson_ci(20, 20)
    assert hi == 1.0 and 0.0 < lo < 1.0
    # A 50/50 split brackets 0.5.
    lo, hi = trials.wilson_ci(10, 20)
    assert lo < 0.5 < hi
    # Degenerate n is safe.
    assert trials.wilson_ci(0, 0) == (0.0, 0.0)


def test_run_trials_reports_ci_containing_the_rate():
    out = trials.injection_resistance_trials(p_follow=0.5, n_trials=20)
    lo, hi = out["ci"]["injection_success_rate"]
    assert lo <= out["injection_success_rate"] <= hi
    # Every headline rate has a matching interval.
    for name in ("contained_rate", "uncontained_rate", "injection_success_rate",
                 "injection_exposure_rate", "tool_misuse_rate"):
        assert name in out["ci"]


def test_sweep_includes_confidence_intervals():
    curve = trials.injection_susceptibility_sweep(n_trials=20)["curve"]
    for row in curve:
        lo, hi = row["injection_success_ci"]
        assert lo <= row["injection_success_rate"] <= hi
    # Endpoints honest: 0.0 has a lower bound of 0, 1.0 an upper bound of 1.
    assert curve[0]["injection_success_ci"][0] == 0.0
    assert curve[-1]["injection_success_ci"][1] == 1.0
