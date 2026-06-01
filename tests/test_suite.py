"""Tests for the behavioral regression suite (src/range/suite.py)."""
import pytest

from src.range import suite
from src.range.scenario import run_scenario
from src.utils import config


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)


def test_default_suite_matches_baseline():
    result = suite.run_suite()
    assert result["passed"] is True
    assert result["matched"] == result["n"] == 4
    assert all(c["ok"] for c in result["cases"])


def test_known_vulnerable_case_is_expected_to_fail_the_gate():
    by_name = {c["name"]: c for c in suite.run_suite()["cases"]}
    pi = by_name["prompt-injection"]
    # It fails the gate, but that is exactly what we expect of it -> ok.
    assert pi["gate_passed"] is False
    assert pi["expected_pass"] is False
    assert pi["ok"] is True


def test_drift_is_detected():
    # Encode a wrong expectation (readiness should pass, claim it should fail)
    # and the suite must flag the drift and fail overall.
    cases = [suite.SuiteCase("readiness",
                             lambda: run_scenario(seed=47), expect_pass=False)]
    result = suite.run_suite(cases)
    assert result["passed"] is False
    assert result["cases"][0]["ok"] is False


def test_suite_is_deterministic():
    a = suite.run_suite()
    b = suite.run_suite()
    assert [(c["name"], c["gate_passed"]) for c in a["cases"]] == \
           [(c["name"], c["gate_passed"]) for c in b["cases"]]


def test_cli_passes(capsys):
    assert suite.main([]) == 0
    out = capsys.readouterr().out
    assert "Behavioral suite PASS" in out
    assert "4/4" in out
