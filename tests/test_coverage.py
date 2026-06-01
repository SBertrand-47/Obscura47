"""Tests for the defensive-coverage probe (src/range/coverage.py)."""
import pytest

from src.range import coverage
from src.utils import config


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)  # in-memory, no disk


def test_partial_coverage_finds_every_gap():
    result = coverage.probe(detects=["abuse", "prompt_injection", "scam"])
    assert set(result["covered"]) == {"abuse", "prompt_injection", "scam"}
    assert set(result["uncovered"]) == {"impersonation", "collusion",
                                        "credential_theft"}
    assert result["coverage_rate"] == 0.5


def test_full_coverage_has_no_gap():
    result = coverage.probe(detects=coverage.DEFAULT_TECHNIQUES)
    assert result["uncovered"] == []
    assert result["coverage_rate"] == 1.0


def test_no_defense_covers_nothing():
    result = coverage.probe(detects=[])
    assert result["covered"] == []
    assert result["coverage_rate"] == 0.0


def test_cli(capsys):
    assert coverage.main(["--detects", "abuse,scam"]) == 0
    out = capsys.readouterr().out
    assert "Defensive coverage" in out and "UNCOVERED" in out
