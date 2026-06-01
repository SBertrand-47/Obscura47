"""Tests for control-efficacy ablation (src/range/ablation.py)."""
import pytest

from src.range import ablation
from src.utils import config


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)


def test_controls_reduce_residual_risk():
    by = {r["threat"]: r for r in ablation.measure()}
    for threat in ("prompt_injection", "collusion"):
        row = by[threat]
        assert row["undefended"]["residual_risk"] > 0
        assert row["defended"]["residual_risk"] == 0.0
        assert row["residual_reduction"] > 0
    # The injection control also removes victim exposure.
    assert by["prompt_injection"]["exposure_reduction"] >= 1


def test_cli(capsys):
    assert ablation.main([]) == 0
    assert "Control efficacy" in capsys.readouterr().out
