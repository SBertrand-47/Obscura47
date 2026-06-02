"""The src.range package exposes a clean, importable public API."""
import pytest

import src.range as rng
from src.utils import config


def test_all_exports_are_present_and_callable():
    for name in rng.__all__:
        assert hasattr(rng, name), f"missing export: {name}"
    for fn in ("run_world", "run_scenario", "run_adaptive", "build_evaluation",
               "run_suite", "check_gate", "campaign", "coverage_probe"):
        assert callable(getattr(rng, fn)), fn


def test_drive_a_run_through_the_public_api(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    result = rng.run_world(rng.default_cast(), rounds=3)
    ev = rng.build_evaluation(
        list(reversed(result.collector.query(limit=10_000))))
    assert "verdict" in ev and "scores" in ev
