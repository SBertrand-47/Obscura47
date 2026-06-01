"""Tests for the research-plane experiment context (src/utils/experiment.py).

Two invariants matter most:
  * public mode is a hard no-op (the consumer network is unaffected), and
  * range mode stamps a replayable experiment_id onto events in both planes.
"""
import json

import pytest

from src.utils import config, experiment


@pytest.fixture
def public(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)
    return experiment


@pytest.fixture
def rng(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)
    return experiment


class TestPublicModeInert:
    def test_no_experiment_id(self, public):
        assert public.current_experiment_id() is None
        assert public.experiment_fields() == {}

    def test_setters_are_noops(self, public):
        public.set_experiment_id("ignored")
        assert public.current_experiment_id() is None
        assert public.start_experiment("ignored") is None
        public.finish_experiment("ignored")  # must not raise

    def test_env_ignored(self, public, monkeypatch):
        monkeypatch.setenv("OBSCURA_EXPERIMENT_ID", "from-env")
        monkeypatch.setattr(experiment, "_env_resolved", False)
        assert public.current_experiment_id() is None


class TestRangeMode:
    def test_env_resolution(self, rng, monkeypatch):
        monkeypatch.setenv("OBSCURA_EXPERIMENT_ID", "exp-env")
        monkeypatch.setattr(experiment, "_env_resolved", False)
        assert rng.current_experiment_id() == "exp-env"
        assert rng.experiment_fields() == {"experiment_id": "exp-env"}

    def test_explicit_set(self, rng):
        rng.set_experiment_id("exp-set")
        assert rng.current_experiment_id() == "exp-set"

    def test_start_persists_replayable_record(self, rng):
        rec = rng.start_experiment(
            "run-1", model_id="claude-opus-4-8", random_seed=7,
            policy_version="v3",
        )
        assert rec is not None
        assert rng.current_experiment_id() == "run-1"
        # Persisted to disk and reloadable for replay.
        loaded = rng.load_record("run-1")
        assert loaded.model_id == "claude-opus-4-8"
        assert loaded.random_seed == 7
        assert loaded.policy_version == "v3"
        assert loaded.started_at > 0
        assert loaded.ended_at is None

    def test_generated_id_when_omitted(self, rng):
        rec = rng.start_experiment()
        assert rec is not None and len(rec.experiment_id) == 16

    def test_finish_stamps_ended_at_immutably(self, rng):
        rng.start_experiment("run-2")
        started = rng.load_record("run-2").started_at
        rng.finish_experiment("run-2")
        done = rng.load_record("run-2")
        assert done.ended_at is not None and done.ended_at >= started
        # start-time fields preserved, active id cleared
        assert done.started_at == started
        assert rng.current_experiment_id() is None

    def test_extra_fields_survive(self, rng, tmp_path):
        rng.start_experiment("run-3", scenario="marketplace")
        raw = json.loads((tmp_path / "exp" / "run-3.json").read_text())
        assert raw["extra"]["scenario"] == "marketplace"
