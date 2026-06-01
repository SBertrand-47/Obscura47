"""Tests for the per-round trajectory view (src/range/trajectory.py)."""
import pytest

from src.range import trajectory as tr
from src.range.adaptive import DEFENDERS, run_adaptive
from src.range.agents import default_cast, run_world
from src.utils import config, experiment


@pytest.fixture
def rng(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)


def test_adaptive_trajectory_shows_cat_and_mouse(rng):
    run_adaptive(rounds=6, defender=DEFENDERS["weak"], experiment_id="t1")
    traj = tr.build_trajectory("t1")
    assert [b["round"] for b in traj] == [1, 2, 3, 4, 5, 6]
    assert sum(b["attacks"] for b in traj) == 6        # one attack per round
    assert any(b["defenses"] for b in traj)            # some rounds caught
    assert sum(b["trust_delta"] for b in traj) < 0     # catches lower trust
    assert all("active_agents" in b for b in traj)


def test_agents_trajectory_has_economy_activity(rng):
    run_world(default_cast(), rounds=3, experiment_id="t2")
    traj = tr.build_trajectory("t2")
    assert any(b["volume"] > 0 for b in traj)          # the buyer's purchase
    assert any(b["attacks"] > 0 for b in traj)


def test_setup_events_without_round_are_skipped(rng):
    # run_world emits agent.online / bank.mint with no round; those must not
    # create a phantom round bucket.
    run_world(default_cast(), rounds=2, experiment_id="t3")
    rounds = {b["round"] for b in tr.build_trajectory("t3")}
    assert rounds == {1, 2}


def test_unknown_experiment_is_empty(rng):
    assert tr.build_trajectory("nope") == []


def test_under_defended_rounds_flags_breach_windows(rng):
    # Weak defender: every other round an attack slips through undefended.
    run_adaptive(rounds=6, defender=DEFENDERS["weak"], experiment_id="ud")
    breaches = tr.under_defended_rounds(tr.build_trajectory("ud"))
    assert breaches == [1, 3, 5]
    # A strong defender catches every attack: no breach windows.
    run_adaptive(rounds=6, defender=DEFENDERS["strong"], experiment_id="ud2")
    assert tr.under_defended_rounds(tr.build_trajectory("ud2")) == []


def test_render_and_cli(rng, capsys):
    run_adaptive(rounds=3, defender=DEFENDERS["weak"], experiment_id="t4")
    assert "round" in tr.render_text(tr.build_trajectory("t4"))
    assert tr.main(["t4"]) == 0
    assert "attacks" in capsys.readouterr().out
