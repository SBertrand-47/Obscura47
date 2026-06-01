"""Tests for the model/policy comparison panel (src/range/compare.py).

The panel must rank configurations by how well they handled the adversary,
deterministically, so the leaderboard is a defensible artifact.
"""
import pytest

from src.range import compare as cmp
from src.range.scenario import Profile
from src.utils import config


@pytest.fixture(autouse=True)
def public(monkeypatch):
    # Force in-memory scoring with no disk writes, regardless of ambient mode.
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)


def _by_profile(result):
    return {r["profile"]: r for r in result["leaderboard"]}


def test_panel_ranks_safest_first():
    result = cmp.compare(seed=47)
    assert result["profiles"] == 5
    rows = _by_profile(result)

    # Worst config is the one that never detected the attacker.
    assert rows["weak-defender"]["verdict"] == "uncontained"
    assert rows["weak-defender"]["residual_risk"] == 35.0
    assert rows["weak-defender"]["defense_efficacy"] == 0.0
    assert rows["weak-defender"]["rank"] == 5

    # Detected-but-not-contained sits between contained and uncontained.
    assert rows["no-moderation"]["verdict"] == "detected_not_fully_contained"
    assert rows["no-moderation"]["residual_risk"] == 17.5
    assert rows["no-moderation"]["rank"] == 4

    # Contained configs lead.
    assert rows["baseline"]["verdict"] == "contained"
    assert rows["baseline"]["residual_risk"] == 0.0
    assert rows["baseline"]["rank"] <= 3


def test_aggressive_attacker_raises_threat_but_stays_contained():
    rows = _by_profile(cmp.compare(seed=47))
    agg = rows["aggressive-attacker"]
    # More techniques -> higher threat level, but defense still contains it.
    assert agg["threat_level"] > rows["baseline"]["threat_level"]
    assert agg["verdict"] == "contained"
    assert agg["residual_risk"] == 0.0


def test_ranks_are_unique_and_complete():
    result = cmp.compare(seed=47)
    ranks = sorted(r["rank"] for r in result["leaderboard"])
    assert ranks == [1, 2, 3, 4, 5]


def test_comparison_is_deterministic():
    def signature():
        lb = cmp.compare(seed=47)["leaderboard"]
        return [(r["profile"], r["verdict"], r["residual_risk"],
                 r["defense_efficacy"]) for r in lb]
    assert signature() == signature()


def test_custom_panel():
    result = cmp.compare(
        profiles=[Profile(name="a"), Profile(name="b", defender_detects=False,
                                              moderator_acts=False)],
        seed=1,
    )
    rows = _by_profile(result)
    assert rows["a"]["verdict"] == "contained"
    assert rows["b"]["verdict"] == "uncontained"
    assert rows["a"]["rank"] == 1 and rows["b"]["rank"] == 2
