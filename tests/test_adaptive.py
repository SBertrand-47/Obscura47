"""Tests for the multi-round adaptive adversary (src/range/adaptive.py).

The emergent dynamics must be correct and deterministic: a weak defender
suffers breaches as the attacker escalates, then contains it once the
repertoire is exhausted; a strong defender contains from round one; a passive
defender never contains. Adaptive runs must also feed the existing evaluator.
"""
import pytest

from src.range import adaptive as ad
from src.range.evaluate import build_evaluation
from src.range.scenario import K_ATTACK
from src.utils import config


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)


def test_weak_defender_breaches_then_contains():
    res = ad.run_adaptive(rounds=10, defender=ad.DEFENDERS["weak"])
    s = res.summary
    # Five novel techniques each slip through exactly once before being learned.
    assert s["breaches"] == 5
    assert s["first_breach_round"] == 1
    assert s["final_state"] == "contained"
    assert s["contained_from_round"] == 10
    # Defender ends up knowing the whole repertoire.
    assert len(s["defender_known_final"]) == 5


def test_attacker_escalates_after_being_caught():
    res = ad.run_adaptive(rounds=10, defender=ad.DEFENDERS["weak"])
    used = res.summary["techniques_used"]
    # The technique only advances after a catch -> each appears twice in order
    # (breach, then caught), and the sequence escalates through the repertoire.
    distinct_in_order = []
    for t in used:
        if t not in distinct_in_order:
            distinct_in_order.append(t)
    assert distinct_in_order == list(ad.DEFAULT_REPERTOIRE)


def test_strong_defender_contains_immediately():
    res = ad.run_adaptive(rounds=6, defender=ad.DEFENDERS["strong"])
    s = res.summary
    assert s["breaches"] == 0
    assert s["contained_from_round"] == 1
    assert s["final_state"] == "contained"


def test_passive_defender_never_contains():
    res = ad.run_adaptive(rounds=8, defender=ad.DEFENDERS["passive"])
    s = res.summary
    # Never learns, never contains -> attacker stays on its first technique and
    # breaches every round.
    assert s["breaches"] == 8
    assert s["final_state"] == "active_breach"
    assert set(s["techniques_used"]) == {ad.DEFAULT_REPERTOIRE[0]}


def test_deterministic():
    a = ad.run_adaptive(rounds=10, defender=ad.DEFENDERS["weak"]).summary
    b = ad.run_adaptive(rounds=10, defender=ad.DEFENDERS["weak"]).summary
    assert a == b


def test_events_feed_the_evaluator():
    res = ad.run_adaptive(rounds=10, defender=ad.DEFENDERS["weak"])
    events = list(reversed(res.collector.query(limit=10_000)))
    report = build_evaluation(events)
    # One attack event per round reaches the evaluator.
    assert report["adversarial"]["attacks"] == 10
    assert report["verdict"] in {
        "contained", "detected_not_fully_contained", "uncontained",
    }


# ── Defender comparison leaderboard ───────────────────────────────

def _by_defender(result):
    return {r["defender"]: r for r in result["leaderboard"]}


def test_defender_leaderboard_ranks_by_resilience():
    result = ad.compare_defenders(rounds=10)
    assert result["defenders"] == 4
    rows = _by_defender(result)

    # Strong defender: zero breaches, best rank.
    assert rows["strong-defender"]["breaches"] == 0
    assert rows["strong-defender"]["rank"] == 1
    # Learning starts ahead of weak (knows phishing), so suffers fewer breaches.
    assert rows["learning-defender"]["breaches"] == 4
    assert rows["weak-defender"]["breaches"] == 5
    assert (rows["learning-defender"]["rank"] < rows["weak-defender"]["rank"])
    # Passive never contains and is worst.
    assert rows["passive-defender"]["ever_contained"] is False
    assert rows["passive-defender"]["rank"] == 4


def test_defender_leaderboard_ranks_unique_and_deterministic():
    a = ad.compare_defenders(rounds=10)
    b = ad.compare_defenders(rounds=10)
    assert [r["rank"] for r in a["leaderboard"]] == [1, 2, 3, 4]
    assert ([(r["defender"], r["breaches"]) for r in a["leaderboard"]]
            == [(r["defender"], r["breaches"]) for r in b["leaderboard"]])
