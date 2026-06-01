"""Tests for the risk-surface matrix (src/range/matrix.py).

The surface must show breaches rising with attacker repertoire and falling with
defender competence, deterministically, including the regime where novel
techniques breach even a strong defender.
"""
from src.range import matrix as mx


def _cells(matrix, defender):
    row = next(r for r in matrix["rows"] if r["defender"] == defender)
    return [c["breaches"] for c in row["cells"]]


def test_breaches_rise_with_repertoire_for_each_defender():
    matrix = mx.risk_matrix(rounds=12)
    for row in matrix["rows"]:
        breaches = [c["breaches"] for c in row["cells"]]
        assert all(b >= a for a, b in zip(breaches, breaches[1:])), row["defender"]


def test_stronger_defender_never_does_worse():
    matrix = mx.risk_matrix(rounds=12)
    strong = _cells(matrix, "strong")
    learning = _cells(matrix, "learning")
    weak = _cells(matrix, "weak")
    passive = _cells(matrix, "passive")
    for col in range(len(matrix["repertoire_sizes"])):
        assert strong[col] <= learning[col] <= weak[col] <= passive[col]


def test_novel_techniques_breach_even_a_strong_defender():
    # Within its known set the strong defender takes no breaches; once the
    # repertoire extends past it (size 8 includes zero-days), it does.
    matrix = mx.risk_matrix(rounds=12)
    strong = _cells(matrix, "strong")
    assert strong[0] == 0
    assert strong[-1] > 0


def test_passive_defender_never_contains():
    matrix = mx.risk_matrix(rounds=12)
    row = next(r for r in matrix["rows"] if r["defender"] == "passive")
    assert all(c["final_state"] == "active_breach" for c in row["cells"])


def test_matrix_is_deterministic():
    assert mx.risk_matrix(rounds=12) == mx.risk_matrix(rounds=12)


def test_cli_runs(capsys):
    assert mx.main(["--rounds", "10"]) == 0
    out = capsys.readouterr().out
    assert "Risk surface" in out
    assert "strong" in out
