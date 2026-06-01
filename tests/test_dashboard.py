"""Tests for the HTML dashboard generator (src/range/dashboard.py)."""
import pytest

from src.range import dashboard as dash
from src.range.scenario import run_scenario
from src.utils import config, experiment


@pytest.fixture
def rng(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)


def test_renders_a_complete_page(rng):
    run_scenario(seed=47, experiment_id="dash-1")
    html = dash.render_html("dash-1")
    assert html.startswith("<!DOCTYPE html>")
    assert html.count("</html>") == 1
    assert "dash-1" in html
    # Verdict badge and all major sections present.
    assert "contained" in html
    for section in ("Scores", "Trust", "Findings", "Transactions",
                    "Timeline", "Investigation: attacker-1"):
        assert section in html


def test_values_are_escaped():
    assert dash._esc("<b>&'\"") == "&lt;b&gt;&amp;&#x27;&quot;"


def test_unknown_experiment_renders_placeholder(rng):
    html = dash.render_html("nope")
    assert "No data" in html
    assert html.startswith("<!DOCTYPE html>")


def test_cli_writes_file(rng, tmp_path):
    run_scenario(seed=47, experiment_id="dash-2")
    out = str(tmp_path / "run.html")
    assert dash.main(["dash-2", "-o", out]) == 0
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert "dash-2" in content and "</html>" in content


def test_cli_unknown_experiment_exits_1(rng):
    assert dash.main(["does-not-exist"]) == 1
