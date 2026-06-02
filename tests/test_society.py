"""Tests for the turnkey live society (src/range/society.py + the CLI)."""
import os

from src.range import __main__ as cli
from src.utils import config


def _range_env(monkeypatch, tmp_path):
    from src.utils import diag
    from src.utils import experiment as exp
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setenv("OBSCURA_DIAG", "1")
    logs = str(tmp_path / "logs")
    os.makedirs(logs, exist_ok=True)
    monkeypatch.setattr(diag, "DIAG_DIR", logs)
    monkeypatch.setattr(exp, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(exp, "_current_id", None)
    monkeypatch.setattr(exp, "_env_resolved", False)
    return logs


def test_run_demo_society_exercises_every_dimension(monkeypatch, tmp_path):
    from src.range import crossplane
    from src.range.society import run_demo_society

    logs = _range_env(monkeypatch, tmp_path)
    view = run_demo_society(logs_dir=logs)

    # Three classes of offender, each caught by its own control.
    flagged = {f["agent"]: f for f in view["threats"]["flagged_agents"]}
    assert {"attacker-1", "seller-1", "troll-1"} <= set(flagged)
    for a in ("attacker-1", "seller-1", "troll-1"):
        assert flagged[a]["status"] == "contained"
    assert "buyer-1" not in flagged and "seller-2" not in flagged
    # Every subsystem present.
    assert view["economy"]["volume"] == 80
    assert "seller-1" in view["economy"]["scam_sellers"]
    assert view["forum"]["post_count"] == 2 and "p2" in view["forum"]["removed"]
    assert view["reputation"]["seller-1"] == -2
    assert view["reputation"]["seller-2"] == 1
    # The attacker's recon traffic was traced on the wire (real ops spans).
    assert any(s["session_id"] == "S-ATK" and s["observed_on_wire"]
               for s in view["sessions"])
    # The regulator passes the run.
    assert view["compliance"]["verdict"] == "PASS"
    # It renders to one dashboard with everything.
    html = crossplane.render_html(view)
    for token in ("Traffic graph", "Reputation", "Case files",
                  "Compliance verdict", "PASS"):
        assert token in html


def test_society_cli_runs_and_reports_verdict(monkeypatch, tmp_path, capsys):
    # The subcommand sets range/diag/dirs itself; monkeypatch the globals first
    # so they are restored after the test.
    from src.utils import diag
    from src.utils import experiment as exp
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    monkeypatch.setattr(diag, "DIAG_DIR", diag.DIAG_DIR)
    monkeypatch.setattr(exp, "EXPERIMENTS_DIR", exp.EXPERIMENTS_DIR)
    monkeypatch.setattr(exp, "_current_id", None)
    monkeypatch.setattr(exp, "_env_resolved", False)

    assert cli.main(["society", "--workdir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "verdict=PASS" in out
    assert "fully observable" in out


def test_society_listed_in_surface(capsys):
    assert cli.main(["list"]) == 0
    assert "society" in capsys.readouterr().out
