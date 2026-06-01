"""Tests for the unified range entry point (src/range/__main__.py)."""
import json

import pytest

from src.range import __main__ as cli
from src.utils import config, experiment


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)


def test_every_readonly_subcommand_works_on_a_persisted_run(monkeypatch,
                                                            tmp_path, capsys):
    # Persist one rich run, then smoke-test every read tool against it.
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    from src.range.agents import default_cast, run_world
    run_world(default_cast(), rounds=4, experiment_id="smoke",
              trace_decisions=True)

    out = str(tmp_path / "x")
    for argv in (["report", "smoke"], ["evaluate", "smoke"],
                 ["incidents", "smoke"], ["trajectory", "smoke"],
                 ["dashboard", "smoke", "-o", out + ".html"],
                 ["evidence", "smoke", "--md", out + ".md"],
                 ["gate", "smoke"]):
        assert cli.main(argv) == 0, argv


def test_every_generator_subcommand_works(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    assert cli.main(["suite"]) == 0
    assert cli.main(["compare"]) == 0
    assert cli.main(["matrix", "--rounds", "8"]) == 0
    assert cli.main(["incidents", "--campaign"]) == 0
    assert cli.main(["adaptive", "--rounds", "4"]) == 0
    assert cli.main(["agents", "--cast", "society", "--rounds", "8"]) == 0


def test_run_readiness(capsys):
    assert cli.main(["run", "--kind", "readiness"]) == 0
    out = capsys.readouterr().out
    assert "kind=readiness" in out
    assert "verdict=" in out


def test_run_adaptive(capsys):
    assert cli.main(["run", "--kind", "adaptive", "--defender", "weak",
                     "--rounds", "8"]) == 0
    assert "kind=adaptive" in capsys.readouterr().out


def test_run_agents(capsys):
    assert cli.main(["run", "--kind", "agents", "--rounds", "6"]) == 0
    assert "kind=agents" in capsys.readouterr().out


def test_run_society(capsys):
    assert cli.main(["run", "--kind", "society", "--rounds", "8"]) == 0
    out = capsys.readouterr().out
    assert "kind=society" in out and "verdict=contained" in out


def test_run_json(capsys):
    assert cli.main(["run", "--kind", "readiness", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "experiment_id" in payload
    assert payload["evaluation"]["verdict"] == "contained"


def test_run_agents_replay_reproduces_without_key(tmp_path):
    # A recording of an attacker attacking each round; replay needs no key.
    recs = [{"blocks": [{"input": {"kind": "attack",
                                   "params": {"technique": "phishing",
                                              "target": "seller-1"}},
                         "id": "tu"}], "usage": None} for _ in range(2)]
    path = str(tmp_path / "rec.json")
    json.dump(recs, open(path, "w"))
    out = cli.run_pipeline(kind="agents", rounds=2, llm_roles={"attacker"},
                           replay_path=path)
    assert out["evaluation"]["adversarial"]["attacks"] >= 1


def test_run_agents_record_without_key_exits_1(capsys, tmp_path):
    # Recording wraps a real client, which needs the SDK + key: fail cleanly.
    code = cli.main(["run", "--kind", "agents", "--llm-roles", "attacker",
                     "--record", str(tmp_path / "out.json")])
    assert code == 1


def test_run_agents_llm_without_key_exits_1(capsys):
    # Requesting a live model role with no SDK/key fails cleanly via the
    # pipeline's RuntimeError handling.
    assert cli.main(["run", "--kind", "agents", "--llm-roles", "attacker"]) == 1
    assert "anthropic" in capsys.readouterr().err


def test_unknown_subcommand(capsys):
    assert cli.main(["bogus"]) == 2
    assert "unknown subcommand" in capsys.readouterr().err


def test_list_command_enumerates_the_surface(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "run kinds:" in out and "casts:" in out and "subcommands:" in out
    for token in ("society", "honeypot", "scam-escrow", "ablation"):
        assert token in out


def test_help_lists_subcommands(capsys):
    assert cli.main([]) == 0
    assert "run" in capsys.readouterr().out


def test_dispatch_to_report(capsys):
    # Delegates to report.main, which returns 1 for an unknown experiment.
    assert cli.main(["report", "does-not-exist-xyz"]) == 1


def test_pipeline_writes_dashboard_in_range_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    out = cli.run_pipeline(kind="readiness", make_dashboard=True)
    assert out["dashboard"] is not None
    with open(out["dashboard"], encoding="utf-8") as f:
        assert "</html>" in f.read()
