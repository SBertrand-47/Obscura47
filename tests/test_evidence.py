"""Tests for the evidence-package export (src/range/evidence.py)."""
import json

import pytest

from src.range import evidence
from src.range.scenario import run_scenario
from src.utils import config, experiment


@pytest.fixture
def rng(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setattr(experiment, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(experiment, "_current_id", None)
    monkeypatch.setattr(experiment, "_env_resolved", False)
    monkeypatch.delenv("OBSCURA_EXPERIMENT_ID", raising=False)


def test_bundle_has_verdict_config_and_reproduce(rng):
    run_scenario(seed=47, experiment_id="ev-1")
    bundle = evidence.build_evidence("ev-1")
    assert bundle["verdict"] == "contained"
    assert bundle["scenario"] == "readiness_gate"
    assert bundle["seed"] == 47
    assert bundle["config"]["code_commit_sha"]  # provenance present
    # Reproduce command targets the right scenario kind.
    assert "run --kind readiness" in bundle["reproduce"]


def test_bundle_is_json_serializable(rng):
    run_scenario(seed=47, experiment_id="ev-2")
    json.dumps(evidence.build_evidence("ev-2"), default=str)  # must not raise


def test_markdown_has_all_sections(rng):
    run_scenario(seed=47, experiment_id="ev-3")
    md = evidence.render_markdown(evidence.build_evidence("ev-3"))
    for section in ("# Obscura47 Range Evaluation", "## Scores",
                    "## Adversarial activity", "## Findings",
                    "## Reproducibility"):
        assert section in md
    assert "Verdict:** **contained**" in md
    assert "run --kind readiness" in md


def test_cli_writes_both_files(rng, tmp_path):
    run_scenario(seed=47, experiment_id="ev-4")
    md, js = str(tmp_path / "r.md"), str(tmp_path / "r.json")
    assert evidence.main(["ev-4", "--md", md, "--json", js]) == 0
    with open(md, encoding="utf-8") as f:
        assert "Range Evaluation" in f.read()
    with open(js, encoding="utf-8") as f:
        assert json.load(f)["verdict"] == "contained"


def test_cli_unknown_experiment_exits_1(rng):
    assert evidence.main(["does-not-exist"]) == 1
