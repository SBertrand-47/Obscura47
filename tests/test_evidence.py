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


# A minimal anthropic-shaped double with token usage.
class _Usage:
    def __init__(self, i, o):
        self.input_tokens = i
        self.output_tokens = o


class _Block:
    def __init__(self, data):
        self.type = "tool_use"
        self.input = data
        self.id = "tu"


class _Resp:
    def __init__(self, blocks, usage):
        self.content = blocks
        self.usage = usage


class _Msgs:
    def __init__(self, a, u):
        self._a, self._u = a, u

    def create(self, **kw):
        return _Resp([_Block(dict(self._a))], self._u)


class _Client:
    def __init__(self, a, u):
        self.messages = _Msgs(a, u)


def test_evidence_includes_llm_cost(rng):
    from src.range.agents import (
        LLMPolicy, ScriptedPolicy, default_cast, run_world)
    client = _Client({"kind": "attack",
                      "params": {"technique": "phishing", "target": "seller-1"}},
                     _Usage(9, 3))
    cast = default_cast(lambda role, goal:
                        LLMPolicy(role, goal, client=client)
                        if role == "attacker" else ScriptedPolicy())
    run_world(cast, rounds=2, experiment_id="ev-cost", trace_decisions=True)
    bundle = evidence.build_evidence("ev-cost")
    assert bundle["llm_cost"]["calls"] == 2     # one LLM call per round
    assert bundle["llm_cost"]["input_tokens"] == 18
    assert bundle["llm_cost"]["output_tokens"] == 6
    assert "## Model cost" in evidence.render_markdown(bundle)


def test_evidence_includes_incidents_summary(rng):
    run_scenario(seed=47, experiment_id="ev-inc")
    bundle = evidence.build_evidence("ev-inc")
    # The readiness attacker is a contained suspect.
    assert bundle["incidents"]["suspects"] >= 1
    assert "## Incidents" in evidence.render_markdown(bundle)


def test_scripted_run_has_zero_llm_cost(rng):
    run_scenario(seed=47, experiment_id="ev-scripted")
    bundle = evidence.build_evidence("ev-scripted")
    assert bundle["llm_cost"]["calls"] == 0
    # No model-cost section when there was no model.
    assert "## Model cost" not in evidence.render_markdown(bundle)
