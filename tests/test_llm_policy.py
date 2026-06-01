"""Tests for the LLM policy integration path (src/range/agents.py::LLMPolicy).

The real-model code path -- the messages.create call and tool_use parsing --
is exercised end to end against a fake client, so the integration is verified
before any API key is present. No network, fully deterministic.
"""
from src.range.agents import (
    LLMPolicy, Observation, ScriptedPolicy, default_cast, run_world,
)
from src.range.evaluate import build_evaluation
from src.utils import config


# ── A minimal anthropic-shaped test double ────────────────────────

class _ToolUseBlock:
    def __init__(self, data):
        self.type = "tool_use"
        self.input = data


class _Resp:
    def __init__(self, blocks):
        self.content = blocks


class _FakeMessages:
    def __init__(self, action_input):
        self._action = action_input
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _Resp([_ToolUseBlock(dict(self._action))])


class _FakeClient:
    def __init__(self, action_input):
        self.messages = _FakeMessages(action_input)


def _obs(**kw):
    base = dict(round=1, actor="attacker-1", role="attacker", goal="g",
                balance=0, banned=False, flags_against_me=0, listings=[],
                trust={}, recent_events=[])
    base.update(kw)
    return Observation(**base)


def test_decide_parses_tool_use_into_action():
    client = _FakeClient({"kind": "attack",
                          "params": {"technique": "phishing",
                                     "target": "seller-1"}})
    policy = LLMPolicy("attacker", "extract value", client=client)
    action = policy.decide(_obs())
    assert action.kind == "attack"
    assert action.params["technique"] == "phishing"


def test_decide_call_shape_forces_the_tool_and_caches_system():
    client = _FakeClient({"kind": "idle"})
    policy = LLMPolicy("attacker", "g", client=client, model="claude-x")
    policy.decide(_obs())
    call = client.messages.calls[0]
    assert call["model"] == "claude-x"
    assert call["tool_choice"] == {"type": "tool", "name": "take_action"}
    assert call["tools"][0]["name"] == "take_action"
    # Static system prompt is marked for prompt caching.
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    # The observation is passed as the user message.
    assert call["messages"][0]["role"] == "user"


def test_unknown_block_falls_back_to_idle():
    class _NoTool:
        type = "text"
    client = _FakeClient({"kind": "attack"})
    client.messages.create = lambda **kw: _Resp([_NoTool()])
    policy = LLMPolicy("attacker", "g", client=client)
    assert policy.decide(_obs()).kind == "idle"


def test_llm_attacker_drives_a_real_world_run(monkeypatch):
    # The full loop: engine builds an Observation, LLMPolicy.decide calls the
    # (fake) model, the tool_use is parsed into an Action, and the engine emits
    # real research telemetry from it.
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)

    def factory(role, goal):
        if role == "attacker":
            return LLMPolicy(role, goal, client=_FakeClient(
                {"kind": "attack",
                 "params": {"technique": "phishing", "target": "seller-1"}}))
        return ScriptedPolicy()

    result = run_world(default_cast(factory), rounds=3)
    events = list(reversed(result.collector.query(limit=10_000)))
    report = build_evaluation(events)
    assert report["adversarial"]["attacks"] >= 1
    # The attack came from the LLM-driven attacker.
    assert any(e.kind == "attack.attempt" and e.actor == "attacker-1"
               for e in events)


def test_llm_rationale_appears_in_decision_trace(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    from src.range.agents import decision_trace
    fake = _FakeClient({"kind": "attack",
                        "params": {"technique": "phishing",
                                   "target": "seller-1"},
                        "rationale": "probe the seller for weakness"})

    def factory(role, goal):
        return (LLMPolicy(role, goal, client=fake) if role == "attacker"
                else ScriptedPolicy())

    result = run_world(default_cast(factory), rounds=2, trace_decisions=True)
    attacker = [d for d in decision_trace(result)
                if d["actor"] == "attacker-1"]
    assert attacker and attacker[0]["rationale"] == "probe the seller for weakness"
