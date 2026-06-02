"""Tests for the LLM policy integration path (src/range/agents.py::LLMPolicy).

The real-model code path -- the messages.create call and tool_use parsing --
is exercised end to end against a fake client, so the integration is verified
before any API key is present. No network, fully deterministic.
"""
import pytest

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
        self.id = "tu_test"


class _Usage:
    def __init__(self, input_tokens, output_tokens):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _Resp:
    def __init__(self, blocks, usage=None):
        self.content = blocks
        self.usage = usage


class _FakeMessages:
    def __init__(self, action_input, usage=None):
        self._action = action_input
        self._usage = usage
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _Resp([_ToolUseBlock(dict(self._action))], self._usage)


class _FakeClient:
    def __init__(self, action_input, usage=None):
        self.messages = _FakeMessages(action_input, usage)


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
    assert call["tool_choice"] == {"type": "tool", "name": "take_action",
                                   "disable_parallel_tool_use": True}
    assert call["tools"][0]["name"] == "take_action"
    # Static system prompt is marked for prompt caching.
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    # The observation is passed as the user message.
    assert call["messages"][0]["role"] == "user"


def test_conversation_memory_accumulates_and_threads_tool_results():
    fake = _FakeClient({"kind": "idle"})
    policy = LLMPolicy("attacker", "g", client=fake)
    policy.decide(_obs(round=1))
    policy.decide(_obs(round=2))
    # The second call carries the prior conversation -- the agent has memory.
    msgs = fake.messages.calls[1]["messages"]
    assert len(msgs) == 3  # user(1), assistant(1), user(2)
    assert msgs[0]["role"] == "user" and msgs[1]["role"] == "assistant"
    # The new user turn closes the previous action's tool-use loop.
    assert any(isinstance(c, dict) and c.get("type") == "tool_result"
               for c in msgs[2]["content"])


def test_parallel_tool_use_is_fully_answered_next_turn():
    # A model may emit more than one tool_use block in a turn (Opus did this in
    # the multi-agent casts). Every tool_use must get a tool_result next turn,
    # or the API rejects the conversation. Act on the first; answer all.
    client = _FakeClient({"kind": "idle"})
    blocks = [_ToolUseBlock({"kind": "attack",
                             "params": {"technique": "phishing",
                                        "target": "seller-1"}}),
              _ToolUseBlock({"kind": "idle"})]
    blocks[0].id, blocks[1].id = "tu_a", "tu_b"
    client.messages.create = lambda **kw: _Resp(blocks)
    policy = LLMPolicy("attacker", "g", client=client)
    action = policy.decide(_obs(round=1))
    assert action.kind == "attack"          # acts on the first tool call
    # Next turn must carry a tool_result for BOTH tool_use ids.
    policy_calls = []
    client.messages.create = lambda **kw: policy_calls.append(kw) or _Resp(
        [_ToolUseBlock({"kind": "idle"})])
    policy.decide(_obs(round=2))
    results = [c for c in policy_calls[0]["messages"][-1]["content"]
               if isinstance(c, dict) and c.get("type") == "tool_result"]
    assert {r["tool_use_id"] for r in results} == {"tu_a", "tu_b"}


def test_token_usage_is_accumulated():
    fake = _FakeClient({"kind": "idle"}, usage=_Usage(10, 5))
    policy = LLMPolicy("attacker", "g", client=fake)
    policy.decide(_obs(round=1))
    policy.decide(_obs(round=2))
    assert policy.usage == {"calls": 2, "input_tokens": 20, "output_tokens": 10}
    assert policy.last_usage == {"input_tokens": 10, "output_tokens": 5}


def test_total_llm_usage_sums_across_cast(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    fake = _FakeClient({"kind": "attack",
                        "params": {"technique": "phishing",
                                   "target": "seller-1"}},
                       usage=_Usage(8, 4))

    def factory(role, goal):
        return (LLMPolicy(role, goal, client=fake) if role == "attacker"
                else ScriptedPolicy())

    cast = default_cast(factory)
    run_world(cast, rounds=3)
    from src.range.agents import total_llm_usage
    usage = total_llm_usage(cast)
    assert usage["llm_agents"] == 1
    assert usage["calls"] == 3            # one LLM call per round
    assert usage["input_tokens"] == 24    # 8 * 3
    assert usage["output_tokens"] == 12   # 4 * 3


def test_unknown_block_falls_back_to_idle():
    class _NoTool:
        type = "text"
    client = _FakeClient({"kind": "attack"})
    client.messages.create = lambda **kw: _Resp([_NoTool()])
    policy = LLMPolicy("attacker", "g", client=client)
    assert policy.decide(_obs()).kind == "idle"


def test_anthropic_api_error_is_wrapped_cleanly():
    # A billing/rate/auth failure from the SDK must surface as a RuntimeError
    # (which the CLI reports cleanly), not a raw traceback.
    class _BadRequestError(Exception):
        __module__ = "anthropic"

    client = _FakeClient({"kind": "idle"})
    def _boom(**kw):
        raise _BadRequestError("credit balance is too low")
    client.messages.create = _boom
    policy = LLMPolicy("attacker", "g", client=client)
    with pytest.raises(RuntimeError, match="model call failed"):
        policy.decide(_obs())


def test_non_anthropic_error_propagates_untouched():
    # A real bug (not an SDK error) must not be masked as a RuntimeError.
    client = _FakeClient({"kind": "idle"})
    def _boom(**kw):
        raise KeyError("a real bug")
    client.messages.create = _boom
    policy = LLMPolicy("attacker", "g", client=client)
    with pytest.raises(KeyError):
        policy.decide(_obs())


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
