"""Tests for record/replay of model runs (src/range/llm_io.py).

Recording a (fake) model run and replaying it must reproduce the same actions
and token usage, deterministically and without the original client.
"""
import pytest

from src.range.agents import LLMPolicy, Observation
from src.range.llm_io import (
    RecordingClient, ReplayClient, load_recording, save_recording,
)


# A fake "real" client returning a scripted sequence of actions + usage.
class _InnerMessages:
    def __init__(self, actions, usage):
        self._actions = actions
        self._usage = usage
        self._i = 0

    def create(self, **kwargs):
        a = self._actions[min(self._i, len(self._actions) - 1)]
        self._i += 1
        block = type("B", (), {"type": "tool_use", "input": dict(a),
                               "id": "tu"})()
        usage = None
        if self._usage:
            usage = type("U", (), {"input_tokens": self._usage[0],
                                   "output_tokens": self._usage[1]})()
        return type("R", (), {"content": [block], "usage": usage})()


class _Inner:
    def __init__(self, actions, usage=None):
        self.messages = _InnerMessages(actions, usage)


def _obs(rnd):
    return Observation(round=rnd, actor="attacker-1", role="attacker", goal="g",
                       balance=0, banned=False, flags_against_me=0, listings=[],
                       trust={}, recent_events=[])


def test_record_then_replay_reproduces_actions_and_usage(tmp_path):
    inner = _Inner([{"kind": "attack", "params": {"technique": "phishing"}},
                    {"kind": "idle"}], usage=(7, 2))
    rec = RecordingClient(inner)
    pol = LLMPolicy("attacker", "g", client=rec)
    first = pol.decide(_obs(1))
    second = pol.decide(_obs(2))
    assert first.kind == "attack" and second.kind == "idle"
    assert len(rec.records) == 2

    # Round-trip the recording through disk.
    path = str(tmp_path / "run.json")
    save_recording(rec, path)
    records = load_recording(path)

    # Replay reproduces the same actions, with no original client.
    replay_pol = LLMPolicy("attacker", "g", client=ReplayClient(records))
    assert replay_pol.decide(_obs(1)).kind == "attack"
    assert replay_pol.decide(_obs(2)).kind == "idle"
    # Usage is replayed too.
    assert replay_pol.usage["input_tokens"] == 14   # 7 * 2
    assert replay_pol.usage["output_tokens"] == 4    # 2 * 2


def test_replay_is_deterministic():
    inner = _Inner([{"kind": "attack", "params": {"technique": "x"}}])
    rec = RecordingClient(inner)
    LLMPolicy("a", "g", client=rec).decide(_obs(1))

    def run():
        p = LLMPolicy("a", "g", client=ReplayClient(rec.records))
        return p.decide(_obs(1)).kind
    assert run() == run() == "attack"


def test_replay_exhaustion_raises():
    pol = LLMPolicy("a", "g", client=ReplayClient([]))
    with pytest.raises(IndexError):
        pol.decide(_obs(1))


def test_rationale_survives_record_replay():
    inner = _Inner([{"kind": "attack", "params": {}, "rationale": "scope it"}])
    rec = RecordingClient(inner)
    LLMPolicy("a", "g", client=rec).decide(_obs(1))
    replay_pol = LLMPolicy("a", "g", client=ReplayClient(rec.records))
    assert replay_pol.decide(_obs(1)).rationale == "scope it"
