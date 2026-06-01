"""Record and replay LLM responses for reproducible real-model runs.

A run driven by a real model is stochastic, so it cannot be reproduced or
regression-tested. These two clients fix that, both drop-in for ``LLMPolicy``'s
``client``:

* :class:`RecordingClient` wraps a real Messages client and captures each
  response (the chosen action + token usage) as it streams by.
* :class:`ReplayClient` replays a saved recording in order -- deterministic, no
  API call, no key.

So you run a real-model experiment once with a RecordingClient, save the
recording, and from then on replay the *exact* run deterministically: a
stochastic agent session becomes a reproducible fixture you can replay, share,
and put in CI. This is the "replayability" pillar applied to the model itself,
not just the network telemetry.
"""

from __future__ import annotations

import json
from typing import Any


# Minimal response shapes matching what LLMPolicy.decide reads.
class _Block:
    def __init__(self, data: dict, block_id: str | None = None):
        self.type = "tool_use"
        self.input = data
        self.id = block_id


class _Usage:
    def __init__(self, input_tokens: int, output_tokens: int):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _Resp:
    def __init__(self, content: list, usage: _Usage | None = None):
        self.content = content
        self.usage = usage


def _snapshot(resp: Any) -> dict:
    """Capture the replay-relevant parts of a model response."""
    blocks = []
    for b in getattr(resp, "content", []) or []:
        if getattr(b, "type", None) == "tool_use":
            blocks.append({"input": dict(b.input or {}),
                           "id": getattr(b, "id", None)})
    usage = None
    u = getattr(resp, "usage", None)
    if u is not None:
        usage = {"input_tokens": int(getattr(u, "input_tokens", 0) or 0),
                 "output_tokens": int(getattr(u, "output_tokens", 0) or 0)}
    return {"blocks": blocks, "usage": usage}


def _rebuild(record: dict) -> _Resp:
    blocks = [_Block(b.get("input") or {}, b.get("id"))
              for b in record.get("blocks", [])]
    u = record.get("usage")
    usage = _Usage(u["input_tokens"], u["output_tokens"]) if u else None
    return _Resp(blocks, usage)


class _RecordingMessages:
    def __init__(self, inner, sink: list):
        self._inner = inner
        self._sink = sink

    def create(self, **kwargs):
        resp = self._inner.create(**kwargs)
        self._sink.append(_snapshot(resp))
        return resp


class RecordingClient:
    """Wraps a real Messages client, capturing each response for later replay."""

    def __init__(self, inner):
        self.records: list[dict] = []
        self.messages = _RecordingMessages(inner.messages, self.records)


class _ReplayMessages:
    def __init__(self, records: list[dict]):
        self._records = list(records)
        self._i = 0

    def create(self, **kwargs):
        if self._i >= len(self._records):
            raise IndexError(
                "replay exhausted: the run made more model calls than were "
                "recorded (different rounds/cast than the recording?)")
        record = self._records[self._i]
        self._i += 1
        return _rebuild(record)


class ReplayClient:
    """Replays a recording in order. Deterministic, no API, no key."""

    def __init__(self, records: list[dict]):
        self.messages = _ReplayMessages(records)


def save_recording(client: RecordingClient, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(client.records, f, indent=2)


def load_recording(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
