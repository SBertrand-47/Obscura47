"""Unit tests for the observability primitives and tool surface."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

import pytest

from src.agent.app import AgentApp, Request, Response
from src.agent.client import AgentClient
from src.agent.ledger import LedgerState, build_ledger_app
from src.agent.observatory import (
    DEFAULT_BUFFER_SIZE,
    KIND_DIAL_OUT,
    KIND_DIAL_RESULT,
    KIND_REQUEST_IN,
    KIND_RESPONSE_OUT,
    KIND_TOOL_ERROR,
    KIND_TOOL_INVOKE,
    KIND_TOOL_RESULT,
    KIND_TX_COMMIT,
    MAX_EVENTS_PER_INGEST,
    OBSERVATORY_PROTOCOL_VERSION,
    QUERY_DEFAULT_LIMIT,
    QUERY_MAX_LIMIT,
    Event,
    JsonlSink,
    MemorySink,
    MultiSink,
    NullSink,
    ObservatoryState,
    Observer,
    build_observatory_app,
    build_observer_from_flags,
    new_session_id,
)
from src.agent.tools import DEFAULT_PREFIX, ToolError, ToolRegistry


def _request_with_caller(
    method: str,
    path: str,
    body: bytes = b"",
    caller_fingerprint: str | None = None,
) -> Request:
    req = Request(method, path, {}, body)
    if caller_fingerprint is not None:
        req._caller_fingerprint = caller_fingerprint  # type: ignore[attr-defined]
    return req


# ---------------------------------------------------------------------------
# Event schema
# ---------------------------------------------------------------------------


def test_event_to_dict_round_trips_through_from_dict():
    e = Event(
        event_id="abcdef",
        ts=1234567890.5,
        actor="my-agent",
        kind=KIND_TOOL_INVOKE,
        session_id="sess",
        payload={"tool": "ping"},
    )
    raw = e.to_dict()
    e2 = Event.from_dict(raw)
    assert e2.event_id == e.event_id
    assert e2.ts == e.ts
    assert e2.actor == e.actor
    assert e2.kind == e.kind
    assert e2.session_id == e.session_id
    assert e2.payload == e.payload


def test_event_from_dict_requires_actor_and_kind():
    with pytest.raises(ValueError):
        Event.from_dict({"kind": "x"})
    with pytest.raises(ValueError):
        Event.from_dict({"actor": "x"})


def test_event_from_dict_payload_must_be_object():
    with pytest.raises(ValueError):
        Event.from_dict({"actor": "a", "kind": "k", "payload": "not-an-object"})


def test_event_from_dict_truncates_long_payload_values():
    big = "x" * 100_000
    e = Event.from_dict({"actor": "a", "kind": "k", "payload": {"v": big}})
    assert len(e.payload["v"]) < len(big)
    assert e.payload["v"].endswith("...")


def test_event_from_dict_drops_keys_past_limit():
    payload = {f"k{i}": i for i in range(200)}
    e = Event.from_dict({"actor": "a", "kind": "k", "payload": payload})
    assert len(e.payload) <= 64


def test_event_from_dict_coerces_non_serialisable_via_repr():
    class Weird:
        def __repr__(self):
            return "<Weird>"

    e = Event.from_dict({"actor": "a", "kind": "k", "payload": {"v": Weird()}})
    assert "<Weird>" in str(e.payload["v"])


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


def test_null_sink_swallows_events():
    s = NullSink()
    s.write(Event("id", 0.0, "a", "k"))
    s.close()  # no-op


def test_memory_sink_buffers_and_caps():
    s = MemorySink(maxsize=3)
    for i in range(5):
        s.write(Event(f"id{i}", float(i), "a", "k"))
    rows = s.events()
    assert len(rows) == 3
    assert [r.event_id for r in rows] == ["id2", "id3", "id4"]
    s.clear()
    assert s.events() == []


def test_jsonl_sink_appends_records(tmp_path):
    path = str(tmp_path / "events.jsonl")
    s = JsonlSink(path, rotate_bytes=None)
    s.write(Event("e1", 1.0, "actor", KIND_TOOL_INVOKE, payload={"x": 1}))
    s.write(Event("e2", 2.0, "actor", KIND_TOOL_RESULT))
    with open(path, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    assert len(lines) == 2
    assert lines[0]["event_id"] == "e1"
    assert lines[1]["event_id"] == "e2"
    assert lines[0]["payload"]["x"] == 1


def test_jsonl_sink_creates_parent_dirs(tmp_path):
    path = str(tmp_path / "nested" / "dir" / "events.jsonl")
    s = JsonlSink(path, rotate_bytes=None)
    s.write(Event("e1", 1.0, "a", "k"))
    assert os.path.isfile(path)


def test_jsonl_sink_rotates_when_threshold_exceeded(tmp_path):
    path = str(tmp_path / "events.jsonl")
    s = JsonlSink(path, rotate_bytes=64)
    for i in range(20):
        s.write(Event(f"e{i}", float(i), "actor", "k", payload={"i": i}))
    rotated = [p for p in os.listdir(tmp_path) if p.startswith("events.jsonl.")]
    assert rotated, "no rotated file produced"


def test_multi_sink_fans_out_and_isolates_failures():
    good = MemorySink()

    class Bad:
        def write(self, event):
            raise RuntimeError("nope")

        def close(self):
            return

    multi = MultiSink([Bad(), good, Bad()])
    multi.write(Event("e", 1.0, "a", "k"))
    assert len(good.events()) == 1


# ---------------------------------------------------------------------------
# Observer
# ---------------------------------------------------------------------------


def test_observer_emit_records_event_with_actor_and_payload():
    sink = MemorySink()
    obs = Observer(actor="my-agent", sink=sink)
    obs.emit(KIND_TOOL_INVOKE, session_id="sess1", tool="ping", caller="cli")
    [event] = sink.events()
    assert event.actor == "my-agent"
    assert event.kind == KIND_TOOL_INVOKE
    assert event.session_id == "sess1"
    assert event.payload == {"tool": "ping", "caller": "cli"}


def test_observer_rejects_blank_actor():
    with pytest.raises(ValueError):
        Observer(actor="")


def test_observer_rejects_blank_kind():
    obs = Observer(actor="a", sink=NullSink())
    with pytest.raises(ValueError):
        obs.emit("")


def test_observer_swallows_sink_exceptions():
    class Boom:
        def write(self, event):
            raise RuntimeError("boom")

        def close(self):
            return

    obs = Observer(actor="a", sink=Boom())
    obs.emit("k", v=1)


def test_new_session_id_is_short_and_unique():
    a = new_session_id()
    b = new_session_id()
    assert a != b
    assert len(a) == 16


# ---------------------------------------------------------------------------
# ObservatoryState
# ---------------------------------------------------------------------------


def test_state_append_and_query_returns_newest_first():
    state = ObservatoryState()
    for i in range(5):
        state.append(Event(f"e{i}", float(i), "actor", KIND_TOOL_INVOKE))
    rows = state.query()
    assert [r.event_id for r in rows] == ["e4", "e3", "e2", "e1", "e0"]


def test_state_query_filters_by_kind_and_actor():
    state = ObservatoryState()
    state.append(Event("a", 1.0, "alice", KIND_TOOL_INVOKE))
    state.append(Event("b", 2.0, "bob", KIND_TOOL_INVOKE))
    state.append(Event("c", 3.0, "alice", KIND_RESPONSE_OUT))

    by_actor = state.query(actor="alice")
    assert {r.event_id for r in by_actor} == {"a", "c"}

    by_kind = state.query(kind=KIND_TOOL_INVOKE)
    assert {r.event_id for r in by_kind} == {"a", "b"}

    both = state.query(kind=KIND_TOOL_INVOKE, actor="alice")
    assert [r.event_id for r in both] == ["a"]


def test_state_query_filters_by_time_range():
    state = ObservatoryState()
    state.append(Event("a", 100.0, "actor", "k"))
    state.append(Event("b", 200.0, "actor", "k"))
    state.append(Event("c", 300.0, "actor", "k"))

    rows = state.query(since=150.0, until=250.0)
    assert [r.event_id for r in rows] == ["b"]


def test_state_query_filters_by_session_and_submitted_by():
    state = ObservatoryState()
    state.append(Event("a", 1.0, "actor", "k", session_id="s1", submitted_by="caller-1"))
    state.append(Event("b", 2.0, "actor", "k", session_id="s2", submitted_by="caller-2"))
    state.append(Event("c", 3.0, "actor", "k", session_id="s1", submitted_by="caller-2"))

    rows = state.query(session_id="s1")
    assert {r.event_id for r in rows} == {"a", "c"}

    rows = state.query(submitted_by="caller-2")
    assert {r.event_id for r in rows} == {"b", "c"}

    rows = state.query(session_id="s1", submitted_by="caller-2")
    assert {r.event_id for r in rows} == {"c"}


def test_state_query_limit_is_clamped_and_validated():
    state = ObservatoryState()
    for i in range(50):
        state.append(Event(f"e{i}", float(i), "actor", "k"))
    rows = state.query(limit=10)
    assert len(rows) == 10
    rows = state.query(limit=QUERY_MAX_LIMIT * 5)
    assert len(rows) == 50

    with pytest.raises(ToolError):
        state.query(limit=0)
    with pytest.raises(ToolError):
        state.query(limit=-1)
    with pytest.raises(ToolError):
        state.query(limit=True)  # type: ignore[arg-type]


def test_state_buffer_drops_oldest_when_full():
    state = ObservatoryState(maxsize=3)
    for i in range(10):
        state.append(Event(f"e{i}", float(i), "actor", "k"))
    rows = state.query()
    assert [r.event_id for r in rows] == ["e9", "e8", "e7"]


def test_state_stats_breakdowns():
    state = ObservatoryState()
    state.append(Event("a", 1.0, "alice", KIND_TOOL_INVOKE))
    state.append(Event("b", 2.0, "alice", KIND_TOOL_RESULT))
    state.append(Event("c", 3.0, "bob", KIND_TOOL_INVOKE))
    stats = state.stats()
    assert stats["accepted"] == 3
    assert stats["by_kind"][KIND_TOOL_INVOKE] == 2
    assert stats["by_actor"]["alice"] == 2
    assert stats["by_actor"]["bob"] == 1


def test_state_clear_resets_buffer_and_counters():
    state = ObservatoryState()
    state.append(Event("a", 1.0, "x", "k"))
    state.reject()
    state.clear()
    stats = state.stats()
    assert stats["accepted"] == 0
    assert stats["rejected"] == 0
    assert stats["buffered"] == 0


# ---------------------------------------------------------------------------
# build_observatory_app — wire-shape tests
# ---------------------------------------------------------------------------


def test_root_route_advertises_protocol():
    state = ObservatoryState()
    app, _ = build_observatory_app(state)
    resp = app.dispatch(_request_with_caller("GET", "/"))
    body = json.loads(resp.body)
    assert body["service"] == "observatory"
    assert body["protocol"] == OBSERVATORY_PROTOCOL_VERSION
    assert "/health" in body["endpoints"]


def test_health_route_includes_stats():
    state = ObservatoryState()
    app, _ = build_observatory_app(state)
    resp = app.dispatch(_request_with_caller("GET", "/health"))
    body = json.loads(resp.body)
    assert body["ok"] is True
    assert body["accepted"] == 0


def test_ingest_tool_records_events_and_stamps_submitted_by():
    state = ObservatoryState()
    _, tools = build_observatory_app(state)
    req = _request_with_caller("POST", "/x", caller_fingerprint="ca" * 32)
    events = [
        {"actor": "ledger", "kind": KIND_TX_COMMIT, "payload": {"amount": 5}},
        {"actor": "ledger", "kind": KIND_TX_COMMIT, "payload": {"amount": 7}},
    ]
    resp = tools.invoke("ingest", {"events": events}, req)
    body = json.loads(resp.body)
    assert body["ok"] is True
    assert body["result"] == {"accepted": 2, "rejected": 0}
    rows = state.query()
    assert {e.payload.get("amount") for e in rows} == {5, 7}
    for e in rows:
        assert e.submitted_by == "ca" * 32


def test_ingest_tool_rejects_malformed_events_individually():
    state = ObservatoryState()
    _, tools = build_observatory_app(state)
    req = _request_with_caller("POST", "/x")
    events = [
        {"actor": "a", "kind": "k", "payload": {}},
        {"kind": "missing-actor"},
        "not-an-object",
    ]
    resp = tools.invoke("ingest", {"events": events}, req)
    body = json.loads(resp.body)
    assert body["result"] == {"accepted": 1, "rejected": 2}


def test_ingest_tool_caps_batch_size():
    state = ObservatoryState()
    _, tools = build_observatory_app(state)
    req = _request_with_caller("POST", "/x")
    events = [{"actor": "a", "kind": "k"}] * (MAX_EVENTS_PER_INGEST + 1)
    resp = tools.invoke("ingest", {"events": events}, req)
    body = json.loads(resp.body)
    assert body["ok"] is False
    assert body["error"]["code"] == "too_many_events"


def test_ingest_tool_publishes_to_topic():
    state = ObservatoryState()
    _, tools = build_observatory_app(state)
    sub = tools.topic("events").subscribe()
    req = _request_with_caller("POST", "/x")
    tools.invoke(
        "ingest",
        {"events": [{"actor": "a", "kind": "k", "payload": {"x": 1}}]},
        req,
    )
    fan_out = sub.get_nowait()
    assert fan_out["actor"] == "a"
    assert fan_out["kind"] == "k"


def test_query_tool_round_trips_filters():
    state = ObservatoryState()
    state.append(Event("a", 1.0, "alice", KIND_TOOL_INVOKE))
    state.append(Event("b", 2.0, "bob", KIND_TOOL_INVOKE))
    _, tools = build_observatory_app(state)

    req = _request_with_caller("POST", "/x")
    resp = tools.invoke("query", {"actor": "alice"}, req)
    rows = json.loads(resp.body)["result"]
    assert [r["event_id"] for r in rows] == ["a"]


def test_query_tool_default_limit_when_omitted():
    state = ObservatoryState()
    for i in range(QUERY_DEFAULT_LIMIT * 3):
        state.append(Event(f"e{i}", float(i), "x", "k"))
    _, tools = build_observatory_app(state)
    req = _request_with_caller("POST", "/x")
    resp = tools.invoke("query", {}, req)
    rows = json.loads(resp.body)["result"]
    assert len(rows) == QUERY_DEFAULT_LIMIT


def test_stats_tool_returns_counters():
    state = ObservatoryState()
    state.append(Event("a", 1.0, "x", "k"))
    _, tools = build_observatory_app(state)
    req = _request_with_caller("POST", "/x")
    resp = tools.invoke("stats", {}, req)
    body = json.loads(resp.body)
    assert body["ok"] is True
    assert body["result"]["accepted"] == 1


def test_build_observatory_app_mounts_tool_routes():
    state = ObservatoryState()
    app, _ = build_observatory_app(state)
    resp = app.dispatch(_request_with_caller("GET", DEFAULT_PREFIX + "tools"))
    body = json.loads(resp.body)
    names = [t["name"] for t in body["tools"]]
    assert {"ingest", "query", "stats"}.issubset(set(names))
    assert "events" in body["topics"]


# ---------------------------------------------------------------------------
# AgentApp / ToolRegistry instrumentation
# ---------------------------------------------------------------------------


def test_agent_app_emits_request_and_response_events():
    sink = MemorySink()
    obs = Observer(actor="agent-a", sink=sink)
    app = AgentApp()
    app.observer = obs

    @app.get("/echo")
    def _echo(_req: Request) -> Response:
        return Response(200, {"ok": True})

    resp = app.dispatch(_request_with_caller("GET", "/echo"))
    assert resp.status == 200

    kinds = [e.kind for e in sink.events()]
    assert kinds[0] == KIND_REQUEST_IN
    assert kinds[-1] == KIND_RESPONSE_OUT
    last = sink.events()[-1]
    assert last.payload["status"] == 200
    assert last.payload["path"] == "/echo"
    assert "latency_ms" in last.payload


def test_agent_app_assigns_session_id_when_observer_set():
    sink = MemorySink()
    obs = Observer(actor="agent-a", sink=sink)
    app = AgentApp()
    app.observer = obs

    @app.get("/x")
    def _x(_req: Request) -> Response:
        return Response(200, {})

    app.dispatch(_request_with_caller("GET", "/x"))
    sessions = {e.session_id for e in sink.events()}
    assert len(sessions) == 1
    assert next(iter(sessions))


def test_agent_app_respects_inbound_session_header():
    sink = MemorySink()
    obs = Observer(actor="agent-a", sink=sink)
    app = AgentApp()
    app.observer = obs

    @app.get("/x")
    def _x(_req: Request) -> Response:
        return Response(200, {})

    req = Request("GET", "/x", {"X-Obscura-Session": "trace-123"}, b"")
    app.dispatch(req)
    for e in sink.events():
        assert e.session_id == "trace-123"


def test_tool_registry_emits_invoke_and_result_events_through_dispatch():
    sink = MemorySink()
    obs = Observer(actor="agent-a", sink=sink)
    app = AgentApp()
    app.observer = obs
    tools = ToolRegistry()
    tools.observer = obs

    @tools.tool("ping", description="ping", returns="object")
    def _ping(args, req):
        return {"v": 1}

    tools.mount(app)

    body = json.dumps({"args": {}}).encode()
    req = Request("POST", DEFAULT_PREFIX + "tools/ping", {}, body)
    resp = app.dispatch(req)
    assert resp.status == 200

    kinds = [e.kind for e in sink.events()]
    assert KIND_REQUEST_IN in kinds
    assert KIND_TOOL_INVOKE in kinds
    assert KIND_TOOL_RESULT in kinds
    assert KIND_RESPONSE_OUT in kinds
    sessions = {e.session_id for e in sink.events()}
    assert len(sessions) == 1


def test_tool_registry_emits_error_event_on_tool_failure():
    sink = MemorySink()
    obs = Observer(actor="agent-a", sink=sink)
    tools = ToolRegistry()
    tools.observer = obs

    @tools.tool("boom", returns="object")
    def _boom(args, req):
        raise ToolError("nope", "explicit failure", status=400)

    req = Request("POST", "/x", {}, b"")
    resp = tools.invoke("boom", {}, req)
    assert resp.status == 400

    error_events = [e for e in sink.events() if e.kind == KIND_TOOL_ERROR]
    assert len(error_events) == 1
    assert error_events[0].payload["code"] == "nope"
    assert error_events[0].payload["status"] == 400


def test_tool_registry_emits_error_for_unknown_tool():
    sink = MemorySink()
    obs = Observer(actor="agent-a", sink=sink)
    tools = ToolRegistry()
    tools.observer = obs

    req = Request("POST", "/x", {}, b"")
    resp = tools.invoke("missing", {}, req)
    assert resp.status == 404

    [error] = [e for e in sink.events() if e.kind == KIND_TOOL_ERROR]
    assert error.payload["code"] == "not_found"


# ---------------------------------------------------------------------------
# AgentClient instrumentation (stub the socket layer)
# ---------------------------------------------------------------------------


class _FakeSocket:
    def __init__(self, response: bytes):
        self._response = response
        self._buf = b""
        self._pos = 0
        self.sent: list[bytes] = []
        self.closed = False

    def settimeout(self, _t: float) -> None:
        return

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int) -> bytes:
        if self._pos >= len(self._response):
            return b""
        chunk = self._response[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


def _fake_response(status: int = 200, body: bytes = b'{"ok": true, "result": {}}') -> bytes:
    ack = b"HTTP/1.1 200 OK\r\n\r\n"
    head = (
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode("ascii")
    return ack + head + body


def test_agent_client_emits_dial_events(monkeypatch):
    fake = _FakeSocket(_fake_response())

    def fake_create_connection(*_a, **_kw):
        return fake

    monkeypatch.setattr("src.agent.client.socket.create_connection", fake_create_connection)

    sink = MemorySink()
    client = AgentClient()
    client.observer = Observer(actor="caller", sink=sink)

    resp = client.request("GET", "agent.obscura", "/health", port=80)
    assert resp.status == 200

    kinds = [e.kind for e in sink.events()]
    assert kinds == [KIND_DIAL_OUT, KIND_DIAL_RESULT]
    out, result = sink.events()
    assert out.payload["addr"] == "agent.obscura"
    assert out.payload["method"] == "GET"
    assert result.payload["status"] == 200
    assert "latency_ms" in result.payload


def test_agent_client_propagates_session_id_header(monkeypatch):
    fake = _FakeSocket(_fake_response())
    monkeypatch.setattr(
        "src.agent.client.socket.create_connection",
        lambda *_a, **_kw: fake,
    )
    client = AgentClient()
    client.request("GET", "agent.obscura", "/x", session_id="trace-xyz")
    sent = b"".join(fake.sent)
    assert b"X-Obscura-Session: trace-xyz" in sent


# ---------------------------------------------------------------------------
# Ledger integration
# ---------------------------------------------------------------------------


def test_ledger_build_app_emits_tx_commit_events():
    alice = "a1" * 32
    bob = "b2" * 32
    sink = MemorySink()
    obs = Observer(actor="ledger", sink=sink)

    state = LedgerState(initial_balances={alice: 100})
    _, tools = build_ledger_app(state, observer=obs)

    req = Request("POST", "/x", {}, b"")
    req._caller_fingerprint = alice  # type: ignore[attr-defined]
    req.session_id = "sess-1"

    tools.invoke(
        "transfer",
        {"to": bob, "amount": 25, "memo": "lunch", "nonce": "n1"},
        req,
    )

    tx_events = [e for e in sink.events() if e.kind == KIND_TX_COMMIT]
    assert len(tx_events) == 1
    assert tx_events[0].payload["from_account"] == alice
    assert tx_events[0].payload["to_account"] == bob
    assert tx_events[0].payload["amount"] == 25
    assert tx_events[0].session_id == "sess-1"


# ---------------------------------------------------------------------------
# build_observer_from_flags
# ---------------------------------------------------------------------------


def test_build_observer_from_flags_returns_none_when_no_sinks():
    assert build_observer_from_flags(actor="x") is None


def test_build_observer_from_flags_jsonl_only(tmp_path):
    path = str(tmp_path / "events.jsonl")
    obs = build_observer_from_flags(actor="x", jsonl_path=path)
    assert obs is not None
    obs.emit("k", v=1)
    assert os.path.isfile(path)


def test_build_observer_from_flags_remote_only(monkeypatch):
    """A remote-only configuration must build a single-sink observer.

    We don't actually need to dial anything in this test — the
    RemoteSink will spawn a worker thread but stays idle until events
    arrive, so a no-op AgentClient is enough.
    """
    obs = build_observer_from_flags(actor="x", remote_addr="some.obscura")
    assert obs is not None
