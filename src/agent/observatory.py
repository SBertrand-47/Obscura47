"""Operator observability tools for hidden-service networks.

A small structured-event substrate that any `.obscura` operator can
plug into to trace traffic across their hosted services. The shape is
deliberately minimal: producers emit :class:`Event` instances through
an :class:`Observer`, sinks decide where the events go (a JSONL file,
in-memory buffer, a remote `.obscura` collector), and an
:class:`ObservatoryState` + :func:`build_observatory_app` pair turn
the same primitives into a hidden-service that can ingest events from
many producers and serve them back to live subscribers.

Event schema
------------

Every event carries a fixed envelope plus a free-form ``payload`` dict.
Required fields:

* ``event_id`` — UUID4 hex; unique per event.
* ``ts`` — float, seconds since epoch (``time.time()``).
* ``actor`` — short string identifying the producer (typically the
  emitting agent's display name; remote ingest also stamps a separate
  ``submitted_by`` fingerprint server-side).
* ``kind`` — one of the documented event kinds (see ``KIND_*`` below).

Optional / contextual fields:

* ``session_id`` — correlates events that belong to the same logical
  flow (one inbound request, the tool invocations it triggered, the
  outbound dials it spawned, the response). Producers are expected to
  set the same ``session_id`` on every event in a flow.
* ``payload`` — kind-specific keys. Conventional names:
  ``method``/``path``/``status``/``latency_ms``/``bytes_in``/
  ``bytes_out`` for HTTP-shaped events; ``tool``/``args_keys``/
  ``code``/``message``/``caller`` for tool events; ``addr``/``port``
  for dials; ``tx_id``/``from``/``to``/``amount`` for ledger events.

Public framing
--------------

This is a **reference observability primitive** for `.obscura` apps.
Anyone can run their own collector; the protocol does not depend on
any blessed central server, and collectors do not federate.

Wire surface (mounted via :class:`~src.agent.tools.ToolRegistry`):

* ``ingest(events: array, source?: string) -> {accepted, rejected}``
* ``query(kind?, actor?, submitted_by?, session_id?, since?, until?,
  limit?) -> [event ...]``
* ``stats() -> {accepted, by_kind, by_actor}``
* Topic ``events`` — every accepted event fans out to subscribers.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol

from src.agent.app import AgentApp, Request, Response
from src.agent.runtime import AgentRuntime
from src.agent.tools import ParamSpec, ToolError, ToolRegistry, Topic
from src.utils.logger import get_logger

log = get_logger(__name__)


OBSERVATORY_PROTOCOL_VERSION = "obscura.observatory/1"

MAX_EVENTS_PER_INGEST = 256
MAX_EVENT_BYTES = 64 * 1024
MAX_PAYLOAD_KEYS = 64
MAX_PAYLOAD_VALUE_LEN = 4096
DEFAULT_BUFFER_SIZE = 10_000
QUERY_DEFAULT_LIMIT = 100
QUERY_MAX_LIMIT = 1000

KIND_REQUEST_IN = "request.in"
KIND_RESPONSE_OUT = "response.out"
KIND_TOOL_INVOKE = "tool.invoke"
KIND_TOOL_RESULT = "tool.result"
KIND_TOOL_ERROR = "tool.error"
KIND_DIAL_OUT = "dial.out"
KIND_DIAL_RESULT = "dial.result"
KIND_DIAL_ERROR = "dial.error"
KIND_TX_COMMIT = "tx.commit"
KIND_TX_ERROR = "tx.error"
KIND_RUNTIME_START = "runtime.start"
KIND_RUNTIME_STOP = "runtime.stop"

KNOWN_KINDS = frozenset({
    KIND_REQUEST_IN, KIND_RESPONSE_OUT,
    KIND_TOOL_INVOKE, KIND_TOOL_RESULT, KIND_TOOL_ERROR,
    KIND_DIAL_OUT, KIND_DIAL_RESULT, KIND_DIAL_ERROR,
    KIND_TX_COMMIT, KIND_TX_ERROR,
    KIND_RUNTIME_START, KIND_RUNTIME_STOP,
})


@dataclass(frozen=True)
class Event:
    """A single structured observability event.

    Frozen on purpose: events are produced once and never mutated.
    Use :meth:`to_dict` / :meth:`from_dict` for wire round-trips.
    """

    event_id: str
    ts: float
    actor: str
    kind: str
    session_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    submitted_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "event_id": self.event_id,
            "ts": self.ts,
            "actor": self.actor,
            "kind": self.kind,
            "payload": dict(self.payload),
        }
        if self.session_id is not None:
            out["session_id"] = self.session_id
        if self.submitted_by is not None:
            out["submitted_by"] = self.submitted_by
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Event":
        if not isinstance(raw, dict):
            raise ValueError("event must be a JSON object")
        event_id = str(raw.get("event_id") or uuid.uuid4().hex)
        try:
            ts = float(raw.get("ts") or time.time())
        except (TypeError, ValueError):
            ts = time.time()
        actor = str(raw.get("actor") or "")
        kind = str(raw.get("kind") or "")
        if not actor:
            raise ValueError("event actor must be non-empty")
        if not kind:
            raise ValueError("event kind must be non-empty")
        session_id = raw.get("session_id")
        if session_id is not None and not isinstance(session_id, str):
            session_id = str(session_id)
        payload = raw.get("payload") or {}
        if not isinstance(payload, dict):
            raise ValueError("event payload must be an object")
        submitted_by = raw.get("submitted_by")
        if submitted_by is not None and not isinstance(submitted_by, str):
            submitted_by = str(submitted_by)
        return cls(
            event_id=event_id,
            ts=ts,
            actor=actor,
            kind=kind,
            session_id=session_id,
            payload=_sanitise_payload(payload),
            submitted_by=submitted_by,
        )


class EventSink(Protocol):
    """Anything that can absorb an :class:`Event`.

    Implementations must be thread-safe; producers may emit from any
    thread that happens to be servicing a request.
    """

    def write(self, event: Event) -> None: ...

    def close(self) -> None: ...


class NullSink:
    """Discards events. Useful as a default placeholder."""

    def write(self, event: Event) -> None:  # noqa: ARG002
        return

    def close(self) -> None:
        return


class MemorySink:
    """Stores events in a bounded list. Test/inspect helper."""

    def __init__(self, maxsize: int = 4096):
        self._maxsize = int(maxsize)
        self._lock = threading.Lock()
        self._events: list[Event] = []

    def write(self, event: Event) -> None:
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._maxsize:
                drop = len(self._events) - self._maxsize
                del self._events[:drop]

    def close(self) -> None:
        return

    def events(self) -> list[Event]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class JsonlSink:
    """Appends events to a JSONL file with optional size-based rotation.

    ``rotate_bytes`` triggers a rename to ``<path>.<ts>`` when the
    current file exceeds the threshold; ``None`` disables rotation.
    Each line is a single JSON object terminated by ``\\n``.
    """

    def __init__(
        self,
        path: str,
        *,
        rotate_bytes: int | None = 16 * 1024 * 1024,
    ):
        self.path = path
        self.rotate_bytes = rotate_bytes
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)

    def write(self, event: Event) -> None:
        line = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True) + "\n"
        with self._lock:
            self._maybe_rotate_locked()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)

    def close(self) -> None:
        return

    def _maybe_rotate_locked(self) -> None:
        if not self.rotate_bytes:
            return
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size < self.rotate_bytes:
            return
        rotated = f"{self.path}.{int(time.time())}"
        try:
            os.replace(self.path, rotated)
        except OSError as e:
            log.warning("observatory: rotate failed: %s", e)


class MultiSink:
    """Fans every event out to a fixed list of child sinks."""

    def __init__(self, sinks: Iterable[EventSink]):
        self._sinks: list[EventSink] = list(sinks)

    def write(self, event: Event) -> None:
        for sink in self._sinks:
            try:
                sink.write(event)
            except Exception:
                log.exception("observatory: sink %s failed", type(sink).__name__)

    def close(self) -> None:
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:
                pass


class RemoteSink:
    """Pushes events to a remote :func:`build_observatory_app` collector.

    Events are buffered on a bounded queue and drained by a worker
    thread that batches them through the ``ingest`` tool. Backpressure
    is intentional: when the queue is full, oldest events are dropped
    so the producer cannot stall on a slow collector. ``close`` flushes
    pending events with a configurable timeout.
    """

    def __init__(
        self,
        addr: str,
        *,
        agent: Any | None = None,
        port: int = 80,
        source: str | None = None,
        batch_size: int = 32,
        flush_interval: float = 1.0,
        max_queue: int = 4096,
        on_drop: Callable[[int], None] | None = None,
    ):
        from src.agent.client import AgentClient

        self.addr = addr
        self.port = int(port)
        self.source = source
        self.agent = agent or AgentClient()
        self._batch_size = max(1, int(batch_size))
        self._flush_interval = max(0.05, float(flush_interval))
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=max(1, int(max_queue)))
        self._stopped = threading.Event()
        self._on_drop = on_drop
        self._dropped = 0
        self._worker = threading.Thread(
            target=self._run, name=f"observatory-remote-{addr}", daemon=True,
        )
        self._worker.start()

    def write(self, event: Event) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            try:
                _ = self._queue.get_nowait()
            except queue.Empty:
                pass
            self._dropped += 1
            if self._on_drop is not None:
                try:
                    self._on_drop(self._dropped)
                except Exception:
                    pass
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                pass

    def close(self, timeout: float = 5.0) -> None:
        self._stopped.set()
        self._worker.join(timeout=timeout)

    @property
    def dropped(self) -> int:
        return self._dropped

    def _run(self) -> None:
        while not self._stopped.is_set():
            batch: list[Event] = []
            try:
                first = self._queue.get(timeout=self._flush_interval)
                batch.append(first)
            except queue.Empty:
                continue
            while len(batch) < self._batch_size:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            self._send(batch)
        # drain remaining events on shutdown
        leftovers: list[Event] = []
        while True:
            try:
                leftovers.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if leftovers:
            self._send(leftovers)

    def _send(self, batch: list[Event]) -> None:
        args: dict[str, Any] = {
            "events": [e.to_dict() for e in batch],
        }
        if self.source:
            args["source"] = self.source
        try:
            self.agent.call_tool(self.addr, "ingest", args, port=self.port)
        except Exception as e:
            log.warning(
                "observatory: ingest to %s:%s failed: %s; %d events lost",
                self.addr, self.port, e, len(batch),
            )


class Observer:
    """Producer-side handle that stamps and ships :class:`Event`\\s.

    Construct one per agent process, share it across the components
    that should emit through it (an :class:`AgentApp`, a
    :class:`ToolRegistry`, an :class:`AgentClient`). ``actor`` is the
    short identifier embedded into every event; sinks decide where the
    events go.
    """

    def __init__(self, actor: str, *, sink: EventSink | None = None):
        if not actor:
            raise ValueError("Observer.actor must be non-empty")
        self.actor = actor
        self.sink: EventSink = sink or NullSink()
        self._lock = threading.Lock()

    def emit(
        self,
        kind: str,
        *,
        session_id: str | None = None,
        **payload: Any,
    ) -> Event:
        if not kind:
            raise ValueError("emit: kind must be non-empty")
        event = Event(
            event_id=uuid.uuid4().hex,
            ts=time.time(),
            actor=self.actor,
            kind=kind,
            session_id=session_id,
            payload=_sanitise_payload(payload),
        )
        try:
            self.sink.write(event)
        except Exception:
            log.exception("observatory: sink rejected event")
        return event

    def close(self) -> None:
        try:
            self.sink.close()
        except Exception:
            pass


def new_session_id() -> str:
    """Short opaque correlator suitable for the ``session_id`` field."""
    return uuid.uuid4().hex[:16]


# ---------------------------------------------------------------------------
# Collector side: in-memory state and the .obscura tool surface.
# ---------------------------------------------------------------------------


class ObservatoryState:
    """Bounded in-memory ring of events with filtered query access.

    Newest events are appended at the end; queries return them in
    reverse chronological order (newest first). When the buffer
    overflows ``maxsize``, oldest events are dropped.
    """

    def __init__(self, maxsize: int = DEFAULT_BUFFER_SIZE):
        self._maxsize = max(1, int(maxsize))
        self._lock = threading.Lock()
        self._events: list[Event] = []
        self._accepted = 0
        self._rejected = 0
        self._by_kind: dict[str, int] = {}
        self._by_actor: dict[str, int] = {}

    def append(self, event: Event) -> None:
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._maxsize:
                drop = len(self._events) - self._maxsize
                del self._events[:drop]
            self._accepted += 1
            self._by_kind[event.kind] = self._by_kind.get(event.kind, 0) + 1
            self._by_actor[event.actor] = self._by_actor.get(event.actor, 0) + 1

    def reject(self) -> None:
        with self._lock:
            self._rejected += 1

    def query(
        self,
        *,
        kind: str | None = None,
        actor: str | None = None,
        submitted_by: str | None = None,
        session_id: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = QUERY_DEFAULT_LIMIT,
    ) -> list[Event]:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ToolError("bad_limit", "limit must be a positive integer")
        limit = min(limit, QUERY_MAX_LIMIT)
        with self._lock:
            rows = list(self._events)
        out: list[Event] = []
        for e in reversed(rows):
            if kind and e.kind != kind:
                continue
            if actor and e.actor != actor:
                continue
            if submitted_by and e.submitted_by != submitted_by:
                continue
            if session_id and e.session_id != session_id:
                continue
            if since is not None and e.ts < float(since):
                continue
            if until is not None and e.ts > float(until):
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "accepted": self._accepted,
                "rejected": self._rejected,
                "buffered": len(self._events),
                "buffer_max": self._maxsize,
                "by_kind": dict(self._by_kind),
                "by_actor": dict(self._by_actor),
            }

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._accepted = 0
            self._rejected = 0
            self._by_kind.clear()
            self._by_actor.clear()


def build_observatory_app(
    state: ObservatoryState,
    *,
    name: str = "observatory",
) -> tuple[AgentApp, ToolRegistry]:
    """Wire an :class:`ObservatoryState` as a `.obscura` tool surface.

    Mirrors the layout used by :mod:`src.agent.ledger`: a couple of
    public ``/`` / ``/health`` / ``/info`` routes, plus the standard
    tool prefix carrying ``ingest``, ``query``, ``stats`` and an
    ``events`` SSE topic.
    """
    app = AgentApp()
    tools = ToolRegistry()
    events_topic: Topic = tools.topic("events")

    def _publish(event: Event) -> None:
        try:
            events_topic.publish(event.to_dict())
        except Exception:
            log.exception("observatory: failed to fan out event")

    @app.get("/")
    def _root(_req: Request) -> Response:
        return Response(200, {
            "service": "observatory",
            "name": name,
            "protocol": OBSERVATORY_PROTOCOL_VERSION,
            "endpoints": [
                "/health", "/info",
                "/.well-known/obscura/tools",
            ],
        })

    @app.get("/health")
    def _health(_req: Request) -> Response:
        return Response(200, {"ok": True, **state.stats()})

    @app.get("/info")
    def _info(_req: Request) -> Response:
        return Response(200, {
            "service": "observatory",
            "name": name,
            "protocol": OBSERVATORY_PROTOCOL_VERSION,
            **state.stats(),
        })

    @tools.tool(
        "ingest",
        description="Append a batch of structured events to the collector.",
        params=[
            ParamSpec("events", type="array",
                      description="list of event dicts (max 256 per call)"),
            ParamSpec("source", type="string", required=False,
                      description="optional free-form producer label"),
        ],
        returns="object",
    )
    def _ingest(args: dict, req: Request) -> dict:
        raw_events = args.get("events") or []
        if not isinstance(raw_events, list):
            raise ToolError("bad_events", "events must be an array")
        if len(raw_events) > MAX_EVENTS_PER_INGEST:
            raise ToolError(
                "too_many_events",
                f"max {MAX_EVENTS_PER_INGEST} events per ingest call",
            )
        submitted_by = req.caller_fingerprint
        accepted = 0
        rejected = 0
        for raw in raw_events:
            try:
                event = Event.from_dict(raw)
            except (ValueError, TypeError) as e:
                log.debug("observatory: rejecting event: %s", e)
                rejected += 1
                state.reject()
                continue
            event = Event(
                event_id=event.event_id,
                ts=event.ts,
                actor=event.actor,
                kind=event.kind,
                session_id=event.session_id,
                payload=event.payload,
                submitted_by=submitted_by,
            )
            state.append(event)
            _publish(event)
            accepted += 1
        return {"accepted": accepted, "rejected": rejected}

    @tools.tool(
        "query",
        description="Return recent events filtered by kind/actor/session/time.",
        params=[
            ParamSpec("kind", type="string", required=False),
            ParamSpec("actor", type="string", required=False),
            ParamSpec("submitted_by", type="string", required=False),
            ParamSpec("session_id", type="string", required=False),
            ParamSpec("since", type="float", required=False,
                      description="lower-bound unix timestamp"),
            ParamSpec("until", type="float", required=False,
                      description="upper-bound unix timestamp"),
            ParamSpec("limit", type="int", required=False,
                      description=f"max rows to return (1..{QUERY_MAX_LIMIT})"),
        ],
        returns="array",
    )
    def _query(args: dict, _req: Request) -> list[dict]:
        rows = state.query(
            kind=args.get("kind"),
            actor=args.get("actor"),
            submitted_by=args.get("submitted_by"),
            session_id=args.get("session_id"),
            since=args.get("since"),
            until=args.get("until"),
            limit=args.get("limit") or QUERY_DEFAULT_LIMIT,
        )
        return [e.to_dict() for e in rows]

    @tools.tool(
        "stats",
        description="Counts of buffered/accepted events broken down by kind and actor.",
        params=[],
        returns="object",
    )
    def _stats(_args: dict, _req: Request) -> dict:
        return state.stats()

    tools.mount(app)
    return app, tools


# ---------------------------------------------------------------------------
# CLI helpers — opt-in observers wired from operator flags.
# ---------------------------------------------------------------------------


def build_observer_from_flags(
    *,
    actor: str,
    jsonl_path: str | None = None,
    remote_addr: str | None = None,
    remote_port: int = 80,
) -> Observer | None:
    """Construct an :class:`Observer` from a small set of CLI flags.

    Returns ``None`` when no sink is configured. When both flags are
    supplied a :class:`MultiSink` is built so events land locally
    *and* on a remote collector — this is the typical operator setup
    where the JSONL file is the durable record and the remote
    collector is a live dashboard.
    """
    sinks: list[EventSink] = []
    if jsonl_path:
        sinks.append(JsonlSink(jsonl_path))
    if remote_addr:
        sinks.append(RemoteSink(remote_addr, port=remote_port, source=actor))
    if not sinks:
        return None
    sink: EventSink = sinks[0] if len(sinks) == 1 else MultiSink(sinks)
    return Observer(actor=actor, sink=sink)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitise_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Trim payloads to bounded sizes to keep events cheap to ship.

    Drops keys past :data:`MAX_PAYLOAD_KEYS` and truncates oversize
    string values. Non-JSON-serialisable values are coerced via
    ``repr``. Dicts/lists are JSON-encoded, length-checked, and parsed
    back so the ring buffer never holds opaque types.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for i, (k, v) in enumerate(raw.items()):
        if i >= MAX_PAYLOAD_KEYS:
            break
        out[str(k)] = _shrink_value(v)
    return out


def _shrink_value(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        if len(v) > MAX_PAYLOAD_VALUE_LEN:
            return v[:MAX_PAYLOAD_VALUE_LEN] + "..."
        return v
    if isinstance(v, (list, tuple)):
        return [_shrink_value(x) for x in v[:MAX_PAYLOAD_KEYS]]
    if isinstance(v, dict):
        return {str(k): _shrink_value(x) for k, x in list(v.items())[:MAX_PAYLOAD_KEYS]}
    try:
        encoded = json.dumps(v)
    except (TypeError, ValueError):
        return repr(v)[:MAX_PAYLOAD_VALUE_LEN]
    if len(encoded) > MAX_PAYLOAD_VALUE_LEN:
        return encoded[:MAX_PAYLOAD_VALUE_LEN] + "..."
    return json.loads(encoded)


# ---------------------------------------------------------------------------
# CLI entry point — `python -m src.agent.observatory`
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.agent.observatory",
        description=(
            "Publish a structured-event collector as a `.obscura` hidden "
            "service. Reference observability primitive for `.obscura` apps."
        ),
    )
    parser.add_argument(
        "--name", default="observatory",
        help="display name surfaced in /info",
    )
    parser.add_argument(
        "--key", default="observatory_service.pem",
        help="path to the ECC service keypair (PEM); created if missing",
    )
    parser.add_argument(
        "--bind", default="127.0.0.1",
        help="local interface for the HTTP server (default 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=0,
        help="local port for the HTTP server (default: pick a free port)",
    )
    parser.add_argument(
        "--buffer", type=int, default=DEFAULT_BUFFER_SIZE,
        help="max events kept in the in-memory ring",
    )
    parser.add_argument(
        "--jsonl", default=None,
        help="if set, also persist every accepted event as JSONL at this path",
    )

    from src.agent.sandboxed_runtime import add_sandbox_arguments, policy_from_args

    add_sandbox_arguments(parser)
    args = parser.parse_args(argv)

    state = ObservatoryState(maxsize=args.buffer)
    app, tools = build_observatory_app(state, name=args.name)

    if args.jsonl:
        sink = JsonlSink(args.jsonl)
        events_topic = tools.topic("events")
        original_publish = events_topic.publish

        def _persist_and_publish(event_dict: Any) -> int:
            try:
                if isinstance(event_dict, dict):
                    sink.write(Event.from_dict(event_dict))
            except Exception:
                log.exception("observatory: jsonl mirror failed")
            return original_publish(event_dict)

        events_topic.publish = _persist_and_publish  # type: ignore[assignment]

    policy = policy_from_args(args)

    runtime = AgentRuntime(
        name=args.name, key_path=args.key,
        app=app, tools=tools,
        bind_host=args.bind, bind_port=args.port,
        policy=policy,
    )

    if not runtime.start():
        print("[observatory] failed to publish hidden service", file=sys.stderr)
        return 1

    print(
        f"[observatory] {runtime.name} → {runtime.address} "
        f"(buffer={args.buffer}, jsonl={args.jsonl or 'off'})"
    )
    try:
        runtime.join()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
