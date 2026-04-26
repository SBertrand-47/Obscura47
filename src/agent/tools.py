"""Reference service protocol for ``.obscura`` apps.

Layers a tiny RPC convention on top of :class:`~src.agent.app.AgentApp`
so any hidden service can describe its capabilities, accept invocations,
and stream events without each host inventing a wire format.

Three routes are mounted (default prefix ``/.well-known/obscura/``):

* ``GET  <prefix>tools``                 — JSON manifest of registered tools
* ``POST <prefix>tools/<name>``          — invoke a tool, body ``{"args": {...}}``
* ``GET  <prefix>subscribe/<topic>``     — long-lived SSE stream of topic events

The manifest is a JSON document of the form::

    {
      "protocol": "obscura.tools/1",
      "tools": [
        {"name": "...", "description": "...",
         "params": [{"name": "...", "type": "string", "required": true,
                     "description": "..."}],
         "returns": "object"}
      ],
      "topics": ["events", ...]
    }

Invocation envelope (response body)::

    {"ok": true, "result": ...}
    {"ok": false, "error": {"code": "...", "message": "..."}}

Schemas are intentionally minimal: a parameter type is one of
``string``, ``int``, ``float``, ``bool``, ``object``, ``array``, ``any``.
Richer validation (JSON Schema) can be layered on later without changing
the wire shape.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator

from src.agent.app import AgentApp, Request, Response, StreamingResponse
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.agent.observatory import Observer

log = get_logger(__name__)


PROTOCOL_VERSION = "obscura.tools/1"
DEFAULT_PREFIX = "/.well-known/obscura/"

_VALID_TYPES = frozenset({
    "string", "int", "float", "bool", "object", "array", "any",
})


ToolHandler = Callable[[dict[str, Any], Request], Any]


class ToolError(Exception):
    """Raised by a tool handler to return a structured error envelope."""

    def __init__(self, code: str, message: str, *, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = int(status)


@dataclass(frozen=True)
class ParamSpec:
    """One declared argument of a tool."""

    name: str
    type: str = "any"
    required: bool = True
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("ParamSpec.name must be a non-empty string")
        if self.type not in _VALID_TYPES:
            raise ValueError(
                f"ParamSpec.type {self.type!r} not in {sorted(_VALID_TYPES)}"
            )

    def to_manifest(self) -> dict[str, Any]:
        out = {"name": self.name, "type": self.type, "required": self.required}
        if self.description:
            out["description"] = self.description
        return out


@dataclass(frozen=True)
class Tool:
    """A registered capability."""

    name: str
    handler: ToolHandler
    description: str = ""
    params: tuple[ParamSpec, ...] = ()
    returns: str = "any"

    def to_manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "params": [p.to_manifest() for p in self.params],
            "returns": self.returns,
        }


class Topic:
    """Fan-out channel of JSON-serialisable events to SSE subscribers.

    Each ``subscribe()`` returns a private queue; ``publish()`` deposits
    a copy onto every live subscriber's queue. Slow subscribers drop
    events past ``maxsize`` rather than blocking publishers.
    """

    def __init__(self, name: str, maxsize: int = 256):
        self.name = name
        self._maxsize = int(maxsize)
        self._lock = threading.Lock()
        self._subs: list[queue.Queue[Any]] = []

    def publish(self, event: Any) -> int:
        with self._lock:
            subs = list(self._subs)
        delivered = 0
        for q in subs:
            try:
                q.put_nowait(event)
                delivered += 1
            except queue.Full:
                log.warning("topic %s subscriber queue full; dropping event", self.name)
        return delivered

    def subscribe(self) -> queue.Queue[Any]:
        q: queue.Queue[Any] = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue[Any]) -> None:
        with self._lock:
            try:
                self._subs.remove(q)
            except ValueError:
                pass

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)


class ToolRegistry:
    """In-process registry of tools and pub/sub topics.

    Mount onto an :class:`AgentApp` once with :meth:`mount`; the
    registry takes care of routing, schema enforcement, and SSE
    framing. The application stays free to register additional non-tool
    routes alongside the mounted ones.
    """

    def __init__(self):
        self._tools: dict[str, Tool] = {}
        self._topics: dict[str, Topic] = {}
        self._lock = threading.Lock()
        self.observer: "Observer | None" = None

    def register(
        self,
        name: str,
        handler: ToolHandler,
        *,
        description: str = "",
        params: Iterable[ParamSpec | dict[str, Any]] | None = None,
        returns: str = "any",
    ) -> Tool:
        if not name or not isinstance(name, str):
            raise ValueError("tool name must be a non-empty string")
        if not _is_safe_name(name):
            raise ValueError(f"tool name {name!r} must match [A-Za-z0-9_.-]+")
        spec_list: list[ParamSpec] = []
        for p in params or ():
            if isinstance(p, ParamSpec):
                spec_list.append(p)
            elif isinstance(p, dict):
                spec_list.append(ParamSpec(**p))
            else:
                raise TypeError(
                    f"params must be ParamSpec or dict, got {type(p).__name__}"
                )
        if returns not in _VALID_TYPES:
            raise ValueError(
                f"returns {returns!r} not in {sorted(_VALID_TYPES)}"
            )
        tool = Tool(
            name=name, handler=handler, description=description,
            params=tuple(spec_list), returns=returns,
        )
        with self._lock:
            if name in self._tools:
                raise ValueError(f"tool {name!r} already registered")
            self._tools[name] = tool
        return tool

    def tool(
        self,
        name: str,
        *,
        description: str = "",
        params: Iterable[ParamSpec | dict[str, Any]] | None = None,
        returns: str = "any",
    ) -> Callable[[ToolHandler], ToolHandler]:
        def _decorate(fn: ToolHandler) -> ToolHandler:
            self.register(
                name, fn, description=description, params=params, returns=returns,
            )
            return fn
        return _decorate

    def get(self, name: str) -> Tool | None:
        with self._lock:
            return self._tools.get(name)

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._tools.keys())

    def topic(self, name: str, *, maxsize: int = 256) -> Topic:
        if not _is_safe_name(name):
            raise ValueError(f"topic name {name!r} must match [A-Za-z0-9_.-]+")
        with self._lock:
            t = self._topics.get(name)
            if t is None:
                t = Topic(name, maxsize=maxsize)
                self._topics[name] = t
            return t

    def topic_names(self) -> list[str]:
        with self._lock:
            return sorted(self._topics.keys())

    def manifest(self) -> dict[str, Any]:
        with self._lock:
            tools = [t.to_manifest() for t in self._tools.values()]
            topics = sorted(self._topics.keys())
        return {
            "protocol": PROTOCOL_VERSION,
            "tools": tools,
            "topics": topics,
        }

    def invoke(self, name: str, args: Any, request: Request) -> Response:
        """Run a tool by name and wrap the result/error into the envelope."""
        observer = self.observer
        session_id = getattr(request, "session_id", None)
        caller = request.caller_fingerprint
        started = time.time() if observer is not None else 0.0

        def _emit_error(resp: Response, code: str, message: str) -> Response:
            if observer is not None:
                try:
                    latency_ms = round((time.time() - started) * 1000, 3)
                    observer.emit(
                        "tool.error",
                        session_id=session_id,
                        tool=name,
                        caller=caller,
                        code=code,
                        message=message,
                        status=resp.status,
                        latency_ms=latency_ms,
                    )
                except Exception:
                    log.exception("observer emit (tool.error) failed")
            return resp

        tool = self.get(name)
        if tool is None:
            resp = Response(404, {
                "ok": False,
                "error": {"code": "not_found", "message": f"unknown tool {name!r}"},
            })
            return _emit_error(resp, "not_found", f"unknown tool {name!r}")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            resp = Response(400, {
                "ok": False,
                "error": {"code": "bad_args", "message": "args must be an object"},
            })
            return _emit_error(resp, "bad_args", "args must be an object")
        try:
            coerced = _validate_args(tool.params, args)
        except ToolError as e:
            resp = Response(e.status, {
                "ok": False,
                "error": {"code": e.code, "message": e.message},
            })
            return _emit_error(resp, e.code, e.message)
        if observer is not None:
            try:
                observer.emit(
                    "tool.invoke",
                    session_id=session_id,
                    tool=name,
                    caller=caller,
                    args_keys=sorted(coerced.keys()),
                )
            except Exception:
                log.exception("observer emit (tool.invoke) failed")
        try:
            result = tool.handler(coerced, request)
        except ToolError as e:
            resp = Response(e.status, {
                "ok": False,
                "error": {"code": e.code, "message": e.message},
            })
            return _emit_error(resp, e.code, e.message)
        except Exception as e:
            log.exception("tool %s handler crashed", name)
            resp = Response(500, {
                "ok": False,
                "error": {"code": "internal", "message": str(e) or repr(e)},
            })
            return _emit_error(resp, "internal", str(e) or repr(e))
        if observer is not None:
            try:
                latency_ms = round((time.time() - started) * 1000, 3)
                observer.emit(
                    "tool.result",
                    session_id=session_id,
                    tool=name,
                    caller=caller,
                    status=200,
                    latency_ms=latency_ms,
                )
            except Exception:
                log.exception("observer emit (tool.result) failed")
        return Response(200, {"ok": True, "result": result})

    def mount(self, app: AgentApp, prefix: str = DEFAULT_PREFIX) -> None:
        if not prefix.startswith("/"):
            raise ValueError("prefix must start with '/'")
        if not prefix.endswith("/"):
            prefix = prefix + "/"

        registry = self

        @app.get(prefix + "tools")
        def _list_tools(_req: Request) -> Response:
            return Response(200, registry.manifest())

        @app.post(prefix + r"tools/(?P<name>[A-Za-z0-9_.\-]+)")
        def _invoke_tool(req: Request) -> Response:
            body = req.json()
            if isinstance(body, dict) and "args" in body:
                args = body.get("args")
            else:
                args = body if isinstance(body, dict) else {}
            return registry.invoke(req.params["name"], args, req)

        @app.get(prefix + r"subscribe/(?P<topic>[A-Za-z0-9_.\-]+)")
        def _subscribe(req: Request) -> StreamingResponse:
            topic = registry.topic(req.params["topic"])
            return StreamingResponse(
                status=200,
                body_iter=_sse_iter(topic),
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                },
                content_type="text/event-stream; charset=utf-8",
            )


def _is_safe_name(name: str) -> bool:
    if not name:
        return False
    return all(c.isalnum() or c in "_.-" for c in name)


def _validate_args(specs: tuple[ParamSpec, ...], args: dict[str, Any]) -> dict[str, Any]:
    out = dict(args)
    declared = {p.name for p in specs}
    for spec in specs:
        if spec.name not in args:
            if spec.required:
                raise ToolError(
                    "missing_arg",
                    f"required argument {spec.name!r} not provided",
                )
            continue
        value = args[spec.name]
        if not _matches_type(value, spec.type):
            raise ToolError(
                "bad_arg_type",
                f"argument {spec.name!r} must be of type {spec.type}",
            )
        out[spec.name] = value
    if specs:
        for k in args:
            if k not in declared:
                raise ToolError(
                    "unknown_arg",
                    f"unexpected argument {k!r}",
                )
    return out


def _matches_type(value: Any, declared: str) -> bool:
    if declared == "any":
        return True
    if declared == "string":
        return isinstance(value, str)
    if declared == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared == "float":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared == "bool":
        return isinstance(value, bool)
    if declared == "object":
        return isinstance(value, dict)
    if declared == "array":
        return isinstance(value, list)
    return False


def _sse_iter(topic: Topic) -> Iterator[bytes]:
    """Generator that pulls from a fresh subscriber queue and yields SSE frames.

    A 15-second keepalive comment keeps intermediaries from closing the
    connection during quiet periods. The subscription is removed when
    the generator is closed by the HTTP handler. Frames terminate with
    CRLF — SSE permits LF, CR, or CRLF, and CRLF is the friendliest
    choice for plain HTTP/1.1 line readers in the rest of the codebase.
    """
    q = topic.subscribe()
    keepalive = 15.0
    try:
        yield b": connected\r\n\r\n"
        while True:
            try:
                event = q.get(timeout=keepalive)
            except queue.Empty:
                yield f": keepalive {int(time.time())}\r\n\r\n".encode("utf-8")
                continue
            yield _format_sse(event)
    except GeneratorExit:
        return
    finally:
        topic.unsubscribe(q)


def _format_sse(event: Any) -> bytes:
    """Encode an event as a single SSE ``data:`` frame.

    ``str`` events go through verbatim, anything else is JSON-encoded.
    Embedded newlines are folded into multiple ``data:`` lines as the
    SSE spec requires.
    """
    if isinstance(event, (bytes, bytearray)):
        text = bytes(event).decode("utf-8", errors="replace")
    elif isinstance(event, str):
        text = event
    else:
        text = json.dumps(event, separators=(",", ":"))
    lines = text.split("\n")
    body = "".join(f"data: {line}\r\n" for line in lines)
    return (body + "\r\n").encode("utf-8")
