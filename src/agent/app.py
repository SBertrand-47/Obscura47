"""Tiny HTTP application abstraction used by the agent runtime.

Just enough to register routes, parse JSON bodies, and emit JSON
responses without dragging in an extra web framework. Backed by
``http.server.ThreadingHTTPServer`` so it runs anywhere stdlib runs.
"""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Callable, Iterable

from src.utils.identity import fingerprint_pubkey, lookup_caller
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.agent.observatory import Observer

log = get_logger(__name__)


Handler = Callable[["Request"], "Response | StreamingResponse"]
BeforeHandler = Callable[["Request"], "Response | StreamingResponse | None"]


class Request:
    """Inbound HTTP request handed to a route handler.

    ``caller_pub`` is the PEM public key of whoever dialed the hidden
    service for this connection, when it can be determined (i.e. the
    request actually arrived through a `.obscura` rendezvous and the
    host registered a caller mapping for the local socket). It's
    ``None`` for purely local traffic — direct ``urllib`` hits during
    tests or operator probes against the bound port.
    """

    def __init__(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        params: dict[str, str] | None = None,
        caller_pub: str | None = None,
    ):
        self.method = method.upper()
        self.path = path
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body
        self.params: dict[str, str] = params or {}
        self.caller_pub: str | None = caller_pub
        self._caller_fingerprint: str | None | object = _UNSET
        self.session_id: str | None = self.headers.get("x-obscura-session") or None

    @property
    def caller_fingerprint(self) -> str | None:
        """SHA-256 hex fingerprint of ``caller_pub``, lazily computed."""
        if self._caller_fingerprint is _UNSET:
            self._caller_fingerprint = fingerprint_pubkey(self.caller_pub)
        return self._caller_fingerprint  # type: ignore[return-value]

    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            return None

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


_UNSET: Any = object()


class Response:
    """Outbound HTTP response.

    ``body`` may be ``bytes``, ``str``, or any JSON-serialisable
    object. Strings are encoded as UTF-8 text; dicts/lists are
    serialised as JSON and the content-type is set accordingly.
    """

    def __init__(
        self,
        status: int = 200,
        body: Any = b"",
        headers: dict[str, str] | None = None,
        content_type: str = "text/plain; charset=utf-8",
    ):
        self.status = int(status)
        self.headers: dict[str, str] = dict(headers or {})
        if isinstance(body, (dict, list)):
            self.body = json.dumps(body).encode("utf-8")
            content_type = "application/json"
        elif isinstance(body, str):
            self.body = body.encode("utf-8")
        elif isinstance(body, (bytes, bytearray)):
            self.body = bytes(body)
        else:
            self.body = json.dumps(body).encode("utf-8")
            content_type = "application/json"
        self.headers.setdefault("Content-Type", content_type)
        self.headers.setdefault("Content-Length", str(len(self.body)))


class StreamingResponse:
    """Outbound response whose body is produced lazily.

    ``body_iter`` yields ``bytes`` (or ``str``, encoded as UTF-8) and
    each chunk is written to the wire as soon as it's produced.
    Content-Length is intentionally never set; clients should treat the
    body as either chunk-streamed (with ``Transfer-Encoding: chunked``)
    or terminated by ``Connection: close`` — by default we emit the
    latter, which is enough for SSE.
    """

    def __init__(
        self,
        status: int = 200,
        body_iter: Iterable[bytes | str] | None = None,
        headers: dict[str, str] | None = None,
        content_type: str = "application/octet-stream",
    ):
        self.status = int(status)
        self.headers: dict[str, str] = dict(headers or {})
        self.headers.setdefault("Content-Type", content_type)
        self.body_iter: Iterable[bytes | str] = body_iter or iter(())


class AgentApp:
    """Route-by-pattern HTTP application.

    Routes are matched by HTTP method + a regex over the request path.
    Use named groups (``(?P<name>...)``) to capture URL parameters into
    ``Request.params``.
    """

    def __init__(self):
        self._routes: list[tuple[str, re.Pattern[str], Handler]] = []
        self._before: list[BeforeHandler] = []
        self.observer: "Observer | None" = None

    def route(self, method: str, pattern: str, handler: Handler) -> None:
        self._routes.append((method.upper(), re.compile(f"^{pattern}$"), handler))

    def get(self, pattern: str):
        def _wrap(handler: Handler) -> Handler:
            self.route("GET", pattern, handler)
            return handler
        return _wrap

    def post(self, pattern: str):
        def _wrap(handler: Handler) -> Handler:
            self.route("POST", pattern, handler)
            return handler
        return _wrap

    def put(self, pattern: str):
        def _wrap(handler: Handler) -> Handler:
            self.route("PUT", pattern, handler)
            return handler
        return _wrap

    def delete(self, pattern: str):
        def _wrap(handler: Handler) -> Handler:
            self.route("DELETE", pattern, handler)
            return handler
        return _wrap

    def before_request(self, fn: BeforeHandler) -> BeforeHandler:
        self._before.append(fn)
        return fn

    def dispatch(self, req: Request) -> Response:
        observer = self.observer
        bare_path = req.path.split("?", 1)[0]
        if observer is not None and req.session_id is None:
            from src.agent.observatory import new_session_id

            req.session_id = new_session_id()
        started = time.time() if observer is not None else 0.0
        if observer is not None:
            try:
                observer.emit(
                    "request.in",
                    session_id=req.session_id,
                    method=req.method,
                    path=bare_path,
                    caller=req.caller_fingerprint,
                    bytes_in=len(req.body or b""),
                )
            except Exception:
                log.exception("observer emit (request.in) failed")
        from src.agent.sandbox import set_current_session_id

        prev_session = None
        try:
            from src.agent.sandbox import current_session_id

            prev_session = current_session_id()
            set_current_session_id(req.session_id)
            resp = self._dispatch_inner(req, bare_path)
        finally:
            set_current_session_id(prev_session)
        if observer is not None:
            try:
                latency_ms = round((time.time() - started) * 1000, 3)
                body_len = 0
                if isinstance(resp, Response):
                    body_len = len(resp.body or b"")
                observer.emit(
                    "response.out",
                    session_id=req.session_id,
                    method=req.method,
                    path=bare_path,
                    status=resp.status,
                    latency_ms=latency_ms,
                    caller=req.caller_fingerprint,
                    bytes_out=body_len,
                    streaming=isinstance(resp, StreamingResponse),
                )
            except Exception:
                log.exception("observer emit (response.out) failed")
        return resp

    def _dispatch_inner(self, req: Request, bare_path: str) -> Response:
        for fn in self._before:
            try:
                early = fn(req)
            except Exception as e:
                log.exception("before_request hook crashed")
                return Response(500, {"error": str(e)})
            if early is not None:
                return early
        for method, pat, handler in self._routes:
            if method != req.method:
                continue
            m = pat.match(bare_path)
            if not m:
                continue
            req.params = m.groupdict()
            try:
                resp = handler(req)
            except Exception as e:
                log.exception("agent route handler crashed")
                return Response(500, {"error": str(e)})
            if isinstance(resp, (Response, StreamingResponse)):
                return resp
            return Response(200, resp)
        return Response(404, {"error": "not_found", "path": bare_path})


def _make_handler(app: AgentApp) -> type[BaseHTTPRequestHandler]:
    class _AgentHTTPRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _serve(self, method: str) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                length = 0
            body = self.rfile.read(length) if length > 0 else b""
            caller_pub = lookup_caller(self.client_address)
            req = Request(
                method, self.path, dict(self.headers), body,
                caller_pub=caller_pub,
            )
            try:
                resp = app.dispatch(req)
            except Exception as e:
                log.exception("agent dispatch error")
                resp = Response(500, {"error": str(e)})
            try:
                self.send_response(resp.status)
                resp.headers.setdefault("Connection", "close")
                for k, v in resp.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                if isinstance(resp, StreamingResponse):
                    for chunk in resp.body_iter:
                        if isinstance(chunk, str):
                            chunk = chunk.encode("utf-8")
                        if not chunk:
                            continue
                        self.wfile.write(chunk)
                        try:
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            return
                elif resp.body:
                    self.wfile.write(resp.body)
            except (BrokenPipeError, ConnectionResetError):
                return

        def do_GET(self) -> None:
            self._serve("GET")

        def do_POST(self) -> None:
            self._serve("POST")

        def do_PUT(self) -> None:
            self._serve("PUT")

        def do_DELETE(self) -> None:
            self._serve("DELETE")

        def do_PATCH(self) -> None:
            self._serve("PATCH")

        def do_HEAD(self) -> None:
            self._serve("HEAD")

    return _AgentHTTPRequestHandler


def serve_app(
    app: AgentApp,
    host: str = "127.0.0.1",
    port: int = 0,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Bind an :class:`AgentApp` to a local HTTP server.

    Returns the server and the worker thread. ``port=0`` lets the OS
    pick a free port, which is the typical case when the runtime hands
    the bound address to a hidden-service host.
    """
    server = ThreadingHTTPServer((host, port), _make_handler(app))
    thread = threading.Thread(
        target=server.serve_forever,
        name=f"agent-app-{port or 'auto'}",
        daemon=True,
    )
    thread.start()
    return server, thread
