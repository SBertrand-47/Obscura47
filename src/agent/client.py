"""HTTP client for talking to `.obscura` agents through an Obscura proxy.

Opens a CONNECT tunnel to the local Obscura HTTP proxy, then speaks
plain HTTP/1.1 to the remote agent's app on the other side. The
underlying onion routing + rendezvous happens inside the proxy; the
client itself only deals in HTTP semantics.

This is the natural counterpart to :class:`AgentRuntime`. Pair them
to have an agent both publish a `.obscura` API surface *and* dial
other agents over the network.
"""

from __future__ import annotations

import json
import socket
from typing import Any, Iterator

from src.agent.tools import DEFAULT_PREFIX
from src.utils.config import PROXY_HOST, PROXY_PORT


class ToolCallError(Exception):
    """Raised when a remote tool returns an ``ok: false`` envelope.

    ``code`` and ``message`` come from the server's error envelope.
    ``status`` is the underlying HTTP status (useful to distinguish
    client-side framing failures from server-side rejections).
    """

    def __init__(self, code: str, message: str, *, status: int = 0):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.status = int(status)


class AgentResponse:
    """Result of an agent HTTP request."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = int(status)
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.text)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class AgentClient:
    """Synchronous HTTP/1.1 client targeting `.obscura` hosts.

    Each request opens a fresh CONNECT tunnel to the Obscura proxy,
    sends a single request with ``Connection: close``, reads the
    response, and tears the tunnel down. That is intentionally simple:
    no connection pooling, no keep-alive, no chunked uploads. The
    primary purpose is reference-quality agent-to-agent calls, not
    high-throughput traffic.
    """

    def __init__(
        self,
        proxy_host: str | None = None,
        proxy_port: int | None = None,
        timeout: float = 30.0,
    ):
        self.proxy_host = proxy_host or PROXY_HOST
        self.proxy_port = int(proxy_port if proxy_port is not None else PROXY_PORT)
        self.timeout = float(timeout)

    def request(
        self,
        method: str,
        addr: str,
        path: str = "/",
        port: int = 80,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> AgentResponse:
        method = method.upper()
        merged_headers: dict[str, str] = {}
        if isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")
            merged_headers["Content-Type"] = "application/json"
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")
        elif body is None:
            body_bytes = b""
        elif isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
        else:
            raise TypeError(f"unsupported body type: {type(body).__name__}")

        if headers:
            merged_headers.update(headers)

        host_header = addr if port == 80 else f"{addr}:{port}"
        merged_headers.setdefault("Host", host_header)
        merged_headers["Connection"] = "close"
        if body_bytes:
            merged_headers.setdefault("Content-Length", str(len(body_bytes)))
        elif method in {"POST", "PUT", "PATCH", "DELETE"}:
            merged_headers.setdefault("Content-Length", "0")

        sock = socket.create_connection(
            (self.proxy_host, self.proxy_port), timeout=self.timeout,
        )
        try:
            sock.settimeout(self.timeout)
            connect = (
                f"CONNECT {addr}:{port} HTTP/1.1\r\n"
                f"Host: {addr}:{port}\r\n"
                f"\r\n"
            ).encode("ascii")
            sock.sendall(connect)

            buf = _SocketBuffer(sock)
            ack_head = buf.read_until(b"\r\n\r\n")
            ack_status = ack_head.split(b"\r\n", 1)[0]
            if not (
                ack_status.startswith(b"HTTP/1.1 200")
                or ack_status.startswith(b"HTTP/1.0 200")
            ):
                raise ConnectionError(
                    f"proxy CONNECT refused: {ack_status!r}"
                )

            request_line = f"{method} {path} HTTP/1.1\r\n".encode("ascii")
            header_lines = b"".join(
                f"{k}: {v}\r\n".encode("latin-1") for k, v in merged_headers.items()
            )
            sock.sendall(request_line + header_lines + b"\r\n" + body_bytes)

            head = buf.read_until(b"\r\n\r\n")
            status, resp_headers = _parse_response_head(head)
            body_out = _read_response_body(buf, resp_headers)
            return AgentResponse(status, resp_headers, body_out)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def get(self, addr: str, path: str = "/", port: int = 80, **kw: Any) -> AgentResponse:
        return self.request("GET", addr, path, port, **kw)

    def post(self, addr: str, path: str = "/", port: int = 80, **kw: Any) -> AgentResponse:
        return self.request("POST", addr, path, port, **kw)

    def put(self, addr: str, path: str = "/", port: int = 80, **kw: Any) -> AgentResponse:
        return self.request("PUT", addr, path, port, **kw)

    def delete(self, addr: str, path: str = "/", port: int = 80, **kw: Any) -> AgentResponse:
        return self.request("DELETE", addr, path, port, **kw)

    def list_tools(
        self, addr: str, port: int = 80, prefix: str = DEFAULT_PREFIX,
    ) -> dict[str, Any]:
        """Fetch the remote agent's tool manifest.

        Returns the parsed JSON document
        (``{"protocol": ..., "tools": [...], "topics": [...]}``).
        """
        resp = self.get(addr, _join_prefix(prefix, "tools"), port=port)
        if not resp.ok:
            raise ToolCallError(
                "manifest_unavailable",
                f"GET tools manifest returned HTTP {resp.status}",
                status=resp.status,
            )
        try:
            return resp.json() or {}
        except ValueError as e:
            raise ToolCallError(
                "bad_manifest", f"manifest was not valid JSON: {e}",
                status=resp.status,
            )

    def call_tool(
        self,
        addr: str,
        name: str,
        args: dict[str, Any] | None = None,
        *,
        port: int = 80,
        prefix: str = DEFAULT_PREFIX,
    ) -> Any:
        """Invoke a remote tool and return its ``result``.

        Raises :class:`ToolCallError` if the server returns
        ``{"ok": false}`` or the response is not a recognisable envelope.
        """
        resp = self.post(
            addr, _join_prefix(prefix, f"tools/{name}"),
            port=port, body={"args": args or {}},
        )
        try:
            envelope = resp.json()
        except ValueError as e:
            raise ToolCallError(
                "bad_envelope", f"response was not JSON: {e}",
                status=resp.status,
            )
        if not isinstance(envelope, dict):
            raise ToolCallError(
                "bad_envelope", "response envelope was not an object",
                status=resp.status,
            )
        if envelope.get("ok") is True:
            return envelope.get("result")
        err = envelope.get("error") or {}
        if not isinstance(err, dict):
            err = {}
        raise ToolCallError(
            err.get("code") or "unknown",
            err.get("message") or f"tool call failed (HTTP {resp.status})",
            status=resp.status,
        )

    def subscribe(
        self,
        addr: str,
        topic: str,
        *,
        port: int = 80,
        prefix: str = DEFAULT_PREFIX,
    ) -> Iterator[Any]:
        """Iterate over events from a remote agent's SSE topic.

        Yields decoded events (JSON if the frame parses, otherwise the
        raw string). The iterator owns the underlying socket; closing
        it (e.g. by exiting a ``for`` loop with ``break``) tears down
        the subscription on both sides.
        """
        sock = socket.create_connection(
            (self.proxy_host, self.proxy_port), timeout=self.timeout,
        )
        try:
            sock.settimeout(self.timeout)
            connect = (
                f"CONNECT {addr}:{port} HTTP/1.1\r\n"
                f"Host: {addr}:{port}\r\n\r\n"
            ).encode("ascii")
            sock.sendall(connect)
            buf = _SocketBuffer(sock)
            ack = buf.read_until(b"\r\n\r\n")
            ack_status = ack.split(b"\r\n", 1)[0]
            if not (
                ack_status.startswith(b"HTTP/1.1 200")
                or ack_status.startswith(b"HTTP/1.0 200")
            ):
                raise ConnectionError(f"proxy CONNECT refused: {ack_status!r}")

            path = _join_prefix(prefix, f"subscribe/{topic}")
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {addr}\r\n"
                f"Accept: text/event-stream\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            sock.sendall(request)

            head = buf.read_until(b"\r\n\r\n")
            status, _headers = _parse_response_head(head)
            if status != 200:
                raise ToolCallError(
                    "subscribe_failed",
                    f"server returned HTTP {status}",
                    status=status,
                )

            sock.settimeout(None)
            yield from _iter_sse_events(buf)
        finally:
            try:
                sock.close()
            except Exception:
                pass


def _join_prefix(prefix: str, suffix: str) -> str:
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    if not prefix.endswith("/"):
        prefix = prefix + "/"
    return prefix + suffix.lstrip("/")


def _iter_sse_events(buf: "_SocketBuffer") -> Iterator[Any]:
    """Yield parsed events from a live SSE byte stream.

    Reads bytes directly off the underlying socket, splitting on CRLF
    or LF so we tolerate any compliant producer. Comments (``: ...``)
    and named events without a ``data:`` field are skipped. Blank-line
    terminators flush any accumulated ``data:`` lines as a single
    event; ``data:`` payloads are JSON-decoded when possible, otherwise
    yielded verbatim. The iterator returns when the socket closes.
    """
    data_lines: list[str] = []
    pending: bytes = bytes(buf._buf)
    buf._buf = b""
    while True:
        nl = _find_line_end(pending)
        while nl is None:
            try:
                chunk = buf._sock.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            pending += chunk
            nl = _find_line_end(pending)
        end_idx, line_end_len = nl
        line = pending[:end_idx]
        pending = pending[end_idx + line_end_len:]

        if line == b"":
            if data_lines:
                payload = "\n".join(data_lines)
                data_lines = []
                yield _decode_sse_payload(payload)
            continue
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text.startswith(":"):
            continue
        if text.startswith("data:"):
            data_lines.append(text[5:].lstrip(" "))


def _find_line_end(buf: bytes) -> tuple[int, int] | None:
    """Locate the next CRLF or LF terminator in ``buf``.

    Returns ``(index_of_terminator, terminator_length)`` or ``None`` if
    no terminator is present yet. The line itself is ``buf[:index]``.
    """
    crlf = buf.find(b"\r\n")
    lf = buf.find(b"\n")
    if crlf == -1 and lf == -1:
        return None
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return crlf, 2
    return lf, 1


def _decode_sse_payload(payload: str) -> Any:
    try:
        return json.loads(payload)
    except (ValueError, TypeError):
        return payload


class _SocketBuffer:
    """Tiny buffered reader so HTTP framing doesn't over-read."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = b""

    def read_line(self) -> bytes:
        while b"\r\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                line, self._buf = self._buf, b""
                return line
            self._buf += chunk
        line, _, rest = self._buf.partition(b"\r\n")
        self._buf = rest
        return line

    def read_until(self, marker: bytes, max_size: int = 65536) -> bytes:
        while marker not in self._buf:
            if len(self._buf) > max_size:
                raise ConnectionError("response header too large")
            chunk = self._sock.recv(4096)
            if not chunk:
                data, self._buf = self._buf, b""
                return data
            self._buf += chunk
        idx = self._buf.find(marker)
        end = idx + len(marker)
        out, self._buf = self._buf[:end], self._buf[end:]
        return out

    def read_n(self, n: int) -> bytes:
        if n <= 0:
            return b""
        out = bytearray()
        if self._buf:
            take = self._buf[:n]
            out.extend(take)
            self._buf = self._buf[len(take):]
        while len(out) < n:
            need = n - len(out)
            chunk = self._sock.recv(min(8192, need))
            if not chunk:
                break
            out.extend(chunk)
        return bytes(out)

    def read_to_eof(self) -> bytes:
        out = bytearray(self._buf)
        self._buf = b""
        while True:
            try:
                chunk = self._sock.recv(8192)
            except OSError:
                break
            if not chunk:
                break
            out.extend(chunk)
        return bytes(out)


def _parse_response_head(head: bytes) -> tuple[int, dict[str, str]]:
    text = head.rstrip(b"\r\n").decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    if not lines:
        return 0, {}
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return status, headers


def _read_response_body(buf: _SocketBuffer, headers: dict[str, str]) -> bytes:
    transfer = headers.get("transfer-encoding", "").lower().strip()
    if transfer == "chunked":
        return _read_chunked_body(buf)
    length = headers.get("content-length")
    if length is not None:
        try:
            n = int(length)
        except ValueError:
            n = 0
        return buf.read_n(n)
    return buf.read_to_eof()


def _read_chunked_body(buf: _SocketBuffer) -> bytes:
    out = bytearray()
    while True:
        size_line = buf.read_line()
        size_str = size_line.split(b";", 1)[0].strip()
        if not size_str:
            continue
        try:
            size = int(size_str, 16)
        except ValueError:
            break
        if size == 0:
            while True:
                trailer = buf.read_line()
                if not trailer:
                    break
            break
        chunk = buf.read_n(size)
        out.extend(chunk)
        buf.read_line()
    return bytes(out)
