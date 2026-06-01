import socket

from src.core import proxy as proxy_mod


class _FakeClientSocket:
    def __init__(self, request: bytes):
        self._request = request
        self.sent = []
        self.closed = False

    def recv(self, _size, _flags=0):
        data = self._request
        self._request = b""
        return data

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def sendall(self, data):
        self.sent.append(data)
        return len(data)

    def close(self):
        self.closed = True


def test_handle_connect_falls_back_to_direct_exit_when_no_relays(monkeypatch):
    """When no relay peers exist but an exit is reachable, we fall back to a
    single-hop direct-to-exit route (commit cf5f355) rather than refusing.
    """
    request = (
        b"CONNECT google.com:443 HTTP/1.1\r\n"
        b"Host: google.com:443\r\n\r\n"
    )
    client = _FakeClientSocket(request)

    proxy_mod.relay_peers[:] = []
    proxy_mod.exit_peers[:] = [{"host": "203.0.113.5", "port": 6000, "pub": "pub"}]

    monkeypatch.setattr(proxy_mod, "choose_best_exit", lambda: dict(proxy_mod.exit_peers[0]))
    monkeypatch.setattr(proxy_mod, "build_route47", lambda peers: [])

    received_route = {"value": None}

    def _capture_start(destination, peers, request_id, host, port, return_path, route=None, session_id=None):
        received_route["value"] = route
        return None  # simulate tunnel setup failure to short-circuit the test

    monkeypatch.setattr(proxy_mod, "start_tunnel", _capture_start)

    proxy_mod.handle_connect(client)

    assert received_route["value"] is not None
    assert received_route["value"][0]["host"] == "203.0.113.5"


def test_handle_connect_refuses_when_no_exits(monkeypatch):
    """No relays and no exits: refuse without attempting start_tunnel.

    ``choose_best_exit`` is monkeypatched to a stub destination so the
    early-refusal guard does not short-circuit; the inner ``if exit_peers``
    check is what we are exercising.
    """
    request = (
        b"CONNECT google.com:443 HTTP/1.1\r\n"
        b"Host: google.com:443\r\n\r\n"
    )
    client = _FakeClientSocket(request)

    proxy_mod.relay_peers[:] = []
    proxy_mod.exit_peers[:] = []

    monkeypatch.setattr(
        proxy_mod, "choose_best_exit",
        lambda: {"host": "203.0.113.5", "port": 6000, "pub": "pub"},
    )
    monkeypatch.setattr(proxy_mod, "build_route47", lambda peers: [])

    started = {"called": False}

    def _unexpected_start(*args, **kwargs):
        started["called"] = True

    monkeypatch.setattr(proxy_mod, "start_tunnel", _unexpected_start)

    proxy_mod.handle_connect(client)

    assert started["called"] is False
    assert client.closed is True


def test_handle_connect_refuses_when_tunnel_setup_fails(monkeypatch):
    request = (
        b"CONNECT google.com:443 HTTP/1.1\r\n"
        b"Host: google.com:443\r\n\r\n"
    )
    client = _FakeClientSocket(request)

    proxy_mod.relay_peers[:] = [{"host": "203.0.113.20", "port": 5001, "pub": "relay-pub"}]
    proxy_mod.exit_peers[:] = [{"host": "203.0.113.5", "port": 6000, "pub": "exit-pub"}]

    monkeypatch.setattr(proxy_mod, "choose_best_exit", lambda: dict(proxy_mod.exit_peers[0]))
    monkeypatch.setattr(proxy_mod, "build_route47", lambda peers: [dict(proxy_mod.relay_peers[0])])
    monkeypatch.setattr(proxy_mod, "start_tunnel", lambda *args, **kwargs: None)

    proxy_mod.handle_connect(client)

    assert client.closed is True
    assert client.sent == [b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n"]


# ── HTTP proxy bridge for .obscura ─────────────────────────────────────

_VALID_OBSCURA = "aaaaaaaaaaaaaaaa.obscura"


def _captured_dial(monkeypatch):
    """Install a stub dial_hidden_service that records the addr and returns
    a synthetic (route, request_id, service_pub) triple. The chunk sender
    is also stubbed so the test does not need a real WS/TCP transport.
    """
    captured = {"addr": None, "chunks": []}

    def fake_dial(addr, _pub, peers=None):
        captured["addr"] = addr
        return ([{"host": "h", "port": 1, "pub": "p"}], "req-123", "svc-pub")

    def fake_seal(_pub, b64_chunk):
        # Pass the decoded chunk through unchanged so the test can inspect it.
        return f"sealed:{b64_chunk}"

    def fake_send(_route, _req_id, sealed_chunk):
        captured["chunks"].append(sealed_chunk)
        return True

    monkeypatch.setattr(proxy_mod, "dial_hidden_service", fake_dial)
    monkeypatch.setattr(proxy_mod, "onion_encrypt_for_peer", fake_seal)
    monkeypatch.setattr(proxy_mod, "send_hs_chunk", fake_send)
    monkeypatch.setattr(proxy_mod, "close_hs", lambda *a, **kw: None)
    return captured


def test_http_proxy_bridges_obscura_request(monkeypatch):
    """A `GET http://<addr>.obscura/page HTTP/1.1` arrives at the proxy;
    we expect it to dial the HS, push a rewritten request, and not crash.
    """
    import base64

    captured = _captured_dial(monkeypatch)
    request = (
        f"GET http://{_VALID_OBSCURA}/page?x=1 HTTP/1.1\r\n"
        f"Host: {_VALID_OBSCURA}\r\n"
        "User-Agent: test\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode()
    client = _FakeClientSocket(request)

    proxy_mod.handle_http_proxy(client)

    assert captured["addr"] == _VALID_OBSCURA
    assert captured["chunks"], "expected at least one HS chunk to be sent"

    # The first chunk holds the rewritten request. Decode it back through the
    # stub's `sealed:<b64>` envelope to verify the rewrite.
    first = captured["chunks"][0]
    assert first.startswith("sealed:")
    decoded = base64.b64decode(first.removeprefix("sealed:")).decode("latin-1")
    # Request line is now relative, not absolute-URI.
    first_line = decoded.split("\r\n", 1)[0]
    assert first_line == "GET /page?x=1 HTTP/1.1"
    # Hop-by-hop headers were stripped.
    lower = decoded.lower()
    assert "proxy-connection" not in lower
    # Keep-alive was replaced with Connection: close.
    assert "connection: close" in lower
    # Host header preserved.
    assert f"host: {_VALID_OBSCURA}" in lower


def test_http_proxy_refuses_clearnet(monkeypatch):
    """Plain HTTP to a non-.obscura target should return 501 and never call
    dial_hidden_service - clearnet HTTP belongs on the CONNECT path so the
    exit sees only encrypted bytes from this proxy's point of view.
    """
    dialed = {"called": False}

    def _unexpected_dial(*a, **kw):
        dialed["called"] = True

    monkeypatch.setattr(proxy_mod, "dial_hidden_service", _unexpected_dial)

    request = (
        b"GET http://example.com/ HTTP/1.1\r\n"
        b"Host: example.com\r\n\r\n"
    )
    client = _FakeClientSocket(request)

    proxy_mod.handle_http_proxy(client)

    assert dialed["called"] is False
    assert client.closed is True
    assert client.sent, "expected a 501 response"
    assert client.sent[0].startswith(b"HTTP/1.1 501 Not Implemented")


def test_http_proxy_returns_502_when_dial_fails(monkeypatch):
    monkeypatch.setattr(
        proxy_mod, "dial_hidden_service", lambda *_a, **_kw: None,
    )

    request = (
        f"GET http://{_VALID_OBSCURA}/ HTTP/1.1\r\n"
        f"Host: {_VALID_OBSCURA}\r\n\r\n"
    ).encode()
    client = _FakeClientSocket(request)

    proxy_mod.handle_http_proxy(client)

    assert client.closed is True
    assert any(b"502 Bad Gateway" in chunk for chunk in client.sent)


def test_handle_new_client_dispatches_http_proxy(monkeypatch):
    """Smoke test the dispatcher: a non-CONNECT request line should route to
    handle_http_proxy (we monkey-patch it to record the call).
    """
    called = {"http": False, "connect": False}

    class _PeekSocket(_FakeClientSocket):
        def recv(self, size, flags=0):
            if flags == socket.MSG_PEEK:
                return self._request
            return super().recv(size, flags)

        def getpeername(self):
            return ("127.0.0.1", 12345)

    request = (
        f"GET http://{_VALID_OBSCURA}/ HTTP/1.1\r\n"
        f"Host: {_VALID_OBSCURA}\r\n\r\n"
    ).encode()
    client = _PeekSocket(request)

    monkeypatch.setattr(
        proxy_mod, "handle_http_proxy",
        lambda _c: called.__setitem__("http", True),
    )
    monkeypatch.setattr(
        proxy_mod, "handle_connect",
        lambda _c: called.__setitem__("connect", True),
    )
    # Token gate disabled by default; ensure the test does not trip it.
    monkeypatch.setattr(proxy_mod, "PROXY_TOKEN", "")

    proxy_mod.handle_new_client(client)

    assert called["http"] is True
    assert called["connect"] is False
