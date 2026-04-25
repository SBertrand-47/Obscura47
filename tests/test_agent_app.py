"""Unit tests for the agent HTTP app abstraction."""

from __future__ import annotations

import json
import urllib.request
import urllib.error

import pytest

from src.agent.app import AgentApp, Request, Response, serve_app


def _request(method: str, path: str, body: bytes = b"", headers=None) -> Request:
    return Request(method, path, dict(headers or {}), body)


def test_dispatch_returns_404_for_unknown_path():
    app = AgentApp()
    resp = app.dispatch(_request("GET", "/missing"))
    assert resp.status == 404
    assert json.loads(resp.body)["error"] == "not_found"


def test_dispatch_invokes_matching_handler():
    app = AgentApp()

    @app.get("/hello")
    def _hello(_req):
        return Response(200, "world")

    resp = app.dispatch(_request("GET", "/hello"))
    assert resp.status == 200
    assert resp.body == b"world"


def test_dispatch_passes_named_groups_into_params():
    app = AgentApp()

    @app.get(r"/agents/(?P<name>[a-z]+)")
    def _show(req):
        return Response(200, {"name": req.params["name"]})

    resp = app.dispatch(_request("GET", "/agents/alice"))
    assert resp.status == 200
    assert json.loads(resp.body) == {"name": "alice"}


def test_dispatch_strips_query_string_from_match():
    app = AgentApp()

    @app.get("/q")
    def _q(_req):
        return Response(200, "ok")

    resp = app.dispatch(_request("GET", "/q?x=1&y=2"))
    assert resp.status == 200


def test_dispatch_method_mismatch_falls_through_to_404():
    app = AgentApp()

    @app.post("/submit")
    def _submit(_req):
        return Response(200, "posted")

    resp = app.dispatch(_request("GET", "/submit"))
    assert resp.status == 404


def test_handler_returning_non_response_is_wrapped():
    app = AgentApp()

    @app.get("/raw")
    def _raw(_req):
        return {"hello": "world"}

    resp = app.dispatch(_request("GET", "/raw"))
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "application/json"
    assert json.loads(resp.body) == {"hello": "world"}


def test_handler_exception_returns_500_with_message():
    app = AgentApp()

    @app.get("/boom")
    def _boom(_req):
        raise RuntimeError("fail-on-purpose")

    resp = app.dispatch(_request("GET", "/boom"))
    assert resp.status == 500
    assert json.loads(resp.body)["error"] == "fail-on-purpose"


def test_before_request_can_short_circuit():
    app = AgentApp()
    seen: list[str] = []

    @app.before_request
    def _auth(req):
        if req.headers.get("authorization") != "Bearer secret":
            return Response(401, {"error": "unauthorized"})
        return None

    @app.get("/protected")
    def _protected(_req):
        seen.append("ran")
        return Response(200, {"ok": True})

    denied = app.dispatch(_request("GET", "/protected"))
    assert denied.status == 401
    assert seen == []

    allowed = app.dispatch(
        _request("GET", "/protected", headers={"Authorization": "Bearer secret"})
    )
    assert allowed.status == 200
    assert seen == ["ran"]


def test_request_json_decodes_body():
    req = _request(
        "POST", "/x",
        body=json.dumps({"a": 1}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert req.json() == {"a": 1}


def test_request_json_returns_none_on_invalid_body():
    req = _request("POST", "/x", body=b"not json")
    assert req.json() is None


@pytest.fixture
def served_app():
    app = AgentApp()

    @app.get("/ping")
    def _ping(_req):
        return Response(200, {"pong": True})

    @app.post("/echo")
    def _echo(req):
        return Response(200, req.json())

    server, _thread = serve_app(app, "127.0.0.1", 0)
    host, port = server.server_address[:2]
    yield f"http://{host}:{port}"
    server.shutdown()
    server.server_close()


def test_serve_app_serves_get(served_app):
    with urllib.request.urlopen(f"{served_app}/ping", timeout=2) as resp:
        assert resp.status == 200
        assert json.loads(resp.read()) == {"pong": True}


def test_serve_app_serves_post_with_json(served_app):
    payload = json.dumps({"x": 42}).encode()
    req = urllib.request.Request(
        f"{served_app}/echo",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=2) as resp:
        assert resp.status == 200
        assert json.loads(resp.read()) == {"x": 42}


def test_serve_app_returns_404_over_http(served_app):
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{served_app}/nope", timeout=2)
    assert exc_info.value.code == 404


def test_request_caller_defaults_to_none():
    req = _request("GET", "/x")
    assert req.caller_pub is None
    assert req.caller_fingerprint is None


def test_request_caller_fingerprint_matches_pub_sha256():
    pub = "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n"
    req = Request("GET", "/x", {}, b"", caller_pub=pub)
    import hashlib
    assert req.caller_fingerprint == hashlib.sha256(pub.encode()).hexdigest()


def test_serve_app_populates_caller_pub_from_registered_socket():
    """When the host registers ``(client_host, client_port)`` in the
    identity registry before the app handler builds the request, the
    handler should surface that as ``req.caller_pub``."""
    import socket

    from src.utils.identity import (
        clear_callers,
        register_caller,
        unregister_caller,
    )

    pub = "-----BEGIN PUBLIC KEY-----\nDIALER\n-----END PUBLIC KEY-----\n"
    captured: dict = {}

    app = AgentApp()

    @app.get("/whoami")
    def _whoami(req):
        captured["caller_pub"] = req.caller_pub
        captured["fp"] = req.caller_fingerprint
        return Response(200, {"caller": req.caller_fingerprint})

    server, _ = serve_app(app, "127.0.0.1", 0)
    try:
        host, port = server.server_address[:2]
        clear_callers()
        sock = socket.create_connection((host, port), timeout=2)
        try:
            local = sock.getsockname()[:2]
            register_caller(local, pub)
            sock.sendall(
                b"GET /whoami HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Connection: close\r\n\r\n"
            )
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            assert b"HTTP/1.1 200" in data
            assert captured["caller_pub"] == pub
            assert captured["fp"] is not None
            assert captured["fp"] in data.decode("utf-8", "replace")
        finally:
            try:
                sock.close()
            except OSError:
                pass
            unregister_caller(local)
    finally:
        server.shutdown()
        server.server_close()
