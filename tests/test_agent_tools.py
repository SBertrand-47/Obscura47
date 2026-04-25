"""Unit tests for the reference tool/RPC layer."""

from __future__ import annotations

import json
import queue
import socket
import threading
import time
from typing import Callable

import pytest

from src.agent.app import AgentApp, Request, serve_app
from src.agent.client import AgentClient, ToolCallError
from src.agent.tools import (
    DEFAULT_PREFIX,
    PROTOCOL_VERSION,
    ParamSpec,
    ToolError,
    ToolRegistry,
    Topic,
    _format_sse,
)


def _request(method: str, path: str, body: bytes = b"", headers=None) -> Request:
    return Request(method, path, dict(headers or {}), body)


# ---------------------------------------------------------------------------
# ParamSpec / Tool dataclasses
# ---------------------------------------------------------------------------


def test_param_spec_rejects_invalid_type():
    with pytest.raises(ValueError):
        ParamSpec("x", type="garbage")


def test_param_spec_rejects_empty_name():
    with pytest.raises(ValueError):
        ParamSpec("")


def test_param_spec_to_manifest_omits_empty_description():
    spec = ParamSpec("x", type="int", required=False)
    out = spec.to_manifest()
    assert out == {"name": "x", "type": "int", "required": False}
    assert "description" not in out


# ---------------------------------------------------------------------------
# ToolRegistry registration
# ---------------------------------------------------------------------------


def test_register_and_get_tool():
    reg = ToolRegistry()
    reg.register("greet", lambda args, req: "hi", description="say hi")
    tool = reg.get("greet")
    assert tool is not None
    assert tool.description == "say hi"
    assert reg.names() == ["greet"]


def test_decorator_registers_tool():
    reg = ToolRegistry()

    @reg.tool("add", params=[ParamSpec("a", type="int"), ParamSpec("b", type="int")],
              returns="int")
    def _add(args, _req):
        return args["a"] + args["b"]

    assert reg.get("add").returns == "int"


def test_duplicate_registration_raises():
    reg = ToolRegistry()
    reg.register("x", lambda a, r: None)
    with pytest.raises(ValueError):
        reg.register("x", lambda a, r: None)


def test_register_rejects_unsafe_name():
    reg = ToolRegistry()
    with pytest.raises(ValueError):
        reg.register("foo bar", lambda a, r: None)
    with pytest.raises(ValueError):
        reg.register("../escape", lambda a, r: None)


def test_register_accepts_dict_params():
    reg = ToolRegistry()
    reg.register(
        "x",
        lambda args, req: args.get("n"),
        params=[{"name": "n", "type": "int", "required": False}],
    )
    assert reg.get("x").params[0].name == "n"


# ---------------------------------------------------------------------------
# Manifest shape
# ---------------------------------------------------------------------------


def test_manifest_includes_protocol_and_topics():
    reg = ToolRegistry()
    reg.register("a", lambda args, req: None, description="a-desc",
                 params=[ParamSpec("x", type="string")])
    reg.topic("events")
    manifest = reg.manifest()
    assert manifest["protocol"] == PROTOCOL_VERSION
    assert "events" in manifest["topics"]
    assert manifest["tools"][0]["name"] == "a"
    assert manifest["tools"][0]["params"] == [
        {"name": "x", "type": "string", "required": True},
    ]


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


def test_invoke_returns_success_envelope():
    reg = ToolRegistry()
    reg.register(
        "double",
        lambda args, req: args["n"] * 2,
        params=[ParamSpec("n", type="int")],
        returns="int",
    )
    resp = reg.invoke("double", {"n": 21}, _request("POST", "/x"))
    assert resp.status == 200
    body = json.loads(resp.body)
    assert body == {"ok": True, "result": 42}


def test_invoke_unknown_tool_returns_404():
    reg = ToolRegistry()
    resp = reg.invoke("nope", {}, _request("POST", "/x"))
    assert resp.status == 404
    body = json.loads(resp.body)
    assert body["ok"] is False
    assert body["error"]["code"] == "not_found"


def test_invoke_missing_required_arg():
    reg = ToolRegistry()
    reg.register("f", lambda a, r: None, params=[ParamSpec("x", type="string")])
    resp = reg.invoke("f", {}, _request("POST", "/x"))
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"]["code"] == "missing_arg"


def test_invoke_wrong_arg_type():
    reg = ToolRegistry()
    reg.register("f", lambda a, r: None, params=[ParamSpec("n", type="int")])
    resp = reg.invoke("f", {"n": "not an int"}, _request("POST", "/x"))
    body = json.loads(resp.body)
    assert resp.status == 400
    assert body["error"]["code"] == "bad_arg_type"


def test_invoke_unknown_arg_when_params_declared():
    reg = ToolRegistry()
    reg.register("f", lambda a, r: None, params=[ParamSpec("n", type="int")])
    resp = reg.invoke("f", {"n": 1, "extra": True}, _request("POST", "/x"))
    body = json.loads(resp.body)
    assert resp.status == 400
    assert body["error"]["code"] == "unknown_arg"


def test_invoke_with_no_declared_params_passes_args_through():
    reg = ToolRegistry()
    reg.register("f", lambda args, req: list(args.keys()))
    resp = reg.invoke("f", {"a": 1, "b": 2}, _request("POST", "/x"))
    body = json.loads(resp.body)
    assert body["ok"] is True
    assert sorted(body["result"]) == ["a", "b"]


def test_invoke_args_must_be_object():
    reg = ToolRegistry()
    reg.register("f", lambda a, r: None)
    resp = reg.invoke("f", "not-an-object", _request("POST", "/x"))
    body = json.loads(resp.body)
    assert resp.status == 400
    assert body["error"]["code"] == "bad_args"


def test_invoke_handler_raises_tool_error():
    reg = ToolRegistry()

    def _h(args, req):
        raise ToolError("forbidden", "nope", status=403)

    reg.register("f", _h)
    resp = reg.invoke("f", {}, _request("POST", "/x"))
    body = json.loads(resp.body)
    assert resp.status == 403
    assert body["error"] == {"code": "forbidden", "message": "nope"}


def test_invoke_handler_raises_generic_exception_returns_500():
    reg = ToolRegistry()

    def _h(args, req):
        raise RuntimeError("boom")

    reg.register("f", _h)
    resp = reg.invoke("f", {}, _request("POST", "/x"))
    body = json.loads(resp.body)
    assert resp.status == 500
    assert body["error"]["code"] == "internal"
    assert "boom" in body["error"]["message"]


def test_int_arg_rejects_bool():
    reg = ToolRegistry()
    reg.register("f", lambda a, r: None, params=[ParamSpec("n", type="int")])
    resp = reg.invoke("f", {"n": True}, _request("POST", "/x"))
    body = json.loads(resp.body)
    assert resp.status == 400
    assert body["error"]["code"] == "bad_arg_type"


# ---------------------------------------------------------------------------
# Mount onto AgentApp
# ---------------------------------------------------------------------------


def test_mount_installs_routes_and_dispatches_invocation():
    app = AgentApp()
    reg = ToolRegistry()
    reg.register(
        "shout",
        lambda args, req: args["s"].upper(),
        params=[ParamSpec("s", type="string")],
    )
    reg.mount(app)

    list_resp = app.dispatch(_request("GET", DEFAULT_PREFIX + "tools"))
    assert list_resp.status == 200
    assert json.loads(list_resp.body)["tools"][0]["name"] == "shout"

    body = json.dumps({"args": {"s": "hi"}}).encode()
    inv_resp = app.dispatch(
        _request("POST", DEFAULT_PREFIX + "tools/shout", body=body)
    )
    assert inv_resp.status == 200
    assert json.loads(inv_resp.body) == {"ok": True, "result": "HI"}


def test_mount_accepts_args_at_top_level_for_convenience():
    app = AgentApp()
    reg = ToolRegistry()
    reg.register("id", lambda args, req: args.get("v"))
    reg.mount(app)

    resp = app.dispatch(_request(
        "POST", DEFAULT_PREFIX + "tools/id",
        body=json.dumps({"v": 7}).encode(),
    ))
    assert json.loads(resp.body) == {"ok": True, "result": 7}


def test_mount_custom_prefix():
    app = AgentApp()
    reg = ToolRegistry()
    reg.register("k", lambda args, req: "v")
    reg.mount(app, prefix="/api/")

    resp = app.dispatch(_request("GET", "/api/tools"))
    assert resp.status == 200


def test_mount_rejects_relative_prefix():
    reg = ToolRegistry()
    with pytest.raises(ValueError):
        reg.mount(AgentApp(), prefix="api/")


# ---------------------------------------------------------------------------
# Topic
# ---------------------------------------------------------------------------


def test_topic_publish_fans_out_to_all_subscribers():
    t = Topic("events")
    a = t.subscribe()
    b = t.subscribe()
    delivered = t.publish({"x": 1})
    assert delivered == 2
    assert a.get_nowait() == {"x": 1}
    assert b.get_nowait() == {"x": 1}


def test_topic_unsubscribe_removes_subscriber():
    t = Topic("events")
    a = t.subscribe()
    t.unsubscribe(a)
    delivered = t.publish("x")
    assert delivered == 0


def test_topic_drops_on_full_subscriber_queue():
    t = Topic("events", maxsize=2)
    q = t.subscribe()
    t.publish(1)
    t.publish(2)
    t.publish(3)
    drained = []
    while True:
        try:
            drained.append(q.get_nowait())
        except queue.Empty:
            break
    assert drained == [1, 2]


def test_topic_registry_returns_existing():
    reg = ToolRegistry()
    a = reg.topic("x")
    b = reg.topic("x")
    assert a is b


# ---------------------------------------------------------------------------
# SSE formatting
# ---------------------------------------------------------------------------


def test_format_sse_dict_is_json_data_frame():
    out = _format_sse({"a": 1})
    assert out == b'data: {"a":1}\r\n\r\n'


def test_format_sse_string_is_passed_through():
    out = _format_sse("hello")
    assert out == b"data: hello\r\n\r\n"


def test_format_sse_multiline_string_split_into_data_lines():
    out = _format_sse("line1\nline2")
    assert out == b"data: line1\r\ndata: line2\r\n\r\n"


# ---------------------------------------------------------------------------
# Subscribe end-to-end via serve_app
# ---------------------------------------------------------------------------


@pytest.fixture
def served_registry():
    app = AgentApp()
    reg = ToolRegistry()

    @reg.tool("ping", description="reachability ping",
              params=[ParamSpec("n", type="int", required=False)])
    def _ping(args, _req):
        return {"pong": True, "n": args.get("n", 0)}

    @reg.tool("boom")
    def _boom(args, _req):
        raise ToolError("denied", "no", status=403)

    topic = reg.topic("events")
    reg.mount(app)
    server, _t = serve_app(app, "127.0.0.1", 0)
    host, port = server.server_address[:2]
    yield host, port, reg, topic
    server.shutdown()
    server.server_close()


def _start_connect_proxy(
    upstream_for: Callable[[str, int], tuple[str, int]],
) -> tuple[str, int, socket.socket]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    proxy_host, proxy_port = srv.getsockname()[:2]

    def _accept():
        while True:
            try:
                cs, _ = srv.accept()
            except OSError:
                return
            threading.Thread(
                target=_serve_connect, args=(cs, upstream_for), daemon=True,
            ).start()

    threading.Thread(target=_accept, daemon=True).start()
    return proxy_host, proxy_port, srv


def _serve_connect(client_sock, upstream_for):
    try:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = client_sock.recv(4096)
            if not chunk:
                return
            head += chunk
        request_line = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
        method, target, _ = request_line.split(" ", 2)
        if method.upper() != "CONNECT":
            return
        host, _, port_str = target.partition(":")
        port = int(port_str or 80)
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        up_host, up_port = upstream_for(host, port)
        upstream = socket.create_connection((up_host, up_port), timeout=5)

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=pump, args=(client_sock, upstream), daemon=True)
        t2 = threading.Thread(target=pump, args=(upstream, client_sock), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
    finally:
        try:
            client_sock.close()
        except OSError:
            pass


@pytest.fixture
def proxy_to_registry(served_registry):
    up_host, up_port, reg, topic = served_registry
    p_host, p_port, srv = _start_connect_proxy(
        upstream_for=lambda _h, _p: (up_host, up_port),
    )
    yield p_host, p_port, reg, topic
    try:
        srv.close()
    except OSError:
        pass


def test_client_list_tools(proxy_to_registry):
    p_host, p_port, _reg, _topic = proxy_to_registry
    client = AgentClient(p_host, p_port, timeout=5)
    manifest = client.list_tools("any.obscura", port=80)
    assert manifest["protocol"] == PROTOCOL_VERSION
    names = [t["name"] for t in manifest["tools"]]
    assert "ping" in names and "boom" in names


def test_client_call_tool_returns_result(proxy_to_registry):
    p_host, p_port, _reg, _topic = proxy_to_registry
    client = AgentClient(p_host, p_port, timeout=5)
    result = client.call_tool("any.obscura", "ping", {"n": 9}, port=80)
    assert result == {"pong": True, "n": 9}


def test_client_call_tool_raises_on_error_envelope(proxy_to_registry):
    p_host, p_port, _reg, _topic = proxy_to_registry
    client = AgentClient(p_host, p_port, timeout=5)
    with pytest.raises(ToolCallError) as exc_info:
        client.call_tool("any.obscura", "boom", {}, port=80)
    assert exc_info.value.code == "denied"
    assert exc_info.value.status == 403


def test_client_call_unknown_tool_raises(proxy_to_registry):
    p_host, p_port, _reg, _topic = proxy_to_registry
    client = AgentClient(p_host, p_port, timeout=5)
    with pytest.raises(ToolCallError) as exc_info:
        client.call_tool("any.obscura", "missing", {}, port=80)
    assert exc_info.value.code == "not_found"


def test_client_subscribe_yields_published_events(proxy_to_registry):
    p_host, p_port, _reg, topic = proxy_to_registry
    client = AgentClient(p_host, p_port, timeout=5)

    received: list = []
    started = threading.Event()
    done = threading.Event()

    def _consume():
        it = client.subscribe("any.obscura", "events", port=80)
        for ev in it:
            if not started.is_set():
                started.set()
            received.append(ev)
            if len(received) >= 3:
                break
        done.set()

    t = threading.Thread(target=_consume, daemon=True)
    t.start()

    deadline = time.time() + 3
    while topic.subscriber_count() < 1 and time.time() < deadline:
        time.sleep(0.02)
    assert topic.subscriber_count() >= 1

    topic.publish({"i": 1})
    topic.publish({"i": 2})
    topic.publish("plain-string")

    assert done.wait(timeout=3)
    assert received == [{"i": 1}, {"i": 2}, "plain-string"]
