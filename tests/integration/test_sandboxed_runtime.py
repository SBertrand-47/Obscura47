"""Integration test for Layer 1 sandbox enforcement inside ``AgentRuntime``.

Brings up an :class:`AgentApp` with a tool registry and the in-process
sandbox installed exactly the way :class:`AgentRuntime` would install
it. The test then drives the local HTTP server with raw HTTP/1.1
requests (no rendezvous, no proxy — those are exercised by
``test_agent_runtime.py``) and asserts:

* tools that try to read outside the FS allowlist fail with the
  ``sandbox`` error code surfaced through the standard tool envelope;
* tools that try to dial an unauthorized peer fail the same way;
* tools that respect the policy succeed normally.

Layer 1 is always exercisable, so this test runs on every platform.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import threading

import pytest

from src.agent.app import AgentApp, serve_app
from src.agent.observatory import MemorySink, Observer
from src.agent.sandbox import Sandbox, SandboxPolicy, SandboxViolation
from src.agent.tools import ToolError, ToolRegistry

pytestmark = pytest.mark.integration


def _http(method: str, host: str, port: int, path: str, body: bytes = b"") -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        headers = {"Content-Length": str(len(body))} if body else {}
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def test_layer1_runtime_blocks_forbidden_actions(tmp_path):
    app = AgentApp()
    tools = ToolRegistry()
    sink = MemorySink()
    observer = Observer(actor="sandbox-it", sink=sink)
    app.observer = observer
    tools.observer = observer

    @tools.tool("read_inside", description="read a file inside the allowlist")
    def _read_inside(args, _req):  # noqa: ARG001
        path = os.path.join(str(tmp_path), "agent.txt")
        with open(path) as f:
            return {"content": f.read()}

    @tools.tool("read_etc", description="try to read /etc/passwd")
    def _read_etc(_args, _req):
        try:
            with open("/etc/passwd") as f:
                return {"content": f.read()[:32]}
        except SandboxViolation as e:
            raise ToolError("sandbox", e.detail)

    @tools.tool("dial_evil", description="try to dial an unauthorized peer")
    def _dial_evil(_args, _req):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            try:
                s.connect(("203.0.113.5", 80))
                return {"connected": True}
            except SandboxViolation as e:
                raise ToolError("sandbox", e.detail)
        finally:
            s.close()

    tools.mount(app)
    (tmp_path / "agent.txt").write_text("ok-content")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    relay_port = listener.getsockname()[1]

    server, server_thread = serve_app(app, "127.0.0.1", 0)
    bound_host, bound_port = server.server_address[:2]

    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="obscura_only",
        relay_endpoints=(("127.0.0.1", relay_port),),
    )

    Sandbox.install(policy, observer=observer)
    try:
        status, body = _http(
            "POST", bound_host, bound_port,
            "/.well-known/obscura/tools/read_inside",
            body=b'{"args":{}}',
        )
        envelope = json.loads(body)
        assert status == 200
        assert envelope == {"ok": True, "result": {"content": "ok-content"}}

        status, body = _http(
            "POST", bound_host, bound_port,
            "/.well-known/obscura/tools/read_etc",
            body=b'{"args":{}}',
        )
        envelope = json.loads(body)
        assert envelope["ok"] is False
        assert envelope["error"]["code"] == "sandbox"
        assert "/etc/passwd" in envelope["error"]["message"]

        status, body = _http(
            "POST", bound_host, bound_port,
            "/.well-known/obscura/tools/dial_evil",
            body=b'{"args":{}}',
        )
        envelope = json.loads(body)
        assert envelope["ok"] is False
        assert envelope["error"]["code"] == "sandbox"
        assert "203.0.113.5" in envelope["error"]["message"]

        kinds = [e.kind for e in sink.events()]
        assert "sandbox.violation" in kinds
        violations = [e for e in sink.events() if e.kind == "sandbox.violation"]
        categories = sorted({v.payload["category"] for v in violations})
        assert "fs_read" in categories
        assert "network" in categories
    finally:
        Sandbox.uninstall()
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass
        try:
            listener.close()
        except Exception:
            pass
        if isinstance(server_thread, threading.Thread):
            server_thread.join(timeout=2)
