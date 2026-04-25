"""End-to-end smoke test for the agent runtime over `.obscura`.

Brings up an AgentRuntime with a custom HTTP app, real ObscuraNode
relays for the rendezvous + intro + middle hops, and a minimal
in-process client that emulates the proxy's HS-dial path. Sends a raw
HTTP/1.1 request through the rendezvous circuit and verifies the
agent's JSON response comes back intact.

Run with:  pytest tests/integration -m integration
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import time

import pytest

pytestmark = pytest.mark.integration


INTRO_PORT = 15201
INTRO_WS_PORT = 15202
RV_PORT = 15211
RV_WS_PORT = 15212
MIDDLE_PORT = 15221
MIDDLE_WS_PORT = 15222


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture
def isolated_env(monkeypatch, tmp_path):
    monkeypatch.setenv("OBSCURA_GUARD_PATH", str(tmp_path / "guards.json"))
    monkeypatch.setenv("OBSCURA_NODE_KEY_PATH", str(tmp_path / "node.pem"))
    monkeypatch.setenv("OBSCURA_REGISTRY_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("OBSCURA_DISCOVERY_INTERVAL", "3600")
    yield


def test_agent_runtime_serves_http_over_obscura(isolated_env, monkeypatch, tmp_path):
    from src.agent.app import AgentApp, Response
    from src.agent.runtime import AgentRuntime
    from src.core import rendezvous as rv_mod
    from src.core.encryptions import (
        ecc_generate_keypair,
        onion_decrypt_with_priv,
        onion_encrypt_for_peer,
    )
    from src.core.hidden_service import HiddenServiceHost
    from src.core.node import ObscuraNode
    from src.core.router import set_proxy_ws_client, set_reverse_frame_callback
    from src.utils.onion_addr import (
        DESCRIPTOR_TTL,
        build_descriptor,
        verify_descriptor,
    )

    store: dict[str, dict] = {}

    def fake_publish(self):
        if not self._intro_peers:
            return False
        intros = [{
            "host": p.get("host"), "port": p.get("port"),
            "ws_port": p.get("ws_port"), "pub": p.get("pub"),
        } for p in self._intro_peers]
        store[self.address] = build_descriptor(
            self.priv, self.pub_pem, port=self.target_port,
            intro_points=intros, ttl=DESCRIPTOR_TTL,
        )
        return True

    def fake_fetch(addr):
        desc = store.get(addr)
        return desc if desc and verify_descriptor(desc) else None

    monkeypatch.setattr(HiddenServiceHost, "publish_descriptor", fake_publish)
    monkeypatch.setattr(rv_mod, "fetch_descriptor", fake_fetch)

    from src.core import node as node_mod

    monkeypatch.setattr(node_mod, "NODE_WS_PORT", INTRO_WS_PORT)
    intro_node = ObscuraNode(port=INTRO_PORT)
    intro_node.run()
    assert _wait_for_port("127.0.0.1", INTRO_PORT, 5.0)

    monkeypatch.setattr(node_mod, "NODE_WS_PORT", RV_WS_PORT)
    rv_node = ObscuraNode(port=RV_PORT)
    rv_node.run()
    assert _wait_for_port("127.0.0.1", RV_PORT, 5.0)

    monkeypatch.setattr(node_mod, "NODE_WS_PORT", MIDDLE_WS_PORT)
    middle_node = ObscuraNode(port=MIDDLE_PORT)
    middle_node.run()
    assert _wait_for_port("127.0.0.1", MIDDLE_PORT, 5.0)

    intro_peer = {
        "host": "127.0.0.1", "port": INTRO_PORT, "pub": intro_node.pub_pem,
        "ws_port": INTRO_WS_PORT, "role": "node", "ts": time.time(),
    }
    rv_peer = {
        "host": "127.0.0.1", "port": RV_PORT, "pub": rv_node.pub_pem,
        "ws_port": RV_WS_PORT, "role": "node", "ts": time.time(),
    }
    middle_peer = {
        "host": "127.0.0.1", "port": MIDDLE_PORT, "pub": middle_node.pub_pem,
        "ws_port": MIDDLE_WS_PORT, "role": "node", "ts": time.time(),
    }
    all_peers = [intro_peer, rv_peer, middle_peer]

    from src.agent.tools import DEFAULT_PREFIX, PROTOCOL_VERSION, ToolRegistry

    app = AgentApp()

    @app.get("/ping")
    def _ping(_req):
        return Response(200, {"pong": True, "agent": "smoketest"})

    @app.post("/echo")
    def _echo(req):
        return Response(200, {"received": req.json()})

    tools = ToolRegistry()

    @tools.tool("greet", description="say hi")
    def _greet(args, _req):
        return {"hello": args.get("name", "world")}

    @tools.tool("whoami", description="echo the authenticated caller")
    def _whoami(_args, req):
        return {
            "caller_pub": req.caller_pub,
            "caller_fingerprint": req.caller_fingerprint,
        }

    runtime = AgentRuntime(
        name="smoketest",
        key_path=str(tmp_path / "agent.pem"),
        app=app,
        tools=tools,
    )
    try:
        assert runtime.start(peers=[intro_peer]), "AgentRuntime.start failed"
        host = runtime._host
        assert host is not None
        host._relay_pool = all_peers

        client_priv, client_pub = ecc_generate_keypair()
        received_chunks: list[bytes] = []
        received_close = threading.Event()

        def client_reverse_handler(frame: dict):
            encrypted = frame.get("encrypted_response")
            if not encrypted:
                return
            inner_json = onion_decrypt_with_priv(client_priv, encrypted)
            if not inner_json:
                return
            inner = json.loads(inner_json)
            typ = inner.get("type")
            req_id = inner.get("request_id", "")
            if typ == "rv_ready":
                rv_mod.notify_rv_ready(req_id)
            elif typ == "hs_data":
                sealed = inner.get("chunk", "")
                unsealed = onion_decrypt_with_priv(client_priv, sealed)
                if unsealed is None:
                    return
                received_chunks.append(base64.b64decode(unsealed))
            elif typ == "hs_close":
                received_close.set()

        def owned_by_host(req_id: str) -> bool:
            if req_id in host._intro_circuits:
                return True
            with host._sessions_lock:
                return req_id in host._sessions

        def dispatch(frame):
            req_id = frame.get("request_id", "")
            if owned_by_host(req_id):
                host._on_tcp_reverse(frame)
            else:
                client_reverse_handler(frame)

        def ws_dispatch(message):
            try:
                frame = json.loads(message) if isinstance(message, str) else message
            except Exception:
                return
            if isinstance(frame, dict) and frame.get("type") in (
                "reverse_data", "reverse_close",
            ):
                dispatch(frame)

        host.ws_client.on_receive = ws_dispatch
        set_reverse_frame_callback(dispatch)
        set_proxy_ws_client(host.ws_client)

        time.sleep(0.3)

        def http_roundtrip(request_bytes: bytes, sentinel: bytes,
                           timeout: float = 10.0) -> bytes:
            received_chunks.clear()
            received_close.clear()
            dialed_local = rv_mod.dial_hidden_service(
                runtime.address, client_pub, peers=all_peers)
            assert dialed_local is not None, "dial_hidden_service returned None"
            route_local, request_id_local, service_pub_local = dialed_local
            assert service_pub_local == runtime.pub_pem
            assert len(route_local) >= 2, (
                f"expected multi-hop rv circuit, got {route_local!r}"
            )
            assert route_local[-1]["port"] != INTRO_PORT
            time.sleep(0.2)

            sealed = onion_encrypt_for_peer(
                service_pub_local,
                base64.b64encode(request_bytes).decode(),
            )
            rv_mod.send_hs_chunk(route_local, request_id_local, sealed)

            deadline = time.time() + timeout
            got_bytes = b""
            while time.time() < deadline:
                got_bytes = b"".join(received_chunks)
                if b"\r\n\r\n" in got_bytes and sentinel in got_bytes:
                    break
                time.sleep(0.05)
            rv_mod.close_hs(route_local, request_id_local)
            assert b"\r\n\r\n" in got_bytes, (
                f"never received complete HTTP response: {got_bytes!r}"
            )
            return got_bytes

        ping_req = (
            f"GET /ping HTTP/1.1\r\n"
            f"Host: {runtime.address}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        got = http_roundtrip(ping_req, sentinel=b"pong")
        head, _, body = got.partition(b"\r\n\r\n")
        assert head.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 200")
        body = body[: body.find(b"}") + 1] if b"}" in body else body
        assert json.loads(body) == {"pong": True, "agent": "smoketest"}

        manifest_req = (
            f"GET {DEFAULT_PREFIX}tools HTTP/1.1\r\n"
            f"Host: {runtime.address}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        got = http_roundtrip(manifest_req, sentinel=b"\"protocol\"")
        head, _, body = got.partition(b"\r\n\r\n")
        assert head.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 200")
        body = body[: body.rfind(b"}") + 1] if b"}" in body else body
        manifest = json.loads(body)
        assert manifest["protocol"] == PROTOCOL_VERSION
        assert any(t["name"] == "greet" for t in manifest["tools"])

        invoke_payload = json.dumps({"args": {"name": "agents"}}).encode()
        invoke_req = (
            f"POST {DEFAULT_PREFIX}tools/greet HTTP/1.1\r\n"
            f"Host: {runtime.address}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(invoke_payload)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii") + invoke_payload
        got = http_roundtrip(invoke_req, sentinel=b"\"result\"")
        head, _, body = got.partition(b"\r\n\r\n")
        assert head.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 200")
        body = body[: body.rfind(b"}") + 1] if b"}" in body else body
        envelope = json.loads(body)
        assert envelope == {"ok": True, "result": {"hello": "agents"}}

        from src.utils.identity import fingerprint_pubkey
        whoami_payload = json.dumps({"args": {}}).encode()
        whoami_req = (
            f"POST {DEFAULT_PREFIX}tools/whoami HTTP/1.1\r\n"
            f"Host: {runtime.address}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(whoami_payload)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii") + whoami_payload
        got = http_roundtrip(whoami_req, sentinel=b"\"caller_fingerprint\"")
        head, _, body = got.partition(b"\r\n\r\n")
        assert head.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 200")
        body = body[: body.rfind(b"}") + 1] if b"}" in body else body
        envelope = json.loads(body)
        assert envelope["ok"] is True
        result = envelope["result"]
        assert result["caller_pub"] == client_pub
        assert result["caller_fingerprint"] == fingerprint_pubkey(client_pub)
    finally:
        runtime.stop()
