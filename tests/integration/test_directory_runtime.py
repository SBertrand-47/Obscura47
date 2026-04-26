"""End-to-end smoke test for the directory discovery flow over `.obscura`.

Brings up:
    - three real relay nodes (intro / rendezvous / middle)
    - one hidden service that publishes ``/.well-known/obscura.json``
    - one directory hidden service

Then registers the site with the directory through real hidden-service
circuits and verifies ``register``, ``list``, and ``get`` all work,
including the directory's server-side manifest fetch of the site.

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


INTRO_PORT = 15501
INTRO_WS_PORT = 15502
RV_PORT = 15511
RV_WS_PORT = 15512
MIDDLE_PORT = 15521
MIDDLE_WS_PORT = 15522
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


def test_directory_runtime_registers_manifest_backed_site(isolated_env, monkeypatch, tmp_path):
    from src.agent.app import AgentApp, Response
    from src.agent.directory import SITE_MANIFEST_PATH, build_directory_app
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

    site_app = AgentApp()
    site_holder: dict[str, AgentRuntime] = {}
    client_priv, client_pub = ecc_generate_keypair()

    @site_app.get("/")
    def _index(_req):
        return Response(200, {"site": "alpha"})

    @site_app.get(r"/\.well-known/obscura\.json")
    def _manifest(_req):
        runtime = site_holder["runtime"]
        return Response(
            200,
            {
                "protocol": "obscura.site/1",
                "address": runtime.address,
                "title": "Alpha",
                "description": "Integration test site",
                "tags": ["blog", "test"],
                },
            )

    client_sessions: dict[str, dict] = {}
    sessions_lock = threading.Lock()

    def owned_by_host(host, req_id: str) -> bool:
        if req_id in host._intro_circuits:
            return True
        with host._sessions_lock:
            return req_id in host._sessions

    def client_reverse_handler(frame: dict):
        encrypted = frame.get("encrypted_response")
        if not encrypted:
            return
        inner_json = onion_decrypt_with_priv(client_priv, encrypted)
        if not inner_json:
            return
        inner = json.loads(inner_json)
        req_id = inner.get("request_id", "")
        typ = inner.get("type")
        if typ == "rv_ready":
            rv_mod.notify_rv_ready(req_id)
            return

        req_id = frame.get("request_id", "")
        with sessions_lock:
            session = client_sessions.get(req_id)
        if not session:
            return
        if typ == "hs_data":
            sealed = inner.get("chunk", "")
            unsealed = onion_decrypt_with_priv(client_priv, sealed)
            if unsealed is None:
                return
            session["chunks"].append(base64.b64decode(unsealed))
        elif typ == "hs_close":
            session["closed"].set()

    def dispatch(frame):
        req_id = frame.get("request_id", "")
        if owned_by_host(site_runtime._host, req_id):
            site_runtime._host._on_tcp_reverse(frame)
        elif owned_by_host(directory_runtime._host, req_id):
            directory_runtime._host._on_tcp_reverse(frame)
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

    def obscura_http_request(
        addr: str,
        request_bytes: bytes,
        *,
        sentinel: bytes,
        timeout: float = 10.0,
    ) -> bytes:
        dialed = rv_mod.dial_hidden_service(addr, client_pub, peers=all_peers)
        assert dialed is not None, f"dial_hidden_service returned None for {addr}"
        route, request_id, service_pub = dialed
        with sessions_lock:
            client_sessions[request_id] = {
                "chunks": [],
                "closed": threading.Event(),
            }
        try:
            time.sleep(0.2)
            sealed = onion_encrypt_for_peer(
                service_pub, base64.b64encode(request_bytes).decode(),
            )
            rv_mod.send_hs_chunk(route, request_id, sealed)

            deadline = time.time() + timeout
            got = b""
            while time.time() < deadline:
                with sessions_lock:
                    got = b"".join(client_sessions[request_id]["chunks"])
                if b"\r\n\r\n" in got and sentinel in got:
                    break
                time.sleep(0.05)
            assert b"\r\n\r\n" in got, (
                f"never received complete HTTP response from {addr}: {got!r}"
            )
            return got
        finally:
            rv_mod.close_hs(route, request_id)
            with sessions_lock:
                client_sessions.pop(request_id, None)

    def fetch_manifest_over_obscura(address: str) -> dict:
        req = (
            f"GET {SITE_MANIFEST_PATH} HTTP/1.1\r\n"
            f"Host: {address}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        got = obscura_http_request(address, req, sentinel=b"protocol")
        _, _, body = got.partition(b"\r\n\r\n")
        body = body[: body.rfind(b"}") + 1] if b"}" in body else body
        return json.loads(body)

    def call_directory_tool(name: str, args: dict, *, sentinel: bytes) -> dict:
        payload = json.dumps({"args": args}).encode()
        req = (
            f"POST /.well-known/obscura/tools/{name} HTTP/1.1\r\n"
            f"Host: {directory_runtime.address}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii") + payload
        got = obscura_http_request(directory_runtime.address, req, sentinel=sentinel)
        _, _, body = got.partition(b"\r\n\r\n")
        body = body[: body.rfind(b"}") + 1] if b"}" in body else body
        return json.loads(body)

    site_runtime = AgentRuntime(
        name="alpha-site",
        key_path=str(tmp_path / "site.pem"),
        app=site_app,
    )
    directory_app, directory_tools = build_directory_app(
        state_path=str(tmp_path / "directory.json"),
        manifest_fetcher=fetch_manifest_over_obscura,
    )
    directory_runtime = AgentRuntime(
        name="directory",
        key_path=str(tmp_path / "directory.pem"),
        app=directory_app,
        tools=directory_tools,
    )

    try:
        assert site_runtime.start(peers=[intro_peer]), "site runtime failed to start"
        site_holder["runtime"] = site_runtime
        assert directory_runtime.start(peers=[intro_peer]), "directory runtime failed to start"

        assert site_runtime._host is not None
        assert directory_runtime._host is not None
        site_runtime._host._relay_pool = all_peers
        directory_runtime._host._relay_pool = all_peers
        site_runtime._host.ws_client.on_receive = ws_dispatch
        directory_runtime._host.ws_client.on_receive = ws_dispatch
        set_reverse_frame_callback(dispatch)
        set_proxy_ws_client(site_runtime._host.ws_client)

        time.sleep(0.5)

        register_envelope = call_directory_tool(
            "register",
            {"address": site_runtime.address},
            sentinel=b"Alpha",
        )
        assert register_envelope["ok"] is True
        registered = register_envelope["result"]
        assert registered["address"] == site_runtime.address
        assert registered["title"] == "Alpha"
        assert registered["description"] == "Integration test site"
        assert registered["tags"] == ["blog", "test"]

        get_envelope = call_directory_tool(
            "get",
            {"address": site_runtime.address},
            sentinel=site_runtime.address.encode(),
        )
        assert get_envelope["ok"] is True
        listing = get_envelope["result"]
        assert listing["address"] == site_runtime.address
        assert listing["title"] == "Alpha"

        list_envelope = call_directory_tool(
            "list",
            {"query": "alpha", "limit": 10},
            sentinel=site_runtime.address.encode(),
        )
        assert list_envelope["ok"] is True
        search = list_envelope["result"]
        assert search["count"] == 1
        assert search["total"] == 1
        assert search["listings"][0]["address"] == site_runtime.address
    finally:
        try:
            site_runtime.stop()
        except Exception:
            pass
        try:
            directory_runtime.stop()
        except Exception:
            pass
