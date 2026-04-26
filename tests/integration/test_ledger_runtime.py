"""End-to-end smoke test for the ledger service over `.obscura`.

Brings up a :class:`LedgerState` published through :class:`AgentRuntime`
on top of real ``ObscuraNode`` relays, then drives it from an
in-process client that emulates the proxy's HS-dial path. Verifies
that the authenticated caller fingerprint surfaced by the rendezvous
handshake correctly authorises mint/transfer and is recorded on the
resulting transactions.

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


INTRO_PORT = 15301
INTRO_WS_PORT = 15302
RV_PORT = 15311
RV_WS_PORT = 15312
MIDDLE_PORT = 15321
MIDDLE_WS_PORT = 15322


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


def test_ledger_runtime_authorises_via_caller_pub(isolated_env, monkeypatch, tmp_path):
    from src.agent.ledger import LedgerState, build_ledger_app
    from src.agent.runtime import AgentRuntime
    from src.agent.tools import DEFAULT_PREFIX
    from src.core import rendezvous as rv_mod
    from src.core.encryptions import (
        ecc_generate_keypair,
        onion_decrypt_with_priv,
        onion_encrypt_for_peer,
    )
    from src.core.hidden_service import HiddenServiceHost
    from src.core.node import ObscuraNode
    from src.core.router import set_proxy_ws_client, set_reverse_frame_callback
    from src.utils.identity import fingerprint_pubkey
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

    alice_priv, alice_pub = ecc_generate_keypair()
    alice_fp = fingerprint_pubkey(alice_pub)

    bob_fp = "b" * 64

    state = LedgerState(admin_fingerprint=alice_fp)
    app, tools = build_ledger_app(state)

    runtime = AgentRuntime(
        name="ledger", key_path=str(tmp_path / "ledger.pem"),
        app=app, tools=tools,
    )
    try:
        assert runtime.start(peers=[intro_peer]), "AgentRuntime.start failed"
        host = runtime._host
        assert host is not None
        host._relay_pool = all_peers

        received_chunks: list[bytes] = []
        received_close = threading.Event()

        def client_reverse_handler(frame: dict):
            encrypted = frame.get("encrypted_response")
            if not encrypted:
                return
            inner_json = onion_decrypt_with_priv(alice_priv, encrypted)
            if not inner_json:
                return
            inner = json.loads(inner_json)
            typ = inner.get("type")
            req_id = inner.get("request_id", "")
            if typ == "rv_ready":
                rv_mod.notify_rv_ready(req_id)
            elif typ == "hs_data":
                sealed = inner.get("chunk", "")
                unsealed = onion_decrypt_with_priv(alice_priv, sealed)
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
            dialed = rv_mod.dial_hidden_service(
                runtime.address, alice_pub, peers=all_peers)
            assert dialed is not None, "dial_hidden_service returned None"
            route, request_id, service_pub = dialed
            assert service_pub == runtime.pub_pem
            time.sleep(0.2)

            sealed = onion_encrypt_for_peer(
                service_pub, base64.b64encode(request_bytes).decode(),
            )
            rv_mod.send_hs_chunk(route, request_id, sealed)

            deadline = time.time() + timeout
            got = b""
            while time.time() < deadline:
                got = b"".join(received_chunks)
                if b"\r\n\r\n" in got and sentinel in got:
                    break
                time.sleep(0.05)
            rv_mod.close_hs(route, request_id)
            assert b"\r\n\r\n" in got, (
                f"never received complete HTTP response: {got!r}"
            )
            return got

        def call_tool(name: str, args: dict, sentinel: bytes) -> dict:
            payload = json.dumps({"args": args}).encode()
            req = (
                f"POST {DEFAULT_PREFIX}tools/{name} HTTP/1.1\r\n"
                f"Host: {runtime.address}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("ascii") + payload
            got = http_roundtrip(req, sentinel=sentinel)
            _, _, body = got.partition(b"\r\n\r\n")
            body = body[: body.rfind(b"}") + 1] if b"}" in body else body
            return json.loads(body)

        bal_envelope = call_tool("balance", {}, sentinel=b"\"balance\"")
        assert bal_envelope == {
            "ok": True,
            "result": {"account": alice_fp, "balance": 0},
        }

        mint_envelope = call_tool(
            "mint", {"to": alice_fp, "amount": 500, "memo": "seed"},
            sentinel=b"\"amount\"",
        )
        assert mint_envelope["ok"] is True
        assert mint_envelope["result"]["from"] is None
        assert mint_envelope["result"]["to"] == alice_fp
        assert mint_envelope["result"]["amount"] == 500

        bal_envelope = call_tool("balance", {}, sentinel=b"\"balance\"")
        assert bal_envelope["result"]["balance"] == 500

        xfer_envelope = call_tool(
            "transfer",
            {"to": bob_fp, "amount": 120, "memo": "lunch", "nonce": "tx-1"},
            sentinel=b"\"balance_after\"",
        )
        assert xfer_envelope["ok"] is True
        result = xfer_envelope["result"]
        assert result["from"] == alice_fp
        assert result["to"] == bob_fp
        assert result["amount"] == 120
        assert result["balance_after"] == 380

        history_envelope = call_tool(
            "history", {"limit": 10}, sentinel=b"\"tx_id\"",
        )
        rows = history_envelope["result"]
        assert len(rows) == 2
        assert rows[0]["nonce"] == "tx-1"
        assert rows[0]["from"] == alice_fp
        assert rows[1]["from"] is None  # mint
        assert rows[1]["to"] == alice_fp

        bob_bal_envelope = call_tool(
            "balance", {"account": bob_fp}, sentinel=b"\"balance\"",
        )
        assert bob_bal_envelope["result"]["balance"] == 120
    finally:
        runtime.stop()
