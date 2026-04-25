"""End-to-end smoke test for the `.obscura` hidden-service stack.

Spins up on localhost:
    - a local echo TCP server (the agent's hosted service)
    - two ObscuraNodes: one acting as intro point, one as rendezvous
    - a HiddenServiceHost pointed at the echo server
    - a minimal in-process client that emulates the proxy's HS-dial path.

The test deliberately skips the HTTP CONNECT proxy to keep the
reverse-frame global-callbacks unambiguous. A separate proxy-level test
would run the proxy in its own process.

Run with:  pytest tests/integration -m integration
"""
import base64
import json
import socket
import threading
import time

import pytest

pytestmark = pytest.mark.integration


INTRO_PORT = 15101
INTRO_WS_PORT = 15102
RV_PORT = 15111
RV_WS_PORT = 15112
MIDDLE_PORT = 15121
MIDDLE_WS_PORT = 15122
ECHO_PORT = 18180


def _start_echo_server(port: int) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)

    def _accept():
        while True:
            try:
                conn, _ = srv.accept()
            except Exception:
                return
            threading.Thread(target=_echo_one, args=(conn,), daemon=True).start()

    def _echo_one(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except Exception:
            pass
        finally:
            conn.close()

    threading.Thread(target=_accept, daemon=True).start()
    return srv


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


def test_hidden_service_round_trip(isolated_env, monkeypatch, tmp_path):
    from src.core import rendezvous as rv_mod
    from src.core.hidden_service import HiddenServiceHost
    from src.core.node import ObscuraNode
    from src.core.encryptions import (
        ecc_generate_keypair,
        onion_decrypt_with_priv,
        onion_encrypt_for_peer,
    )
    from src.core.router import set_proxy_ws_client, set_reverse_frame_callback
    from src.utils.onion_addr import verify_descriptor, build_descriptor, DESCRIPTOR_TTL

    # ── In-memory descriptor registry ─────────────────────────────
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

    echo_sock = _start_echo_server(ECHO_PORT)
    try:
        # 1. Start three nodes — intro, rendezvous, and a middle relay
        # used to pad multi-hop HS circuits. Each ObscuraNode binds its
        # WS server at construction, so we patch the module-level
        # NODE_WS_PORT between constructions to avoid port collisions.
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

        # 2. Start hidden-service host.
        host = HiddenServiceHost(
            target_host="127.0.0.1",
            target_port=ECHO_PORT,
            key_path=str(tmp_path / "hs.pem"),
        )

        # 3. Minimal HS client — collects decrypted inner payloads.
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

        # Dispatcher: route inbound reverse frames to host or client based
        # on the outer request_id. The host owns all intro-circuit ids and
        # all rv-join ids it creates. Everything else belongs to the client.
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
            if isinstance(frame, dict) and frame.get("type") in ("reverse_data", "reverse_close"):
                dispatch(frame)

        host.ws_client.on_receive = ws_dispatch
        set_reverse_frame_callback(dispatch)
        set_proxy_ws_client(host.ws_client)

        # 4. Establish intros + publish descriptor. We only want
        # intro_peer acting as an intro point here; the other two are
        # available as middle relays for multi-hop padding.
        assert host.establish(peers=[intro_peer])
        host._relay_pool = all_peers
        assert host.publish_descriptor()
        time.sleep(0.3)

        # 5. Dial the hidden service — rv must be distinct from intro.
        dialed = rv_mod.dial_hidden_service(
            host.address, client_pub, peers=all_peers)
        assert dialed is not None, "dial_hidden_service returned None"
        route, request_id, service_pub = dialed
        assert service_pub == host.pub_pem
        # Multi-hop circuit: at least one middle relay before the terminal.
        # The terminal must be whichever non-intro relay was chosen as rv.
        assert len(route) >= 2, f"expected multi-hop rv circuit, got {route!r}"
        assert route[-1]["port"] != INTRO_PORT
        rv_terminal_port = route[-1]["port"]
        time.sleep(0.3)

        # 6. Send sealed data through the rendezvous circuit.
        payload = b"ping-obscura-hs-smoke"
        sealed_up = onion_encrypt_for_peer(
            service_pub, base64.b64encode(payload).decode())
        rv_mod.send_hs_chunk(route, request_id, sealed_up)

        # 7. Wait for echo reply to traverse back.
        deadline = time.time() + 10
        got = b""
        while len(got) < len(payload) and time.time() < deadline:
            got = b"".join(received_chunks)
            if len(got) < len(payload):
                time.sleep(0.05)
        assert got == payload, f"echo mismatch: {got!r} != {payload!r}"

        rv_mod.close_hs(route, request_id)
    finally:
        try:
            echo_sock.close()
        except Exception:
            pass
