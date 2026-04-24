"""End-to-end smoke test for the `.obscura` hidden-service stack.

Spins up on localhost:
    - a local echo TCP server (the agent's hosted service)
    - one ObscuraNode (relay / meeting point)
    - a HiddenServiceHost pointed at the echo server
    - a minimal in-process client that emulates the proxy's HS-dial path:
      calls rendezvous.dial_hidden_service, pumps bytes, decrypts reverse
      frames with an ephemeral client keypair.

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


NODE_PORT = 15101
NODE_WS_PORT = 15102
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
    monkeypatch.setenv("OBSCURA_NODE_LISTEN_PORT", str(NODE_PORT))
    monkeypatch.setenv("OBSCURA_NODE_WS_PORT", str(NODE_WS_PORT))
    yield


def test_hidden_service_round_trip(isolated_env, monkeypatch, tmp_path):
    from src.core import hidden_service as hs_mod
    from src.core import rendezvous as rv_mod
    from src.core.hidden_service import HiddenServiceHost
    from src.core.node import ObscuraNode
    from src.core.encryptions import (
        ecc_generate_keypair,
        onion_decrypt_with_priv,
        onion_encrypt_for_peer,
    )
    from src.core.router import set_proxy_ws_client, set_reverse_frame_callback
    from src.utils.onion_addr import verify_descriptor

    # ── In-memory descriptor registry ─────────────────────────────
    store: dict[str, dict] = {}

    def fake_publish(self):
        if not self.meeting_point:
            return False
        from src.utils.onion_addr import build_descriptor, DESCRIPTOR_TTL
        intro = [{
            "host": self.meeting_point.get("host"),
            "port": self.meeting_point.get("port"),
            "ws_port": self.meeting_point.get("ws_port"),
            "pub": self.meeting_point.get("pub"),
        }]
        store[self.address] = build_descriptor(
            self.priv, self.pub_pem, port=self.target_port,
            intro_points=intro, ttl=DESCRIPTOR_TTL,
        )
        return True

    def fake_fetch(addr):
        desc = store.get(addr)
        return desc if desc and verify_descriptor(desc) else None

    monkeypatch.setattr(HiddenServiceHost, "publish_descriptor", fake_publish)
    monkeypatch.setattr(rv_mod, "fetch_descriptor", fake_fetch)

    echo_sock = _start_echo_server(ECHO_PORT)
    try:
        # 1. Start meeting-point relay.
        node = ObscuraNode(port=NODE_PORT)
        node.run()
        assert _wait_for_port("127.0.0.1", NODE_PORT, 5.0)

        node_peer = {
            "host": "127.0.0.1",
            "port": NODE_PORT,
            "pub": node.pub_pem,
            "ws_port": NODE_WS_PORT,
            "role": "node",
            "ts": time.time(),
        }

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
            if typ == "hs_data":
                sealed = inner.get("chunk", "")
                # Host sealed the chunk for our client keypair; meeting
                # point only saw ciphertext.
                unsealed = onion_decrypt_with_priv(client_priv, sealed)
                if unsealed is None:
                    return
                received_chunks.append(base64.b64decode(unsealed))
            elif typ == "hs_close":
                received_close.set()

        # Dispatcher: route inbound reverse frames to host or client based on
        # the outer request_id (host's intro circuit vs. client's circuit).
        def dispatch(frame):
            req_id = frame.get("request_id", "")
            if req_id == host.intro_request_id:
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

        # 4. Establish + publish.
        assert host.establish(peers=[node_peer])
        assert host.publish_descriptor()
        time.sleep(0.3)

        # 5. Dial the hidden service using rendezvous functions.
        dialed = rv_mod.dial_hidden_service(host.address, client_pub)
        assert dialed is not None, "dial_hidden_service returned None"
        route, request_id, service_pub = dialed
        assert service_pub == host.pub_pem
        time.sleep(0.3)  # let hs_incoming propagate to host + local connect

        # 6. Send data through the circuit, sealed for the service pubkey so
        # the meeting point only relays ciphertext.
        payload = b"ping-obscura-hs-smoke"
        sealed_up = onion_encrypt_for_peer(
            service_pub, base64.b64encode(payload).decode()
        )
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
