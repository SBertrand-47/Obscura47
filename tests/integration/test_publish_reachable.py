"""A published `.obscura` site is reachable on obscura nodes, and tracked.

This is the product loop end to end, with NOTHING stubbed in the transport:

    1. real ObscuraNodes act as intro + rendezvous relays;
    2. a real HiddenServiceHost establishes intro circuits and publishes a
       real, signed descriptor to a REAL registry server (a uvicorn-hosted
       ``registry_server.app`` on a loopback port) over real HTTP;
    3. the descriptor is fetched back from that registry and verified;
    4. a client dials the service through the rendezvous machinery and gets
       the hosted bytes back - i.e. the site is reachable on the nodes;
    5. the publication ledger records the publish and the REACHABLE verdict,
       so the agent can answer "what did I publish, and is it up?".

Unlike ``test_hs_smoke`` (which uses an in-memory descriptor registry), the
descriptor here makes a real round-trip through the registry's
``/hs/descriptor`` endpoints - the same path a globally-deployed host uses.
The single remaining in-process concession is the reverse-frame dispatcher
(host and client share one process), documented in ``test_hs_smoke``.

Individual-run integration test (binds sockets). Run with:

    pytest tests/integration/test_publish_reachable.py -m integration
"""
import base64
import json
import socket
import threading
import time

import pytest

pytestmark = pytest.mark.integration

INTRO_PORT = 15401
INTRO_WS_PORT = 15402
RV_PORT = 15411
RV_WS_PORT = 15412
MIDDLE_PORT = 15421
MIDDLE_WS_PORT = 15422
ECHO_PORT = 18480
REGISTRY_PORT = 18471


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


def _wait_for_port(host: str, port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _start_registry(port: int, db_path: str):
    """Run the real registry_server.app on a loopback port in a thread."""
    import importlib
    import os

    os.environ["OBSCURA_REGISTRY_DB_PATH"] = db_path
    os.environ["OBSCURA_REGISTRY_ADMIN_KEY"] = "test-admin-key"
    os.environ["OBSCURA_REGISTRY_RATE_LIMIT"] = "100000"

    import registry_server
    importlib.reload(registry_server)

    import uvicorn

    config = uvicorn.Config(
        registry_server.app, host="127.0.0.1", port=port, log_level="warning"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    assert _wait_for_port("127.0.0.1", port), "registry never came up"
    return server, thread


@pytest.fixture
def isolated_env(monkeypatch, tmp_path):
    monkeypatch.setenv("OBSCURA_GUARD_PATH", str(tmp_path / "guards.json"))
    monkeypatch.setenv("OBSCURA_NODE_KEY_PATH", str(tmp_path / "node.pem"))
    monkeypatch.setenv("OBSCURA_DISCOVERY_INTERVAL", "3600")
    yield


def test_published_site_is_reachable_and_tracked(isolated_env, monkeypatch, tmp_path):
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
    from src.utils import publications
    from src.utils.onion_addr import verify_descriptor

    # --- a real registry server on loopback; point the stack at it ---------
    registry_url = f"http://127.0.0.1:{REGISTRY_PORT}"
    server, _thread = _start_registry(REGISTRY_PORT, str(tmp_path / "registry.db"))
    monkeypatch.setattr(hs_mod, "REGISTRY_URL", registry_url)
    monkeypatch.setattr(rv_mod, "REGISTRY_URL", registry_url)

    ledger_path = str(tmp_path / "publications.json")
    echo_sock = _start_echo_server(ECHO_PORT)
    try:
        # --- three real relay nodes (intro / rendezvous / middle) ----------
        from src.core import node as node_mod
        monkeypatch.setattr(node_mod, "NODE_WS_PORT", INTRO_WS_PORT)
        intro_node = ObscuraNode(port=INTRO_PORT)
        intro_node.run()
        assert _wait_for_port("127.0.0.1", INTRO_PORT)

        monkeypatch.setattr(node_mod, "NODE_WS_PORT", RV_WS_PORT)
        rv_node = ObscuraNode(port=RV_PORT)
        rv_node.run()
        assert _wait_for_port("127.0.0.1", RV_PORT)

        monkeypatch.setattr(node_mod, "NODE_WS_PORT", MIDDLE_WS_PORT)
        middle_node = ObscuraNode(port=MIDDLE_PORT)
        middle_node.run()
        assert _wait_for_port("127.0.0.1", MIDDLE_PORT)

        intro_peer = {"host": "127.0.0.1", "port": INTRO_PORT, "pub": intro_node.pub_pem,
                      "ws_port": INTRO_WS_PORT, "role": "node", "ts": time.time()}
        rv_peer = {"host": "127.0.0.1", "port": RV_PORT, "pub": rv_node.pub_pem,
                   "ws_port": RV_WS_PORT, "role": "node", "ts": time.time()}
        middle_peer = {"host": "127.0.0.1", "port": MIDDLE_PORT, "pub": middle_node.pub_pem,
                       "ws_port": MIDDLE_WS_PORT, "role": "node", "ts": time.time()}
        all_peers = [intro_peer, rv_peer, middle_peer]

        # --- the host: serve the echo server as a .obscura site ------------
        host = HiddenServiceHost(
            target_host="127.0.0.1", target_port=ECHO_PORT,
            key_path=str(tmp_path / "hs.pem"),
        )

        # Minimal in-process client (collects decrypted inner payloads).
        client_priv, client_pub = ecc_generate_keypair()
        received_chunks: list[bytes] = []

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
                if unsealed is not None:
                    received_chunks.append(base64.b64decode(unsealed))

        def owned_by_host(req_id: str) -> bool:
            if req_id in host._intro_circuits:
                return True
            with host._intro_acks_lock:
                if req_id in host._intro_acks:
                    return True
            with host._sessions_lock:
                return req_id in host._sessions

        def dispatch(frame):
            if owned_by_host(frame.get("request_id", "")):
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

        # --- establish intros and publish a REAL descriptor to the registry-
        assert host.establish(peers=[intro_peer])
        host._relay_pool = all_peers
        assert host.publish_descriptor(), "real publish to the registry failed"

        # The agent records what it published.
        publications.record_publish(
            host.address, name="echo-site", target=f"127.0.0.1:{ECHO_PORT}",
            title="Echo", path=ledger_path,
        )

        # --- the descriptor made a real round-trip through the registry ----
        fetched = rv_mod.fetch_descriptor(host.address)
        assert fetched is not None, "registry did not return the descriptor"
        assert verify_descriptor(fetched)
        assert fetched["addr"] == host.address
        time.sleep(0.3)

        # --- a client dials the site and gets the hosted bytes back --------
        dialed = rv_mod.dial_hidden_service(host.address, client_pub, peers=all_peers)
        assert dialed is not None, "dial_hidden_service returned None"
        route, request_id, service_pub = dialed
        assert service_pub == host.pub_pem
        time.sleep(0.3)

        payload = b"reachable-on-the-nodes"
        sealed_up = onion_encrypt_for_peer(service_pub, base64.b64encode(payload).decode())
        rv_mod.send_hs_chunk(route, request_id, sealed_up)

        deadline = time.time() + 10
        got = b""
        while len(got) < len(payload) and time.time() < deadline:
            got = b"".join(received_chunks)
            if len(got) < len(payload):
                time.sleep(0.05)
        assert got == payload, f"site not reachable: {got!r} != {payload!r}"
        rv_mod.close_hs(route, request_id)

        # --- the agent records that the site is reachable ------------------
        # The dial above proves reachability on the nodes; stamp it the same
        # way `host status` would after a successful probe.
        publications.record_reachability(host.address, True, path=ledger_path)
        rec = publications.get(host.address, path=ledger_path)
        assert rec is not None
        assert rec.name == "echo-site"
        assert rec.reachable is True
        assert rec.last_reachable_at is not None
    finally:
        try:
            host.delete_descriptor()
        except Exception:
            pass
        try:
            echo_sock.close()
        except Exception:
            pass
        server.should_exit = True
