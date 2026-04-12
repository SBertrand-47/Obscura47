"""
End-to-end smoke test for Obscura47.

Spins up on localhost:
    - a local echo TCP server (the origin)
    - one ObscuraNode (relay / pinned guard)
    - one ExitNode
    - the proxy, with peers injected directly (no registry, no multicast)

Then pushes an HTTP CONNECT request through the proxy to the echo server and
verifies the bytes round-trip. This exercises the full stack end-to-end:
route building + guard pinning + onion layering + WebSocket transport +
tunnel data frames + return path.

Excluded from the default `pytest tests/` run because it spawns background
threads and binds real sockets. Run explicitly with:

    pytest tests/integration -m integration
"""
import os
import socket
import sys
import tempfile
import threading
import time

import pytest

pytestmark = pytest.mark.integration


# Ports chosen well above the usual 5k/6k/9k defaults so a background dev
# instance of Obscura47 on the same machine doesn't collide with the test.
NODE_PORT = 15001
NODE_WS_PORT = 15002
EXIT_PORT = 16000
EXIT_WS_PORT = 16001
PROXY_PORT = 19047
PROXY_RESP_PORT = 19051
PROXY_WS_RESP_PORT = 19052
ECHO_PORT = 18080


def _start_echo_server(host: str = "127.0.0.1", port: int = ECHO_PORT) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
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
    """Route all persistent state into a tmp dir and disable external lookups."""
    monkeypatch.setenv("OBSCURA_GUARD_PATH", str(tmp_path / "guards.json"))
    monkeypatch.setenv("OBSCURA_NODE_KEY_PATH", str(tmp_path / "node.pem"))
    monkeypatch.setenv("OBSCURA_EXIT_KEY_PATH", str(tmp_path / "exit.pem"))
    # Unreachable registry — internet discovery should tolerate its absence
    monkeypatch.setenv("OBSCURA_REGISTRY_URL", "http://127.0.0.1:1")
    # Stretch the multicast sweep interval so it doesn't spam during the test
    monkeypatch.setenv("OBSCURA_DISCOVERY_INTERVAL", "3600")
    # Pin the ports the test expects
    monkeypatch.setenv("OBSCURA_PROXY_PORT", str(PROXY_PORT))
    monkeypatch.setenv("OBSCURA_NODE_LISTEN_PORT", str(NODE_PORT))
    monkeypatch.setenv("OBSCURA_EXIT_LISTEN_PORT", str(EXIT_PORT))
    monkeypatch.setenv("OBSCURA_NODE_WS_PORT", str(NODE_WS_PORT))
    monkeypatch.setenv("OBSCURA_EXIT_WS_PORT", str(EXIT_WS_PORT))
    monkeypatch.setenv("OBSCURA_PROXY_WS_RESP_PORT", str(PROXY_WS_RESP_PORT))
    monkeypatch.setenv("OBSCURA_PROXY_RESP_PORT", str(PROXY_RESP_PORT))
    # Test echo server runs on 127.0.0.1 — allow private IPs for testing
    monkeypatch.setenv("OBSCURA_EXIT_DENY_PRIVATE_IPS", "false")
    yield


def test_end_to_end_tunnel_round_trip(isolated_env):
    """Client -> proxy -> guard -> exit -> origin -> back. Full stack."""
    # Import after env vars are set so config.py picks them up.
    # These imports are intentionally inside the test: at module-import time
    # they would bind the default ports.
    from src.core import proxy as proxy_mod
    from src.core.exit_node import ExitNode
    from src.core.node import ObscuraNode

    echo_sock = _start_echo_server(port=ECHO_PORT)
    try:
        # Start relay + exit
        node = ObscuraNode(port=NODE_PORT)
        node.run()
        exit_node = ExitNode(port=EXIT_PORT)
        threading.Thread(target=exit_node.start_server, daemon=True).start()

        assert _wait_for_port("127.0.0.1", NODE_PORT, timeout=5.0), "relay TCP never came up"
        assert _wait_for_port("127.0.0.1", EXIT_PORT, timeout=5.0), "exit TCP never came up"

        # Inject peers directly — bypass registry + multicast for determinism.
        # `ts` is required or the internet-discovery sweeper purges the entry
        # the first time it runs.
        now = time.time()
        proxy_mod.relay_peers[:] = [{
            "host": "127.0.0.1",
            "port": NODE_PORT,
            "pub": node.pub_pem,
            "ws_port": NODE_WS_PORT,
            "ts": now,
        }]
        proxy_mod.exit_peers[:] = [{
            "host": "127.0.0.1",
            "port": EXIT_PORT,
            "pub": exit_node.pub_pem,
            "ws_port": EXIT_WS_PORT,
            "ts": now,
        }]

        threading.Thread(target=proxy_mod.start_proxy, daemon=True).start()
        assert _wait_for_port("127.0.0.1", PROXY_PORT, timeout=5.0), "proxy never came up"

        # HTTP CONNECT the echo server through the proxy
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10.0)
        client.connect(("127.0.0.1", PROXY_PORT))
        req = (
            f"CONNECT 127.0.0.1:{ECHO_PORT} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{ECHO_PORT}\r\n"
            "\r\n"
        ).encode()
        client.sendall(req)
        resp = client.recv(4096).decode(errors="ignore")
        assert "200" in resp, f"CONNECT did not return 200: {resp!r}"

        # Push a payload through the tunnel and read it back from the echo
        payload = b"ping-obscura47-smoke"
        client.sendall(payload)

        got = b""
        deadline = time.time() + 10
        while len(got) < len(payload) and time.time() < deadline:
            try:
                chunk = client.recv(len(payload) - len(got))
            except socket.timeout:
                break
            if not chunk:
                break
            got += chunk

        try:
            client.close()
        except Exception:
            pass

        assert got == payload, f"echo mismatch: {got!r} != {payload!r}"
    finally:
        try:
            echo_sock.close()
        except Exception:
            pass
