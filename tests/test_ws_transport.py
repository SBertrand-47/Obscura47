"""Integration tests for the WebSocket transport layer."""
import json
import threading
import time
import socket
import pytest

from src.core.encryptions import ecc_generate_keypair
from src.core.ws_transport import WSServer, WSClient


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


@pytest.fixture
def server_setup():
    """Start a WSServer on a free port and return (server, port, received_frames)."""
    priv, pub = ecc_generate_keypair()
    port = _free_port()
    received: list[str] = []

    def on_frame(msg):
        received.append(msg)

    server = WSServer("127.0.0.1", port, priv, pub, on_frame)
    server.start()
    assert _wait_for_port(port), f"WSServer did not open port {port}"

    yield server, port, received, (priv, pub)

    server.stop()


@pytest.fixture
def client_keys():
    priv, pub = ecc_generate_keypair()
    return priv, pub


class TestWSServerClient:
    def test_auth_and_frame_delivery(self, server_setup, client_keys):
        server, port, received, _ = server_setup
        priv, pub = client_keys

        client = WSClient(priv, pub)
        try:
            ok = client.send_frame("127.0.0.1", port, json.dumps({"hello": "world"}))
            assert ok is True

            # Give the server a moment to dispatch
            deadline = time.time() + 2.0
            while time.time() < deadline and not received:
                time.sleep(0.05)
            assert len(received) == 1
            assert json.loads(received[0]) == {"hello": "world"}
        finally:
            client.close_all()

    def test_multiple_frames_same_connection(self, server_setup, client_keys):
        server, port, received, _ = server_setup
        priv, pub = client_keys

        client = WSClient(priv, pub)
        try:
            for i in range(5):
                assert client.send_frame("127.0.0.1", port, json.dumps({"n": i})) is True

            deadline = time.time() + 2.0
            while time.time() < deadline and len(received) < 5:
                time.sleep(0.05)
            assert len(received) == 5
            nums = sorted(json.loads(m)["n"] for m in received)
            assert nums == [0, 1, 2, 3, 4]

            # Connection should be reused (only one entry in the pool)
            assert len(client._connections) == 1
        finally:
            client.close_all()

    def test_send_to_unreachable_host_fails(self, client_keys):
        priv, pub = client_keys
        client = WSClient(priv, pub)
        try:
            bogus_port = _free_port()  # free ≠ listening
            ok = client.send_frame("127.0.0.1", bogus_port, json.dumps({"x": 1}))
            assert ok is False
        finally:
            client.close_all()

    def test_close_connection(self, server_setup, client_keys):
        server, port, received, _ = server_setup
        priv, pub = client_keys

        client = WSClient(priv, pub)
        try:
            assert client.send_frame("127.0.0.1", port, json.dumps({"a": 1})) is True
            assert ("127.0.0.1", port, False) in client._connections

            client.close_connection("127.0.0.1", port)
            # Give event loop a tick to process the close
            time.sleep(0.1)
            assert ("127.0.0.1", port, False) not in client._connections
        finally:
            client.close_all()

    def test_reconnect_after_drop(self, server_setup, client_keys):
        """After closing a connection, the next send should auto-reconnect."""
        server, port, received, _ = server_setup
        priv, pub = client_keys

        client = WSClient(priv, pub)
        try:
            assert client.send_frame("127.0.0.1", port, json.dumps({"first": 1})) is True
            client.close_connection("127.0.0.1", port)
            time.sleep(0.1)

            # Next send should succeed via auto-reconnect
            assert client.send_frame("127.0.0.1", port, json.dumps({"second": 2})) is True

            deadline = time.time() + 2.0
            while time.time() < deadline and len(received) < 2:
                time.sleep(0.05)
            assert len(received) == 2
        finally:
            client.close_all()
