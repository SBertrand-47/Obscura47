"""Unit tests for the gateway inbound port forwarder and its config parsing.

The forwarder lets a NAT "sibling" relay become reachable at the gateway's
public IP by relaying an inbound public port to the sibling's LAN WebSocket
port. These tests cover the config parser and the byte relay itself (no real
WebSocket/registry involved - a dumb echo server stands in for the sibling).
"""

import socket
import threading
import time

import pytest

from src.utils.config import _parse_gateway_forwards, _parse_port_pool
from src.core.gateway_forward import GatewayForwarder


# --------------------------------------------------------------------------
# _parse_gateway_forwards
# --------------------------------------------------------------------------

def test_parse_single_mapping():
    assert _parse_gateway_forwards("5012:192.168.1.33:5002") == [
        (5012, "192.168.1.33", 5002)
    ]


def test_parse_multiple_mappings_and_whitespace():
    raw = " 5012:192.168.1.33:5002 , 5013:10.0.0.4:5002 "
    assert _parse_gateway_forwards(raw) == [
        (5012, "192.168.1.33", 5002),
        (5013, "10.0.0.4", 5002),
    ]


def test_parse_empty_is_empty_list():
    assert _parse_gateway_forwards("") == []
    assert _parse_gateway_forwards("   ") == []


def test_parse_skips_malformed_keeps_valid():
    # Missing target port, non-numeric port, too many fields -> all skipped;
    # the one valid entry survives.
    raw = "foo,5012:host,abc:host:5002,5013:1.2.3.4:6000:extra,7000:1.2.3.4:8000"
    assert _parse_gateway_forwards(raw) == [(7000, "1.2.3.4", 8000)]


# --------------------------------------------------------------------------
# GatewayForwarder byte relay
# --------------------------------------------------------------------------

def _free_port() -> int:
    """Reserve an ephemeral port and return it (small TOCTOU race, fine here)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _EchoServer:
    """Minimal TCP echo server standing in for the sibling's WS port."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.conns: list[socket.socket] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.sock.settimeout(0.5)
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.conns.append(conn)
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    def _echo(self, conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


def _recv_exactly(sock: socket.socket, n: int, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


@pytest.fixture
def echo():
    server = _EchoServer()
    yield server
    server.stop()


def test_forwarder_relays_bidirectionally(echo):
    listen_port = _free_port()
    fwd = GatewayForwarder(
        [(listen_port, "127.0.0.1", echo.port)], listen_host="127.0.0.1"
    )
    fwd.start()
    try:
        # Give the accept loop a moment to bind.
        deadline = time.time() + 2.0
        client = None
        while time.time() < deadline:
            try:
                client = socket.create_connection(("127.0.0.1", listen_port), timeout=1.0)
                break
            except OSError:
                time.sleep(0.05)
        assert client is not None, "forwarder never accepted a connection"

        # First chunk round-trips through forwarder -> echo -> forwarder.
        client.sendall(b"hello")
        assert _recv_exactly(client, 5) == b"hello"

        # Second chunk proves the pump loops rather than relaying once.
        client.sendall(b"world!!")
        assert _recv_exactly(client, 7) == b"world!!"
        client.close()
    finally:
        fwd.stop()


def test_forwarder_stop_closes_listener(echo):
    listen_port = _free_port()
    fwd = GatewayForwarder(
        [(listen_port, "127.0.0.1", echo.port)], listen_host="127.0.0.1"
    )
    fwd.start()
    # Wait until it is accepting.
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", listen_port), timeout=1.0).close()
            break
        except OSError:
            time.sleep(0.05)

    fwd.stop()

    # After stop(), the listen port should refuse connections (allow a moment
    # for the accept loop to wake on its timeout and close the socket).
    refused = False
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", listen_port), timeout=0.5).close()
            time.sleep(0.1)
        except OSError:
            refused = True
            break
    assert refused, "listen port still accepting after stop()"


def test_forwarder_handles_unreachable_target_without_crashing():
    # Target port is closed; the forwarder should accept, fail to connect, and
    # cleanly close the client without raising or leaving the loop dead.
    listen_port = _free_port()
    dead_target = _free_port()  # nothing listening here
    fwd = GatewayForwarder(
        [(listen_port, "127.0.0.1", dead_target)], listen_host="127.0.0.1"
    )
    fwd.start()
    try:
        deadline = time.time() + 2.0
        client = None
        while time.time() < deadline:
            try:
                client = socket.create_connection(("127.0.0.1", listen_port), timeout=1.0)
                break
            except OSError:
                time.sleep(0.05)
        assert client is not None
        # The forwarder closes the client once the target connect fails.
        client.settimeout(2.0)
        assert client.recv(16) == b""
        client.close()

        # The listener is still alive and serving subsequent connections.
        client2 = socket.create_connection(("127.0.0.1", listen_port), timeout=1.0)
        client2.close()
    finally:
        fwd.stop()


# --------------------------------------------------------------------------
# _parse_port_pool
# --------------------------------------------------------------------------

def test_parse_port_pool_range():
    assert _parse_port_pool("5012-5014") == [5012, 5013, 5014]


def test_parse_port_pool_single():
    assert _parse_port_pool("5012") == [5012]


def test_parse_port_pool_empty_and_malformed():
    assert _parse_port_pool("") == []
    assert _parse_port_pool("   ") == []
    assert _parse_port_pool("abc-def") == []
    assert _parse_port_pool("5040-5012") == []   # inverted range
    assert _parse_port_pool("0-10") == []        # below valid port range
    assert _parse_port_pool("70000") == []       # above valid port range


# --------------------------------------------------------------------------
# Dynamic pool-based add_mapping / remove_mapping
# --------------------------------------------------------------------------

def _connect_retry(port: int, timeout: float = 2.0) -> socket.socket | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=1.0)
        except OSError:
            time.sleep(0.05)
    return None


def test_add_mapping_allocates_and_relays(echo):
    pool = [_free_port(), _free_port()]
    fwd = GatewayForwarder([], listen_host="127.0.0.1", pool=pool)
    fwd.start()
    try:
        port = fwd.add_mapping("127.0.0.1", echo.port)
        assert port in pool
        client = _connect_retry(port)
        assert client is not None
        client.sendall(b"ping")
        assert _recv_exactly(client, 4) == b"ping"
        client.close()
    finally:
        fwd.stop()


def test_add_mapping_is_idempotent(echo):
    pool = [_free_port(), _free_port()]
    fwd = GatewayForwarder([], listen_host="127.0.0.1", pool=pool)
    fwd.start()
    try:
        p1 = fwd.add_mapping("127.0.0.1", echo.port)
        p2 = fwd.add_mapping("127.0.0.1", echo.port)
        assert p1 == p2  # same target -> same port, no second allocation
    finally:
        fwd.stop()


def test_add_mapping_distinct_targets_distinct_ports(echo):
    echo2 = _EchoServer()
    pool = [_free_port(), _free_port()]
    fwd = GatewayForwarder([], listen_host="127.0.0.1", pool=pool)
    fwd.start()
    try:
        p1 = fwd.add_mapping("127.0.0.1", echo.port)
        p2 = fwd.add_mapping("127.0.0.1", echo2.port)
        assert p1 != p2
        assert {p1, p2} == set(pool)
    finally:
        fwd.stop()
        echo2.stop()


def test_add_mapping_pool_exhaustion_returns_none(echo):
    echo2 = _EchoServer()
    pool = [_free_port()]  # room for exactly one
    fwd = GatewayForwarder([], listen_host="127.0.0.1", pool=pool)
    fwd.start()
    try:
        assert fwd.add_mapping("127.0.0.1", echo.port) == pool[0]
        assert fwd.add_mapping("127.0.0.1", echo2.port) is None  # pool full
    finally:
        fwd.stop()
        echo2.stop()


def test_remove_mapping_frees_port_and_closes_listener(echo):
    pool = [_free_port()]
    fwd = GatewayForwarder([], listen_host="127.0.0.1", pool=pool)
    fwd.start()
    try:
        port = fwd.add_mapping("127.0.0.1", echo.port)
        assert _connect_retry(port) is not None
        fwd.remove_mapping("127.0.0.1", echo.port)
        # Port freed: the same pool slot is reusable for a new target.
        deadline = time.time() + 3.0
        reused = None
        while time.time() < deadline:
            reused = fwd.add_mapping("127.0.0.1", echo.port)
            if reused is not None:
                break
            time.sleep(0.1)
        assert reused == port
    finally:
        fwd.stop()
