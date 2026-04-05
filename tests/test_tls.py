"""TLS integration tests: wss:// WebSocket transport + https:// registry."""
import json
import os
import ssl
import socket
import subprocess
import time
import importlib
import pytest
from fastapi.testclient import TestClient

from src.core.encryptions import ecc_generate_keypair
from src.core.ws_transport import WSServer, WSClient


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


@pytest.fixture(scope="session")
def self_signed_cert(tmp_path_factory):
    """Generate a self-signed cert+key once per session via openssl."""
    d = tmp_path_factory.mktemp("tls")
    cert = d / "cert.pem"
    key = d / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


# ── wss:// WebSocket transport ────────────────────────────────────

class TestWSSTransport:
    def test_wss_auth_and_frame_delivery(self, self_signed_cert):
        cert, key = self_signed_cert
        priv_s, pub_s = ecc_generate_keypair()
        priv_c, pub_c = ecc_generate_keypair()

        port = _free_port()
        received = []
        server = WSServer(
            "127.0.0.1", port, priv_s, pub_s,
            on_frame=received.append,
            tls_cert=cert, tls_key=key,
        )
        server.start()
        assert _wait_for_port(port), "wss server did not open port"

        # Plain TLS-level reachability check (handshake should succeed)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port)) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as ts:
                assert ts.version() is not None  # TLS handshake succeeded

        # Client with verify disabled (self-signed)
        client = WSClient(priv_c, pub_c, tls_verify=False)
        try:
            ok = client.send_frame("127.0.0.1", port, json.dumps({"msg": "wss"}), tls=True)
            assert ok is True

            deadline = time.time() + 2.0
            while time.time() < deadline and not received:
                time.sleep(0.05)
            assert len(received) == 1
            assert json.loads(received[0]) == {"msg": "wss"}

            # Connection pool key should reflect TLS
            assert ("127.0.0.1", port, True) in client._connections
        finally:
            client.close_all()
            server.stop()

    def test_wss_verify_enabled_rejects_self_signed(self, self_signed_cert):
        """With tls_verify=True, connecting to a self-signed cert must fail."""
        cert, key = self_signed_cert
        priv_s, pub_s = ecc_generate_keypair()
        priv_c, pub_c = ecc_generate_keypair()

        port = _free_port()
        server = WSServer(
            "127.0.0.1", port, priv_s, pub_s,
            on_frame=lambda _m: None,
            tls_cert=cert, tls_key=key,
        )
        server.start()
        assert _wait_for_port(port)

        client = WSClient(priv_c, pub_c, tls_verify=True)
        try:
            ok = client.send_frame("127.0.0.1", port, "{}", tls=True)
            assert ok is False
        finally:
            client.close_all()
            server.stop()


# ── Registry: ws_tls field round-trip ─────────────────────────────

class TestRegistryWSTLS:
    def test_ws_tls_field_persisted_and_returned(self, tmp_path, monkeypatch):
        db_path = str(tmp_path / "tls_registry.db")
        monkeypatch.setenv("OBSCURA_REGISTRY_DB_PATH", db_path)
        monkeypatch.setenv("OBSCURA_REGISTRY_RATE_LIMIT", "1000")

        import registry_server
        importlib.reload(registry_server)
        registry_server._pending_challenges.clear()
        registry_server._rate_buckets.clear()

        with TestClient(registry_server.app) as c:
            r = c.post("/register", json={
                "role": "node", "port": 5001,
                "ws_port": 5002, "ws_tls": True,
            })
            assert r.status_code == 200
            peers = c.get("/peers").json()
            assert len(peers) == 1
            assert peers[0]["ws_port"] == 5002
            assert peers[0]["ws_tls"] is True

    def test_ws_tls_absent_returns_null(self, tmp_path, monkeypatch):
        """A peer registering without ws_tls should have ws_tls=None in listing."""
        db_path = str(tmp_path / "tls_registry2.db")
        monkeypatch.setenv("OBSCURA_REGISTRY_DB_PATH", db_path)
        monkeypatch.setenv("OBSCURA_REGISTRY_RATE_LIMIT", "1000")

        import registry_server
        importlib.reload(registry_server)
        registry_server._pending_challenges.clear()
        registry_server._rate_buckets.clear()

        with TestClient(registry_server.app) as c:
            c.post("/register", json={"role": "node", "port": 5001, "ws_port": 5002})
            peers = c.get("/peers").json()
            assert peers[0]["ws_tls"] is None
