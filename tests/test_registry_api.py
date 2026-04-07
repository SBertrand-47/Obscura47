"""Integration tests for the FastAPI registry server."""
import importlib
import json
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from src.core.encryptions import ecc_generate_keypair, ecdsa_sign


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Return a FastAPI TestClient with a fresh isolated SQLite database."""
    db_path = str(tmp_path / "test_registry.db")
    audit_path = str(tmp_path / "registry_admin.jsonl")
    monkeypatch.setenv("OBSCURA_REGISTRY_DB_PATH", db_path)
    monkeypatch.setenv("OBSCURA_REGISTRY_ADMIN_KEY", "test-admin-key")
    monkeypatch.setenv("OBSCURA_REGISTRY_RATE_LIMIT", "1000")  # high for tests
    monkeypatch.setenv("OBSCURA_REGISTRY_ADMIN_AUDIT_ENABLED", "true")
    monkeypatch.setenv("OBSCURA_REGISTRY_ADMIN_AUDIT_PATH", audit_path)

    # Reload registry_server to pick up new env vars
    import registry_server
    importlib.reload(registry_server)
    # Reset in-memory state between tests
    registry_server._pending_challenges.clear()
    registry_server._rate_buckets.clear()

    with TestClient(registry_server.app) as c:
        c.audit_path = audit_path
        yield c


# ── Basic endpoints ───────────────────────────────────────────────

class TestBasicEndpoints:
    def test_health_empty(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert r.json()["peers"] == 0

    def test_register_no_auth(self, client):
        r = client.post("/register", json={"role": "node", "port": 5001})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "your_ip" in data

    def test_peers_after_register(self, client):
        client.post("/register", json={"role": "node", "port": 5001})
        client.post("/register", json={"role": "exit", "port": 6000, "ws_port": 6001})
        r = client.get("/peers")
        assert r.status_code == 200
        peers = r.json()
        assert len(peers) == 1
        roles = {p["role"] for p in peers}
        assert roles == {"node"}

    def test_peers_role_filter(self, client):
        client.post("/register", json={"role": "node", "port": 5001})
        client.post("/register", json={"role": "exit", "port": 6000})
        r = client.get("/peers?role=node")
        assert len(r.json()) == 1
        assert r.json()[0]["role"] == "node"

    def test_register_validates_port(self, client):
        r = client.post("/register", json={"role": "node", "port": 99999})
        assert r.status_code == 422  # Pydantic validation error

    def test_register_validates_role(self, client):
        r = client.post("/register", json={"role": "invalid", "port": 5001})
        assert r.status_code == 422

    def test_ws_port_in_peer_list(self, client):
        client.post("/register", json={"role": "node", "port": 5001, "ws_port": 5002})
        peers = client.get("/peers").json()
        assert peers[0]["ws_port"] == 5002


# ── ECDSA Challenge-Response Auth ─────────────────────────────────

class TestAuthFlow:
    def test_challenge_issued_with_pubkey(self, client):
        _, pub = ecc_generate_keypair()
        r = client.post("/register", json={"role": "node", "port": 5001, "pub": pub})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is False
        assert "challenge" in data
        assert len(data["challenge"]) == 64  # 32 hex bytes

    def test_verify_with_valid_signature(self, client):
        priv, pub = ecc_generate_keypair()
        r = client.post("/register", json={"role": "node", "port": 5001, "pub": pub})
        challenge = r.json()["challenge"]
        peer_id = r.json()["peer_id"]

        sig = ecdsa_sign(priv, challenge.encode())
        r2 = client.post("/register/verify", json={"peer_id": peer_id, "signature": sig})
        assert r2.status_code == 200
        assert r2.json()["ok"] is True

        # Peer should now be in the list
        peers = client.get("/peers").json()
        assert any(p["port"] == 5001 for p in peers)

    def test_verify_with_invalid_signature(self, client):
        _, pub = ecc_generate_keypair()
        r = client.post("/register", json={"role": "node", "port": 5001, "pub": pub})
        peer_id = r.json()["peer_id"]

        # Sign with wrong key
        wrong_priv, _ = ecc_generate_keypair()
        bad_sig = ecdsa_sign(wrong_priv, r.json()["challenge"].encode())
        r2 = client.post("/register/verify", json={"peer_id": peer_id, "signature": bad_sig})
        assert r2.status_code == 403

    def test_verify_without_pending_challenge(self, client):
        priv, pub = ecc_generate_keypair()
        sig = ecdsa_sign(priv, b"anything")
        r = client.post("/register/verify", json={"peer_id": "fake:1234", "signature": sig})
        assert r.status_code == 400

    def test_heartbeat_after_auth_no_reverify(self, client):
        """Once registered with pubkey, heartbeats should succeed without re-auth."""
        priv, pub = ecc_generate_keypair()
        r1 = client.post("/register", json={"role": "node", "port": 5001, "pub": pub})
        sig = ecdsa_sign(priv, r1.json()["challenge"].encode())
        client.post("/register/verify", json={"peer_id": r1.json()["peer_id"], "signature": sig})

        # Heartbeat: same pubkey, should skip challenge
        r2 = client.post("/register", json={"role": "node", "port": 5001, "pub": pub})
        assert r2.json()["ok"] is True


# ── Admin Endpoints ───────────────────────────────────────────────

class TestAdminAPI:
    def test_delete_requires_admin_key(self, client):
        client.post("/register", json={"role": "node", "port": 5001})
        r = client.delete("/peers/testclient:5001")
        assert r.status_code == 403

    def test_delete_with_admin_key(self, client):
        client.post("/register", json={"role": "node", "port": 5001})
        r = client.delete(
            "/peers/testclient:5001",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        assert r.status_code == 200
        # Peer should be gone
        peers = client.get("/peers").json()
        assert len(peers) == 0

    def test_delete_nonexistent(self, client):
        r = client.delete(
            "/peers/nonexistent:1234",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        assert r.status_code == 404

    def test_delete_with_admin_key_writes_audit_event(self, client):
        client.post("/register", json={"role": "node", "port": 5001})
        r = client.delete(
            "/peers/testclient:5001",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        assert r.status_code == 200

        with open(client.audit_path, "r", encoding="utf-8") as fh:
            events = [json.loads(line) for line in fh if line.strip()]

        assert len(events) == 1
        assert events[0]["event"] == "admin_action"
        assert events[0]["action"] == "remove_peer"
        assert events[0]["allowed"] is True
        assert events[0]["source_ip"] == "testclient"
        assert events[0]["target"] == "testclient:5001"


# ── Persistence ───────────────────────────────────────────────────

class TestPersistence:
    def test_peers_persist_across_reload(self, tmp_path, monkeypatch):
        """Peers stored in SQLite should survive a registry restart."""
        db_path = str(tmp_path / "persist.db")
        monkeypatch.setenv("OBSCURA_REGISTRY_DB_PATH", db_path)
        monkeypatch.setenv("OBSCURA_REGISTRY_RATE_LIMIT", "1000")

        import registry_server
        importlib.reload(registry_server)
        registry_server._pending_challenges.clear()
        registry_server._rate_buckets.clear()

        # First instance: register a peer
        with TestClient(registry_server.app) as c1:
            c1.post("/register", json={"role": "node", "port": 5001})
            assert len(c1.get("/peers").json()) == 1

        # Second instance: same DB file, peer should still be there
        importlib.reload(registry_server)
        registry_server._pending_challenges.clear()
        registry_server._rate_buckets.clear()
        with TestClient(registry_server.app) as c2:
            peers = c2.get("/peers").json()
            assert len(peers) == 1
            assert peers[0]["role"] == "node"
