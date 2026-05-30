"""Integration tests for the FastAPI registry server."""
import importlib
import json
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from src.core.encryptions import ecc_generate_keypair, ecdsa_sign


def register_authed(client, role: str, port: int, *, ws_port: int | None = None,
                    ws_tls: bool | None = None, advertised_host: str | None = None,
                    headers: dict | None = None):
    """Run the full ECDSA challenge-response flow. Returns (peer_id, response_json).

    Relay (``role=node``) and ``role=exit`` registrations now require a pubkey
    plus signed nonce; the registry rejects unauth attempts with 401. Tests
    that just want a peer in the listing should use this helper. ``headers``
    (e.g. an ``X-Forwarded-For``) is applied to both round-trips so the
    challenge IP-match check still passes.
    """
    priv, pub = ecc_generate_keypair()
    body = {"role": role, "port": port, "pub": pub}
    if ws_port is not None:
        body["ws_port"] = ws_port
    if ws_tls is not None:
        body["ws_tls"] = ws_tls
    if advertised_host is not None:
        body["advertised_host"] = advertised_host
    r1 = client.post("/register", json=body, headers=headers)
    assert r1.status_code == 200, r1.text
    data = r1.json()
    peer_id = data["peer_id"]
    sig = ecdsa_sign(priv, data["challenge"].encode())
    r2 = client.post("/register/verify", json={"peer_id": peer_id, "signature": sig},
                     headers=headers)
    assert r2.status_code == 200, r2.text
    return peer_id, r2.json()


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

    def test_register_no_auth_rejected_for_relay(self, client):
        # Relays and exits must complete ECDSA challenge-response; the unauth
        # path is reserved for proxies (client-side, never picked as a hop).
        r = client.post("/register", json={"role": "node", "port": 5001})
        assert r.status_code == 401
        r = client.post("/register", json={"role": "exit", "port": 6000})
        assert r.status_code == 401

    def test_register_proxy_unauth_still_allowed(self, client):
        r = client.post("/register", json={"role": "proxy", "port": 5050})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["registered_host"] == "testclient"

    def test_register_uses_advertised_host_override(self, client):
        _peer_id, data = register_authed(
            client, role="exit", port=6000, advertised_host="154.38.172.2",
        )
        assert data["registered_host"] == "154.38.172.2"
        assert data["peer_id"] == "154.38.172.2:6000"

        admin = client.get(
            "/admin/peers",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        exit_peer = next(p for p in admin.json()["peers"] if p["role"] == "exit")
        assert exit_peer["host"] == "154.38.172.2"

    def test_peers_after_register(self, client):
        register_authed(client, role="node", port=5001)
        register_authed(client, role="exit", port=6000, ws_port=6001)
        r = client.get("/peers")
        assert r.status_code == 200
        peers = r.json()
        # Exits are pending approval by default → excluded from /peers
        assert len(peers) == 1
        roles = {p["role"] for p in peers}
        assert roles == {"node"}

    def test_peers_role_filter(self, client):
        register_authed(client, role="node", port=5001)
        register_authed(client, role="exit", port=6000)
        r = client.get("/peers?role=node")
        assert len(r.json()) == 1
        assert r.json()[0]["role"] == "node"

    def test_register_validates_port(self, client):
        # Pydantic validation runs before the auth gate.
        r = client.post("/register", json={"role": "node", "port": 99999})
        assert r.status_code == 422

    def test_register_validates_role(self, client):
        r = client.post("/register", json={"role": "invalid", "port": 5001})
        assert r.status_code == 422

    def test_ws_port_in_peer_list(self, client):
        register_authed(client, role="node", port=5001, ws_port=5002)
        peers = client.get("/peers").json()
        # Probe will fail against testclient:5002 → ws_port masked. That's the
        # new contract: an unreachable ws_port doesn't get advertised. The
        # peer itself still shows up in the listing.
        assert len(peers) == 1
        assert peers[0]["port"] == 5001


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

    def test_verify_keeps_advertised_host_override(self, client):
        priv, pub = ecc_generate_keypair()
        r = client.post(
            "/register",
            json={
                "role": "node",
                "port": 5001,
                "pub": pub,
                "advertised_host": "154.38.172.2",
            },
        )
        challenge = r.json()["challenge"]
        peer_id = r.json()["peer_id"]

        sig = ecdsa_sign(priv, challenge.encode())
        r2 = client.post("/register/verify", json={"peer_id": peer_id, "signature": sig})
        assert r2.status_code == 200
        assert r2.json()["registered_host"] == "154.38.172.2"

        peers = client.get("/peers").json()
        assert peers[0]["host"] == "154.38.172.2"

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


# ── Signed self-deregister ────────────────────────────────────────

class TestDeregister:
    def _register(self, client, port=5001):
        priv, pub = ecc_generate_keypair()
        r1 = client.post("/register", json={"role": "node", "port": port, "pub": pub})
        peer_id = r1.json()["peer_id"]
        sig = ecdsa_sign(priv, r1.json()["challenge"].encode())
        r2 = client.post("/register/verify", json={"peer_id": peer_id, "signature": sig})
        assert r2.status_code == 200
        return priv, pub, peer_id

    def test_signed_deregister_removes_peer(self, client):
        import time as _time
        priv, _, peer_id = self._register(client)
        ts = _time.time()
        sig = ecdsa_sign(priv, f"deregister:{peer_id}:{ts}".encode())
        r = client.post("/deregister", json={
            "peer_id": peer_id, "timestamp": ts, "signature": sig,
        })
        assert r.status_code == 200
        assert r.json()["deleted"] is True
        assert client.get("/peers").json() == []

    def test_deregister_with_wrong_signature_rejected(self, client):
        import time as _time
        _, _, peer_id = self._register(client)
        wrong_priv, _ = ecc_generate_keypair()
        ts = _time.time()
        sig = ecdsa_sign(wrong_priv, f"deregister:{peer_id}:{ts}".encode())
        r = client.post("/deregister", json={
            "peer_id": peer_id, "timestamp": ts, "signature": sig,
        })
        assert r.status_code == 403
        # Peer must still be there
        assert len(client.get("/peers").json()) == 1

    def test_deregister_replay_outside_skew_rejected(self, client):
        import time as _time
        priv, _, peer_id = self._register(client)
        stale_ts = _time.time() - 600  # 10 minutes old
        sig = ecdsa_sign(priv, f"deregister:{peer_id}:{stale_ts}".encode())
        r = client.post("/deregister", json={
            "peer_id": peer_id, "timestamp": stale_ts, "signature": sig,
        })
        assert r.status_code == 400
        assert len(client.get("/peers").json()) == 1

    def test_deregister_missing_peer_is_noop(self, client):
        import time as _time
        priv, _ = ecc_generate_keypair()
        ts = _time.time()
        sig = ecdsa_sign(priv, f"deregister:ghost:9999:{ts}".encode())
        r = client.post("/deregister", json={
            "peer_id": "ghost:9999", "timestamp": ts, "signature": sig,
        })
        assert r.status_code == 200
        assert r.json()["deleted"] is False

    def test_deregister_signature_for_different_peer_rejected(self, client):
        """Signing your own peer_id then submitting it for someone else's must fail."""
        import time as _time
        priv_a, _, peer_a = self._register(client, port=5001)
        _, _, peer_b = self._register(client, port=5002)
        ts = _time.time()
        # priv_a signs B's peer_id - but registry verifies against B's pubkey.
        sig = ecdsa_sign(priv_a, f"deregister:{peer_b}:{ts}".encode())
        r = client.post("/deregister", json={
            "peer_id": peer_b, "timestamp": ts, "signature": sig,
        })
        assert r.status_code == 403
        assert len(client.get("/peers").json()) == 2


# ── Admin Endpoints ───────────────────────────────────────────────

class TestAdminAPI:
    def test_delete_requires_admin_key(self, client):
        register_authed(client, role="node", port=5001)
        r = client.delete("/peers/testclient:5001")
        assert r.status_code == 403

    def test_delete_with_admin_key(self, client):
        register_authed(client, role="node", port=5001)
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
        register_authed(client, role="node", port=5001)
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

    def test_admin_peers_lists_sqlite_registry_peers(self, client):
        register_authed(client, role="node", port=5001, ws_port=5002)
        register_authed(client, role="exit", port=6000, ws_port=6001)

        r = client.get(
            "/admin/peers",
            headers={"Authorization": "Bearer test-admin-key"},
        )

        assert r.status_code == 200
        data = r.json()
        assert data["total_peers"] == 2
        assert {p["role"] for p in data["peers"]} == {"node", "exit"}
        exit_peer = next(p for p in data["peers"] if p["role"] == "exit")
        assert exit_peer["approved"] is False
        # Admin view shows raw DB values - ws_port not masked by probe state.
        assert exit_peer["ws_port"] == 6001

    def test_dashboard_data_highlights_pending_exits(self, client):
        register_authed(client, role="node", port=5001)
        register_authed(client, role="exit", port=6000, ws_port=6001)

        r = client.get(
            "/admin/dashboard/data",
            headers={"Authorization": "Bearer test-admin-key"},
        )

        assert r.status_code == 200
        data = r.json()
        assert data["summary"]["total"] == 2
        assert data["summary"]["pending_exits"] == 1
        assert data["pending_exits"][0]["peer_id"] == "testclient:6000"

    def test_dashboard_data_requires_admin_key(self, client):
        r = client.get("/admin/dashboard/data")
        assert r.status_code == 403

    def test_admin_dashboard_reports_when_not_built(self, client):
        r = client.get("/admin/dashboard")
        assert r.status_code in (200, 503)


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
            register_authed(c1, role="node", port=5001)
            assert len(c1.get("/peers").json()) == 1

        # Second instance: same DB file, peer should still be there
        importlib.reload(registry_server)
        registry_server._pending_challenges.clear()
        registry_server._rate_buckets.clear()
        with TestClient(registry_server.app) as c2:
            peers = c2.get("/peers").json()
            assert len(peers) == 1
            assert peers[0]["role"] == "node"


# ── NAT-scoped visibility for private (LAN) hosts ─────────────────

class TestNatScopedPeers:
    """A peer advertising an RFC1918 host must only be served to requesters
    the registry observed behind the same public IP. Public hosts stay
    globally visible, so a growing WAN network is unaffected."""

    LAN_NAT = {"X-Forwarded-For": "203.0.113.7"}      # the home NAT's public IP
    OTHER_NAT = {"X-Forwarded-For": "198.51.100.9"}   # an unrelated node (e.g. VPS)

    def test_lan_peer_hidden_from_other_nat(self, client):
        # A home machine registers its LAN address from behind the home NAT.
        register_authed(client, role="node", port=5001,
                        advertised_host="192.168.1.50", headers=self.LAN_NAT)
        # A node on a different public IP must not see the unreachable LAN host.
        peers = client.get("/peers", headers=self.OTHER_NAT).json()
        assert all(p["host"] != "192.168.1.50" for p in peers)

    def test_lan_peer_visible_to_same_nat(self, client):
        register_authed(client, role="node", port=5001,
                        advertised_host="192.168.1.50", headers=self.LAN_NAT)
        # A second machine behind the same NAT should see it (LAN routing).
        peers = client.get("/peers", headers=self.LAN_NAT).json()
        assert any(p["host"] == "192.168.1.50" for p in peers)

    def test_public_peer_visible_across_nats(self, client):
        register_authed(client, role="node", port=5001,
                        advertised_host="154.38.172.2", headers=self.LAN_NAT)
        peers = client.get("/peers", headers=self.OTHER_NAT).json()
        assert any(p["host"] == "154.38.172.2" for p in peers)

    def test_opt_in_serves_lan_to_everyone(self, client, monkeypatch):
        monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "1")
        register_authed(client, role="node", port=5001,
                        advertised_host="192.168.1.50", headers=self.LAN_NAT)
        peers = client.get("/peers", headers=self.OTHER_NAT).json()
        assert any(p["host"] == "192.168.1.50" for p in peers)


class TestSlotBinding:
    """First-claimant binding: a live host:port slot is owned by the first key."""

    def test_live_slot_rejects_foreign_key(self, client):
        # Key A claims 9.9.9.9:5001 and is live.
        register_authed(client, role="node", port=5001, advertised_host="9.9.9.9")
        # A different key tries to claim the same slot while A is live → 409.
        _priv_b, pub_b = ecc_generate_keypair()
        r = client.post("/register", json={
            "role": "node", "port": 5001, "pub": pub_b, "advertised_host": "9.9.9.9",
        })
        assert r.status_code == 409, r.text
        # A still owns the slot; the foreign key never replaced it.
        slot = [p for p in client.get("/peers").json()
                if p["host"] == "9.9.9.9" and p["port"] == 5001]
        assert len(slot) == 1
        assert slot[0]["pub"] != pub_b

    def test_same_key_heartbeat_not_blocked(self, client):
        # The owning key re-registering is a heartbeat, not a takeover.
        priv, pub = ecc_generate_keypair()
        body = {"role": "node", "port": 5001, "pub": pub, "advertised_host": "9.9.9.9"}
        r1 = client.post("/register", json=body)
        sig = ecdsa_sign(priv, r1.json()["challenge"].encode())
        client.post("/register/verify",
                    json={"peer_id": r1.json()["peer_id"], "signature": sig})
        r2 = client.post("/register", json=body)
        assert r2.status_code == 200, r2.text
        assert r2.json()["ok"] is True

    def test_stale_slot_can_be_reclaimed(self, client, monkeypatch):
        import registry_server
        register_authed(client, role="node", port=5001, advertised_host="9.9.9.9")
        # Age every existing peer past the TTL so the slot is free to reclaim.
        monkeypatch.setattr(registry_server, "PEER_TTL", -1)
        _peer_id, data = register_authed(client, role="node", port=5001,
                                         advertised_host="9.9.9.9")
        assert data["ok"] is True

    def test_unauth_proxy_cannot_clobber_live_keyed_slot(self, client):
        # An unauthenticated (keyless) registration can't overwrite a live
        # slot that an established key owns.
        register_authed(client, role="node", port=5001, advertised_host="9.9.9.9")
        r = client.post("/register", json={
            "role": "proxy", "port": 5001, "advertised_host": "9.9.9.9",
        })
        assert r.status_code == 409, r.text
