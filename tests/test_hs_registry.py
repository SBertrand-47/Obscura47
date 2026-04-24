"""Integration tests for hidden-service descriptor endpoints."""
import importlib

import pytest
from fastapi.testclient import TestClient

from src.core.encryptions import ecc_generate_keypair
from src.utils.onion_addr import build_descriptor


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_registry.db")
    monkeypatch.setenv("OBSCURA_REGISTRY_DB_PATH", db_path)
    monkeypatch.setenv("OBSCURA_REGISTRY_ADMIN_KEY", "test-admin-key")
    monkeypatch.setenv("OBSCURA_REGISTRY_RATE_LIMIT", "1000")

    import registry_server
    importlib.reload(registry_server)
    registry_server._pending_challenges.clear()
    registry_server._rate_buckets.clear()

    with TestClient(registry_server.app) as c:
        yield c


def _fresh_descriptor(port=8080, intro_points=None):
    priv, pub_pem = ecc_generate_keypair()
    return priv, pub_pem, build_descriptor(
        priv, pub_pem, port=port, intro_points=intro_points or [{"node_id": "n1", "circuit_id": "c1"}]
    )


def test_publish_and_fetch_descriptor(client):
    _, _, desc = _fresh_descriptor()
    r = client.post("/hs/descriptor", json=desc)
    assert r.status_code == 200
    assert r.json()["addr"] == desc["addr"]

    r = client.get(f"/hs/descriptor/{desc['addr']}")
    assert r.status_code == 200
    got = r.json()
    assert got["addr"] == desc["addr"]
    assert got["pubkey"] == desc["pubkey"]
    assert got["port"] == desc["port"]


def test_rejects_tampered_descriptor(client):
    _, _, desc = _fresh_descriptor()
    desc["port"] = 9999  # sig no longer matches
    r = client.post("/hs/descriptor", json=desc)
    assert r.status_code == 400


def test_rejects_non_json_body(client):
    r = client.post("/hs/descriptor", data="not-json", headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_fetch_unknown_returns_404(client):
    r = client.get("/hs/descriptor/nonexistentaddr12.obscura")
    assert r.status_code == 404


def test_list_descriptors(client):
    _, _, d1 = _fresh_descriptor(port=80)
    _, _, d2 = _fresh_descriptor(port=81)
    client.post("/hs/descriptor", json=d1)
    client.post("/hs/descriptor", json=d2)

    r = client.get("/hs/list")
    assert r.status_code == 200
    addrs = {row["addr"] for row in r.json()}
    assert {d1["addr"], d2["addr"]} <= addrs


def test_republish_replaces_descriptor(client):
    priv, pub_pem, desc1 = _fresh_descriptor(port=80)
    client.post("/hs/descriptor", json=desc1)

    # Same key, new descriptor with different port
    desc2 = build_descriptor(priv, pub_pem, port=9000, intro_points=[])
    assert desc2["addr"] == desc1["addr"]
    r = client.post("/hs/descriptor", json=desc2)
    assert r.status_code == 200

    got = client.get(f"/hs/descriptor/{desc1['addr']}").json()
    assert got["port"] == 9000
