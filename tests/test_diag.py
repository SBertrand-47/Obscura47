"""Tests for the diag emitter and registry /diag endpoint."""
import importlib
import json
import os
import time

import pytest
from fastapi.testclient import TestClient


# ── Emitter: src/utils/diag.py ────────────────────────────────────

class TestDiagEmitter:
    def _reload(self, monkeypatch, *, local: bool = False, registry: bool = False,
                token: str = ""):
        # Use empty strings instead of delenv so the project's .env loader
        # (which only fills vars *not* in os.environ) doesn't quietly
        # restore the developer's local OBSCURA_DIAG=1 between tests.
        monkeypatch.setenv("OBSCURA_DIAG", "1" if local else "")
        monkeypatch.setenv("OBSCURA_DIAG_REGISTRY", "1" if registry else "")
        monkeypatch.setenv("OBSCURA_DIAG_TOKEN", token)
        from src.utils import diag
        importlib.reload(diag)
        return diag

    def test_disabled_is_noop(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        diag = self._reload(monkeypatch)
        diag.set_role("proxy")
        diag.emit("exit_pick", exit="1.2.3.4:6000")
        # Nothing written, no errors.
        assert not (tmp_path / ".obscura47" / "logs" / "proxy.jsonl").exists()
        assert diag.is_enabled() is False

    def test_local_writes_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        diag = self._reload(monkeypatch, local=True)
        diag.set_role("proxy")
        diag.set_node_id("1.2.3.4:5050")
        diag.emit("exit_pick", exit="9.9.9.9:6000", rtt_ms=12.5)

        path = tmp_path / ".obscura47" / "logs" / "proxy.jsonl"
        assert path.exists()
        lines = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        assert len(lines) == 1
        record = lines[0]
        assert record["role"] == "proxy"
        assert record["node_id"] == "1.2.3.4:5050"
        assert record["event"] == "exit_pick"
        assert record["fields"]["exit"] == "9.9.9.9:6000"
        assert record["fields"]["rtt_ms"] == 12.5
        assert isinstance(record["ts"], float)

    def test_non_json_fields_coerced(self, tmp_path, monkeypatch):
        """An unserialisable value gets repr'd instead of crashing the caller."""
        monkeypatch.setenv("HOME", str(tmp_path))
        diag = self._reload(monkeypatch, local=True)
        diag.set_role("node")

        class NotJSON:
            def __repr__(self):
                return "NotJSON()"

        diag.emit("weird", obj=NotJSON())

        path = tmp_path / ".obscura47" / "logs" / "node.jsonl"
        record = json.loads(path.read_text().splitlines()[0])
        assert record["fields"]["obj"] == "NotJSON()"


# ── Registry /diag endpoint ───────────────────────────────────────

@pytest.fixture
def diag_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_registry.db")
    diag_path = str(tmp_path / "diag.jsonl")
    monkeypatch.setenv("OBSCURA_REGISTRY_DB_PATH", db_path)
    monkeypatch.setenv("OBSCURA_REGISTRY_ADMIN_KEY", "test-admin-key")
    monkeypatch.setenv("OBSCURA_REGISTRY_RATE_LIMIT", "1000")
    monkeypatch.setenv("OBSCURA_DIAG_TOKEN", "supersecret")
    monkeypatch.setenv("OBSCURA_DIAG_PATH", diag_path)

    import registry_server
    importlib.reload(registry_server)
    registry_server._pending_challenges.clear()
    registry_server._rate_buckets.clear()

    with TestClient(registry_server.app) as c:
        c.diag_path = diag_path
        yield c


class TestDiagEndpoint:
    def test_rejects_missing_token(self, diag_client):
        r = diag_client.post("/diag", json={"event": "x"})
        assert r.status_code == 401

    def test_rejects_wrong_token(self, diag_client):
        r = diag_client.post(
            "/diag", json={"event": "x"},
            headers={"X-Diag-Token": "nope"},
        )
        assert r.status_code == 401

    def test_accepts_single_event(self, diag_client):
        r = diag_client.post(
            "/diag",
            json={"event": "exit_pick", "role": "proxy", "fields": {"exit": "a:1"}},
            headers={"X-Diag-Token": "supersecret"},
        )
        assert r.status_code == 200
        assert r.json()["accepted"] == 1

        with open(diag_client.diag_path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 1
        assert lines[0]["event"] == "exit_pick"
        assert lines[0]["fields"]["exit"] == "a:1"
        # Registry stamps these on receipt.
        assert "received_at" in lines[0]
        assert "source_ip" in lines[0]

    def test_accepts_batch(self, diag_client):
        events = [
            {"event": "tunnel_open", "fields": {"req": "r1"}},
            {"event": "tunnel_closed", "fields": {"req": "r1", "ok": True}},
        ]
        r = diag_client.post(
            "/diag", json={"events": events},
            headers={"X-Diag-Token": "supersecret"},
        )
        assert r.status_code == 200
        assert r.json()["accepted"] == 2

        with open(diag_client.diag_path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert [l["event"] for l in lines] == ["tunnel_open", "tunnel_closed"]

    def test_rejects_event_without_event_field(self, diag_client):
        r = diag_client.post(
            "/diag", json={"role": "proxy"},  # no 'event'
            headers={"X-Diag-Token": "supersecret"},
        )
        assert r.status_code == 400

    def test_disabled_without_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OBSCURA_REGISTRY_DB_PATH", str(tmp_path / "db"))
        monkeypatch.setenv("OBSCURA_REGISTRY_RATE_LIMIT", "1000")
        # Empty string defeats both monkeypatch and the .env restore path.
        monkeypatch.setenv("OBSCURA_DIAG_TOKEN", "")
        import registry_server
        importlib.reload(registry_server)
        with TestClient(registry_server.app) as c:
            r = c.post("/diag", json={"event": "x"},
                       headers={"X-Diag-Token": "anything"})
            assert r.status_code == 503
