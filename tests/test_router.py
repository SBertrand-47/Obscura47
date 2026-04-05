"""Unit tests for src/core/router.py — route building and WS-preference logic."""
import json
import pytest

from src.core import router as router_mod
from src.core.router import Router, build_route47, _try_ws_send
from src.core.encryptions import ecc_generate_keypair, onion_decrypt_with_priv


# ── Route building ────────────────────────────────────────────────

class TestRouteBuilding:
    def test_build_random_route_sample_size(self):
        peers = [{"host": f"10.0.0.{i}", "port": 5000 + i} for i in range(10)]
        r = Router(node=None, peers=peers)
        route = r.build_random_route(hops=3)
        assert len(route) == 3
        # Hops are unique
        assert len({(p["host"], p["port"]) for p in route}) == 3

    def test_build_random_route_not_enough_peers(self):
        peers = [{"host": "10.0.0.1", "port": 5001}]
        r = Router(node=None, peers=peers)
        route = r.build_random_route(hops=3)
        assert len(route) == 1

    def test_build_random_route_empty(self):
        r = Router(node=None, peers=[])
        assert r.build_random_route(hops=3) == []

    def test_build_route47_range(self):
        peers = [{"host": f"10.0.0.{i}", "port": 5000 + i} for i in range(10)]
        for _ in range(20):
            route = build_route47(peers, min_hops=4, max_hops=7)
            assert 4 <= len(route) <= 7

    def test_build_route47_empty(self):
        assert build_route47([]) == []

    def test_build_route47_capped_at_peer_count(self):
        peers = [{"host": "10.0.0.1", "port": 5001}, {"host": "10.0.0.2", "port": 5002}]
        route = build_route47(peers, min_hops=4, max_hops=7)
        assert len(route) == 2


# ── WebSocket preference logic ────────────────────────────────────

class TestWSPreference:
    def test_no_ws_port_returns_false(self):
        """Peer without ws_port should fall back to TCP."""
        assert _try_ws_send({"host": "10.0.0.1", "port": 5001}, "{}") is False

    def test_ws_client_missing_returns_false(self, monkeypatch):
        """If get_ws_client() returns None, fall back to TCP."""
        monkeypatch.setattr(router_mod, "PREFER_WEBSOCKET", True)
        import src.core.ws_transport as wst
        monkeypatch.setattr(wst, "_global_client", None)
        peer = {"host": "10.0.0.1", "port": 5001, "ws_port": 5002}
        assert _try_ws_send(peer, "{}") is False

    def test_prefer_websocket_disabled(self, monkeypatch):
        """When PREFER_WEBSOCKET is False, skip WS even when ws_port set."""
        monkeypatch.setattr(router_mod, "PREFER_WEBSOCKET", False)
        peer = {"host": "10.0.0.1", "port": 5001, "ws_port": 5002}
        assert _try_ws_send(peer, "{}") is False

    def test_ws_send_called_when_available(self, monkeypatch):
        """When conditions are met, the WS client's send_frame is invoked."""
        calls = []

        class FakeClient:
            def send_frame(self, host, port, frame, tls=False):
                calls.append((host, port, frame, tls))
                return True

        monkeypatch.setattr(router_mod, "PREFER_WEBSOCKET", True)
        import src.core.ws_transport as wst
        monkeypatch.setattr(wst, "get_ws_client", lambda: FakeClient())

        peer = {"host": "10.0.0.1", "port": 5001, "ws_port": 5002}
        assert _try_ws_send(peer, '{"x":1}') is True
        assert calls == [("10.0.0.1", 5002, '{"x":1}', False)]

    def test_ws_tls_flag_passed_through(self, monkeypatch):
        """Peer with ws_tls=True should cause tls=True to reach the client."""
        calls = []

        class FakeClient:
            def send_frame(self, host, port, frame, tls=False):
                calls.append((host, port, tls))
                return True

        monkeypatch.setattr(router_mod, "PREFER_WEBSOCKET", True)
        import src.core.ws_transport as wst
        monkeypatch.setattr(wst, "get_ws_client", lambda: FakeClient())

        peer = {"host": "10.0.0.1", "port": 5001, "ws_port": 5002, "ws_tls": True}
        assert _try_ws_send(peer, "{}") is True
        assert calls == [("10.0.0.1", 5002, True)]


# ── Onion layer construction ──────────────────────────────────────

class TestOnionRouting:
    def test_relay_message_builds_peelable_onion(self, monkeypatch):
        """relay_message should produce an onion that peels cleanly hop-by-hop."""
        p1, pub1 = ecc_generate_keypair()
        p2, pub2 = ecc_generate_keypair()
        p3, pub3 = ecc_generate_keypair()
        p_dest, pub_dest = ecc_generate_keypair()

        peers = [
            {"host": "h1", "port": 1, "pub": pub1},
            {"host": "h2", "port": 2, "pub": pub2},
            {"host": "h3", "port": 3, "pub": pub3},
        ]
        destination = {"host": "hd", "port": 9, "pub": pub_dest}

        sent = {}

        def fake_send(route, envelope):
            sent["route"] = route
            sent["envelope"] = envelope
            return True

        monkeypatch.setattr(router_mod, "_send_frame_via_route", fake_send)
        # Make route deterministic
        monkeypatch.setattr(router_mod.random, "sample", lambda pop, k: pop[:k])

        r = Router(node=None, peers=peers)
        r.relay_message("hello", destination, return_path={"host": "back"}, request_id="req-1")

        # First-hop envelope contains an onion sealed for peers[0]
        assert sent["route"] == [peers[0]]
        envelope = sent["envelope"]
        assert "encrypted_data" in envelope

        # Peel layer 1 (peers[0])
        layer1 = json.loads(onion_decrypt_with_priv(p1, envelope["encrypted_data"]))
        assert layer1["next_hop"] == peers[1]

        # Peel layer 2 (peers[1])
        layer2 = json.loads(onion_decrypt_with_priv(p2, layer1["inner"]))
        assert layer2["next_hop"] == peers[2]

        # Peel layer 3 (peers[2])
        layer3 = json.loads(onion_decrypt_with_priv(p3, layer2["inner"]))
        assert layer3["next_hop"] == destination

        # Peel final layer (destination) — contains payload
        final = json.loads(onion_decrypt_with_priv(p_dest, layer3["inner"]))
        assert final["payload"]["data"] == "hello"
        assert final["payload"]["return_path"] == {"host": "back"}
        assert final["payload"]["request_id"] == "req-1"

    def test_relay_message_no_peers(self, capsys):
        r = Router(node=None, peers=[])
        r.relay_message("hello", None)
        out = capsys.readouterr().out
        assert "No peers" in out or "No route" in out
