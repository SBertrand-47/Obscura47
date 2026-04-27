from src.core import internet_discovery as disc
import time


def test_merge_internet_peers_keeps_same_ip_exit(monkeypatch):
    monkeypatch.setattr(
        disc,
        "fetch_peers_from_registry",
        lambda role_filter=None: [
            {
                "host": "203.0.113.10",
                "port": 6000,
                "role": "exit",
                "pub": "exit-pub",
                "ws_port": 6001,
            }
        ],
    )
    monkeypatch.setattr(disc, "_my_public_ip", "203.0.113.10")

    peers = []
    disc.merge_internet_peers(peers, role_filter="exit")

    assert len(peers) == 1
    assert peers[0]["host"] == "203.0.113.10"
    assert peers[0]["port"] == 6000
    assert peers[0]["pub"] == "exit-pub"
    assert peers[0]["ws_port"] == 6001


def test_merge_internet_peers_updates_existing_peer_metadata(monkeypatch):
    monkeypatch.setattr(
        disc,
        "fetch_peers_from_registry",
        lambda role_filter=None: [
            {
                "host": "203.0.113.10",
                "port": 6000,
                "role": "exit",
                "pub": "exit-pub",
                "ws_port": 6001,
            }
        ],
    )

    peers = [{"host": "203.0.113.10", "port": 6000, "ts": 1.0}]
    disc.merge_internet_peers(peers, role_filter="exit")

    assert len(peers) == 1
    assert peers[0]["host"] == "203.0.113.10"
    assert peers[0]["port"] == 6000
    assert peers[0]["pub"] == "exit-pub"
    assert peers[0]["ws_port"] == 6001


def test_merge_internet_peers_rekeys_existing_node_when_port_changes(monkeypatch):
    monkeypatch.setattr(
        disc,
        "fetch_peers_from_registry",
        lambda role_filter=None: [
            {
                "host": "203.0.113.10",
                "port": 5002,
                "role": "node",
                "pub": "node-pub",
                "ws_port": 5003,
            }
        ],
    )

    now = time.time()
    peers = [
        {"host": "192.168.1.20", "port": 5001, "pub": "node-pub", "ts": now},
        {"host": "198.51.100.5", "port": 5001, "pub": "other-node", "ts": now},
    ]
    disc.merge_internet_peers(peers, role_filter="node")

    assert len(peers) == 2
    updated = next(peer for peer in peers if peer["pub"] == "node-pub")
    assert updated["host"] == "203.0.113.10"
    assert updated["port"] == 5002
    assert updated["ws_port"] == 5003
