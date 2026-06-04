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


# ---------------------------------------------------------------------------
# is_private_peer / allow_lan_peers
# ---------------------------------------------------------------------------


def test_is_private_peer_flags_rfc1918():
    assert disc.is_private_peer({"host": "192.168.1.86", "port": 5001})
    assert disc.is_private_peer({"host": "10.2.0.2", "port": 5001})
    assert disc.is_private_peer({"host": "172.16.0.1", "port": 5001})


def test_is_private_peer_flags_loopback_and_linklocal():
    assert disc.is_private_peer({"host": "127.0.0.1", "port": 5001})
    assert disc.is_private_peer({"host": "169.254.10.10", "port": 5001})
    assert disc.is_private_peer({"host": "::1", "port": 5001})


def test_is_private_peer_passes_public_addresses():
    assert not disc.is_private_peer({"host": "95.173.221.72", "port": 5001})
    assert not disc.is_private_peer({"host": "154.38.172.2", "port": 5001})
    assert not disc.is_private_peer({"host": "8.8.8.8", "port": 53})


def test_is_private_peer_tolerates_missing_or_hostname():
    # We don't resolve hostnames - treat them as plausibly public so we
    # never block a registered .com peer because of an unrelated DNS quirk.
    assert not disc.is_private_peer(None)
    assert not disc.is_private_peer({})
    assert not disc.is_private_peer({"host": "", "port": 5001})
    assert not disc.is_private_peer({"host": "node.example.com", "port": 5001})


def test_allow_lan_peers_env_override(monkeypatch):
    monkeypatch.delenv("OBSCURA_ALLOW_LAN_PEERS", raising=False)
    assert disc.allow_lan_peers() is False
    monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "1")
    assert disc.allow_lan_peers() is True
    monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "yes")
    assert disc.allow_lan_peers() is True
    monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "0")
    assert disc.allow_lan_peers() is False


class TestIsSelfPeerSibling:
    """A same-WAN-IP sibling (distinct port + pubkey) is usable in LAN mode.

    In a same-NAT fleet the rendezvous/intro path normally runs through such
    a sibling, but the WAN-IP self-filter would NAT-loop-filter it. With
    OBSCURA_ALLOW_LAN_PEERS on, a distinct-pubkey sibling is kept usable.
    """

    def _isolate(self, monkeypatch):
        monkeypatch.setattr(disc, "_my_public_ip", "203.0.113.10")
        monkeypatch.setattr(disc, "get_self_peer_keys", lambda: set())
        monkeypatch.setattr(disc, "get_self_peer_pubs", lambda: set())

    def test_sibling_filtered_by_default(self, monkeypatch):
        self._isolate(monkeypatch)
        monkeypatch.delenv("OBSCURA_ALLOW_LAN_PEERS", raising=False)
        sibling = {"host": "203.0.113.10", "port": 9999, "pub": "sibling-pub"}
        assert disc.is_self_peer(sibling) is True

    def test_sibling_usable_in_lan_mode(self, monkeypatch):
        self._isolate(monkeypatch)
        monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "1")
        sibling = {"host": "203.0.113.10", "port": 9999, "pub": "sibling-pub"}
        assert disc.is_self_peer(sibling) is False

    def test_publess_collapsed_entry_stays_self_in_lan_mode(self, monkeypatch):
        self._isolate(monkeypatch)
        monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "1")
        entry = {"host": "203.0.113.10", "port": 9999}  # no pubkey to prove identity
        assert disc.is_self_peer(entry) is True

    def test_own_hostport_always_self_even_in_lan_mode(self, monkeypatch):
        monkeypatch.setattr(disc, "_my_public_ip", "203.0.113.10")
        monkeypatch.setattr(disc, "get_self_peer_keys",
                            lambda: {("203.0.113.10", 5001)})
        monkeypatch.setattr(disc, "get_self_peer_pubs", lambda: set())
        monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "1")
        me = {"host": "203.0.113.10", "port": 5001, "pub": "sibling-pub"}
        assert disc.is_self_peer(me) is True
