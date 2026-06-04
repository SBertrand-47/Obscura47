"""LAN/RFC1918 peer filtering for intro and rendezvous selection.

Both `HiddenServiceHost._pick_intro_points` (host side) and
`rendezvous._pick_rendezvous_point` (dialer side) need to skip private
addresses so a host on one LAN cannot strand remote dialers by
advertising / proposing a peer that has no externally-routable path.
"""

from __future__ import annotations

import types
import pytest


PUBLIC_A = {
    "host": "95.173.221.72", "port": 5001, "role": "node",
    "pub": "PUB-A", "ws_port": 5002,
}
PUBLIC_B = {
    "host": "154.38.172.2", "port": 5001, "role": "node",
    "pub": "PUB-B", "ws_port": 5002,
}
PUBLIC_C = {
    "host": "164.119.5.12", "port": 5001, "role": "node",
    "pub": "PUB-C", "ws_port": 5002,
}
LAN_PEER = {
    "host": "192.168.1.86", "port": 5001, "role": "node",
    "pub": "PUB-LAN", "ws_port": 5002,
}
# A public node registered with NO ws_port - exactly how the gateway peer
# (142.56.46.175) appeared in the registry. It cannot be reachability-probed
# or maintained as an intro circuit, so it must be excluded.
NO_WS_PEER = {
    "host": "142.56.46.175", "port": 5001, "role": "node",
    "pub": "PUB-NOWS", "ws_port": None,
}


@pytest.fixture(autouse=True)
def _no_lan_override(monkeypatch):
    """Make sure the opt-in env var is unset for every test by default."""
    monkeypatch.delenv("OBSCURA_ALLOW_LAN_PEERS", raising=False)


@pytest.fixture(autouse=True)
def _stub_intro_probe(monkeypatch):
    """Stub host-side reachability probe so IP-class tests don't hit the
    network. The intro picker probes each candidate's WS port before
    publishing; the synthetic peers in these tests can't accept TCP, so
    without the stub every probe would fail and erase the filter logic
    under test."""
    from src.core import peer_health
    monkeypatch.setattr(peer_health, "probe_tcp", lambda *a, **k: (True, ""))
    peer_health.reset()


def _fake_host():
    """Build a HiddenServiceHost-shaped object without running __init__."""
    from src.core import hidden_service as hs_mod
    fake = types.SimpleNamespace(address="svc.obscura")
    fake._pick_intro_points = types.MethodType(
        hs_mod.HiddenServiceHost._pick_intro_points, fake,
    )
    return fake


# ---------------------------------------------------------------------------
# Intro-point selection
# ---------------------------------------------------------------------------


def test_pick_intro_skips_private_peer_by_default(monkeypatch):
    from src.core import internet_discovery as disc
    monkeypatch.setattr(disc, "is_self_peer", lambda p: False)

    host = _fake_host()
    peers = [LAN_PEER, PUBLIC_A, PUBLIC_B]
    picked = host._pick_intro_points(peers, count=3)
    picked_hosts = {p["host"] for p in picked}

    assert LAN_PEER["host"] not in picked_hosts
    assert picked_hosts == {PUBLIC_A["host"], PUBLIC_B["host"]}


def test_pick_intro_skips_peer_without_ws_port(monkeypatch):
    """A public peer with no ws_port must be excluded: it cannot be probed for
    reachability nor maintained as a live intro circuit, so advertising it
    strands every dial. probe_tcp is stubbed to PASS here, so the old code
    (which skipped the probe for ws-less peers and appended them) would wrongly
    include it - this guards that regression."""
    from src.core import internet_discovery as disc
    monkeypatch.setattr(disc, "is_self_peer", lambda p: False)

    host = _fake_host()
    picked = host._pick_intro_points([NO_WS_PEER, PUBLIC_A], count=3)
    picked_hosts = {p["host"] for p in picked}

    assert NO_WS_PEER["host"] not in picked_hosts
    assert picked_hosts == {PUBLIC_A["host"]}


def test_pick_intro_falls_back_to_lan_when_no_public(monkeypatch):
    """If the public pool is empty (all self-filtered), still publish.

    The host can't reach anyone, but exposing an intro at all is better
    than going dark - the diagnose dial-step now catches the result.
    """
    from src.core import internet_discovery as disc
    monkeypatch.setattr(disc, "is_self_peer", lambda p: p["pub"] == "PUB-A")

    host = _fake_host()
    peers = [PUBLIC_A, LAN_PEER]  # only PUBLIC_A is "self", LAN is non-public
    picked = host._pick_intro_points(peers, count=3)
    picked_hosts = {p["host"] for p in picked}

    # PUBLIC_A is self -> dropped. LAN_PEER is private -> normally dropped,
    # but fallback kicks in because there are no public non-self candidates.
    assert LAN_PEER["host"] in picked_hosts


def test_pick_intro_respects_lan_opt_in(monkeypatch):
    from src.core import internet_discovery as disc
    monkeypatch.setattr(disc, "is_self_peer", lambda p: False)
    monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "1")

    host = _fake_host()
    peers = [LAN_PEER, PUBLIC_A]
    picked = host._pick_intro_points(peers, count=3)
    picked_hosts = {p["host"] for p in picked}

    assert LAN_PEER["host"] in picked_hosts
    assert PUBLIC_A["host"] in picked_hosts


# ---------------------------------------------------------------------------
# Rendezvous-point selection
# ---------------------------------------------------------------------------


def test_pick_rv_skips_private_peer_by_default(monkeypatch):
    from src.core import internet_discovery as disc
    from src.core import rendezvous as rv

    monkeypatch.setattr(disc, "is_self_peer", lambda p: False)

    peers = [LAN_PEER, PUBLIC_A, PUBLIC_B, PUBLIC_C]
    seen = set()
    for _ in range(50):
        rv_point = rv._pick_rendezvous_point(peers, exclude=set())
        assert rv_point is not None
        seen.add(rv_point["host"])
    assert LAN_PEER["host"] not in seen
    # And the public ones should be picked plausibly often.
    assert seen <= {PUBLIC_A["host"], PUBLIC_B["host"], PUBLIC_C["host"]}


def test_pick_rv_returns_none_when_only_private(monkeypatch):
    from src.core import internet_discovery as disc
    from src.core import rendezvous as rv

    monkeypatch.setattr(disc, "is_self_peer", lambda p: False)

    peers = [LAN_PEER]
    assert rv._pick_rendezvous_point(peers, exclude=set()) is None


def test_pick_rv_respects_lan_opt_in(monkeypatch):
    from src.core import internet_discovery as disc
    from src.core import rendezvous as rv

    monkeypatch.setattr(disc, "is_self_peer", lambda p: False)
    monkeypatch.setenv("OBSCURA_ALLOW_LAN_PEERS", "1")

    peers = [LAN_PEER]
    rv_point = rv._pick_rendezvous_point(peers, exclude=set())
    assert rv_point is not None
    assert rv_point["host"] == LAN_PEER["host"]
