"""Host-side intro establishment: a hidden service must only advertise intro
points the intro node actually confirmed (acked), so it never publishes a
descriptor naming an intro it cannot reach through the circuit.

These drive HiddenServiceHost.establish() with the network primitives mocked
(no sockets), simulating which intro points ack and asserting which end up in
the published intro set.
"""
import src.core.hidden_service as hs
from src.core.hidden_service import HiddenServiceHost

PEER_A = {'host': '1.1.1.1', 'port': 5001, 'ws_port': 6001, 'pub': 'pubA',
          'role': 'node'}
PEER_B = {'host': '2.2.2.2', 'port': 5001, 'ws_port': 6001, 'pub': 'pubB',
          'role': 'node'}


def _host(tmp_path):
    return HiddenServiceHost("127.0.0.1", 8080, str(tmp_path / "svc.pem"))


def _wire(monkeypatch, host, *, intros, acking_hosts, ack_timeout=0.4):
    """Mock intro selection + routing; ack only the peers in acking_hosts."""
    monkeypatch.setattr(host, '_pick_intro_points', lambda pool, count: list(intros))
    monkeypatch.setattr(hs, 'build_hs_route', lambda pool, term, hops: [term])
    monkeypatch.setattr(hs, 'INTRO_ACK_TIMEOUT', ack_timeout)

    def fake_send(route, env):
        terminal = route[-1]
        if terminal['host'] in acking_hosts:
            # The intro point confirmed: deliver the ack synchronously, the
            # way the reverse channel would.
            host._handle_establish_ack({'request_id': env['request_id']})
        return True

    monkeypatch.setattr(hs, 'send_hs_frame', fake_send)


def test_publishes_only_acked_intros(tmp_path, monkeypatch):
    host = _host(tmp_path)
    _wire(monkeypatch, host, intros=[PEER_A, PEER_B], acking_hosts={'1.1.1.1'})

    assert host.establish(peers=[PEER_A, PEER_B]) is True
    # Only the intro that acked is published; the silent (dead) one is excluded.
    assert [p['host'] for p in host._intro_peers] == ['1.1.1.1']
    assert all(c['peer']['host'] == '1.1.1.1'
               for c in host._intro_circuits.values())


def test_initial_establish_falls_back_when_no_acks(tmp_path, monkeypatch):
    """Against relays that never ack (older build), an initial publish still
    advertises the send-succeeded intros so the host is not stranded."""
    host = _host(tmp_path)
    _wire(monkeypatch, host, intros=[PEER_A, PEER_B], acking_hosts=set())

    assert host.establish(peers=[PEER_A, PEER_B]) is True
    assert {p['host'] for p in host._intro_peers} == {'1.1.1.1', '2.2.2.2'}


def test_refresh_keeps_existing_intros_when_no_acks(tmp_path, monkeypatch):
    """A refresh cycle with no confirmations keeps the last good intro set
    rather than swapping to unconfirmed peers - the live descriptor stays up."""
    host = _host(tmp_path)
    host._intro_peers = [PEER_A]
    host._intro_circuits = {'old': {'peer': PEER_A, 'route': [PEER_A]}}
    _wire(monkeypatch, host, intros=[PEER_B], acking_hosts=set())

    assert host.establish(peers=[PEER_B], refresh=True) is True
    assert host._intro_peers == [PEER_A]


def test_ack_waiters_are_cleaned_up(tmp_path, monkeypatch):
    """establish() must not leak per-request ack Events."""
    host = _host(tmp_path)
    _wire(monkeypatch, host, intros=[PEER_A, PEER_B], acking_hosts={'1.1.1.1'})
    host.establish(peers=[PEER_A, PEER_B])
    assert host._intro_acks == {}
