"""Unit tests for hidden-service terminal handling in ObscuraNode.

Exercises the meeting-point logic directly by calling the internal
handlers — no real sockets or circuits.
"""
import json
import types

import pytest

from src.core.encryptions import ecc_generate_keypair, onion_decrypt_with_priv


class FakeNode:
    """Stand-in with just the state/methods the HS handlers touch."""

    def __init__(self):
        import threading
        self._hs_services = {}
        self._hs_sessions = {}
        self._hs_pubs = {}
        self._hs_lock = threading.Lock()
        self._reverse_channels = {}
        self._reverse_lock = threading.Lock()
        self.sent = []  # list of (target_request_id, inner_dict)

    # Copy the real methods by binding them to this fake.
    def register_channel(self, req_id, pub):
        """Helper — simulate an established circuit."""
        self._reverse_channels[req_id] = lambda s: self._capture(req_id, s)
        self._hs_pubs[req_id] = pub

    def _capture(self, req_id, raw):
        """Store reverse frames emitted by the node under test."""
        frame = json.loads(raw)
        self.sent.append((req_id, frame))


def _bind_hs(fake):
    from src.core import node as node_mod
    for name in (
        '_hs_send_reverse', '_hs_terminal_establish', '_hs_terminal_connect',
        '_hs_terminal_data', '_hs_terminal_close', '_process_hs_frame',
    ):
        setattr(fake, name, types.MethodType(getattr(node_mod.ObscuraNode, name), fake))
    # forward_message is unused for terminal-only tests, but stub it.
    fake.router = types.SimpleNamespace(forward_message=lambda *a, **k: None)


def _decode_reverse(frame, priv):
    inner_json = onion_decrypt_with_priv(priv, frame['encrypted_response'])
    return json.loads(inner_json)


@pytest.fixture
def fake():
    f = FakeNode()
    _bind_hs(f)
    return f


def test_establish_registers_service(fake):
    host_priv, host_pub = ecc_generate_keypair()
    fake.register_channel('HOST1', host_pub)
    fake._hs_terminal_establish({
        'type': 'hs_establish',
        'request_id': 'HOST1',
        'service_addr': 'svc.obscura',
        'pub': host_pub,
    })
    assert fake._hs_services['svc.obscura'] == 'HOST1'


def test_connect_notifies_host(fake):
    host_priv, host_pub = ecc_generate_keypair()
    _, client_pub = ecc_generate_keypair()
    fake.register_channel('HOST1', host_pub)
    fake._hs_terminal_establish({
        'type': 'hs_establish', 'request_id': 'HOST1',
        'service_addr': 'svc.obscura', 'pub': host_pub,
    })
    fake.register_channel('CLIENT1', client_pub)
    fake._hs_terminal_connect({
        'type': 'hs_connect', 'request_id': 'CLIENT1',
        'service_addr': 'svc.obscura', 'pub': client_pub,
    })
    # Host should have received an hs_incoming notification.
    assert len(fake.sent) == 1
    target, frame = fake.sent[0]
    assert target == 'HOST1'
    inner = _decode_reverse(frame, host_priv)
    assert inner['type'] == 'hs_incoming'
    assert inner['session_id'] == 'CLIENT1'
    assert inner['service_addr'] == 'svc.obscura'
    assert inner['client_pub'] == client_pub


def test_connect_to_unknown_service_closes_client(fake):
    _, client_pub = ecc_generate_keypair()
    client_priv, _ = ecc_generate_keypair()  # unrelated
    fake.register_channel('CLIENT1', client_pub)
    fake._hs_terminal_connect({
        'type': 'hs_connect', 'request_id': 'CLIENT1',
        'service_addr': 'missing.obscura', 'pub': client_pub,
    })
    assert len(fake.sent) == 1
    _, frame = fake.sent[0]
    assert frame['type'] == 'reverse_close'


def test_data_client_to_host_and_back(fake):
    host_priv, host_pub = ecc_generate_keypair()
    client_priv, client_pub = ecc_generate_keypair()
    fake.register_channel('HOST1', host_pub)
    fake.register_channel('CLIENT1', client_pub)
    fake._hs_terminal_establish({
        'type': 'hs_establish', 'request_id': 'HOST1',
        'service_addr': 'svc.obscura', 'pub': host_pub,
    })
    fake._hs_terminal_connect({
        'type': 'hs_connect', 'request_id': 'CLIENT1',
        'service_addr': 'svc.obscura', 'pub': client_pub,
    })
    fake.sent.clear()

    # Client → host
    fake._hs_terminal_data({
        'type': 'hs_data', 'request_id': 'CLIENT1', 'chunk': 'Zm9v',
    })
    assert len(fake.sent) == 1
    target, frame = fake.sent[0]
    assert target == 'HOST1'
    inner = _decode_reverse(frame, host_priv)
    assert inner == {'type': 'hs_data', 'session_id': 'CLIENT1', 'chunk': 'Zm9v'}
    fake.sent.clear()

    # Host → client
    fake._hs_terminal_data({
        'type': 'hs_data', 'request_id': 'HOST1',
        'session_id': 'CLIENT1', 'chunk': 'YmFy',
    })
    assert len(fake.sent) == 1
    target, frame = fake.sent[0]
    assert target == 'CLIENT1'
    inner = _decode_reverse(frame, client_priv)
    assert inner == {'type': 'hs_data', 'request_id': 'CLIENT1', 'chunk': 'YmFy'}


def test_client_close_notifies_host(fake):
    host_priv, host_pub = ecc_generate_keypair()
    _, client_pub = ecc_generate_keypair()
    fake.register_channel('HOST1', host_pub)
    fake.register_channel('CLIENT1', client_pub)
    fake._hs_terminal_establish({
        'type': 'hs_establish', 'request_id': 'HOST1',
        'service_addr': 'svc.obscura', 'pub': host_pub,
    })
    fake._hs_terminal_connect({
        'type': 'hs_connect', 'request_id': 'CLIENT1',
        'service_addr': 'svc.obscura', 'pub': client_pub,
    })
    fake.sent.clear()
    fake._hs_terminal_close({'type': 'hs_close', 'request_id': 'CLIENT1'})
    assert len(fake.sent) == 1
    target, frame = fake.sent[0]
    assert target == 'HOST1'
    assert frame['type'] == 'reverse_close'
    inner = _decode_reverse(frame, host_priv)
    assert inner == {'type': 'hs_close', 'session_id': 'CLIENT1'}
    # Session cleaned up.
    assert 'CLIENT1' not in fake._hs_sessions
