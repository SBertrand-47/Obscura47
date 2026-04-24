"""Unit tests for hidden-service relay handling in ObscuraNode.

Exercises the intro-point and rendezvous-point logic directly by
calling the internal handlers — no real sockets or circuits.
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
        self._hs_pubs = {}
        self._rv_cookies = {}
        self._rv_pairs = {}
        self._hs_lock = threading.Lock()
        self._reverse_channels = {}
        self._reverse_lock = threading.Lock()
        self.sent = []  # list of (target_request_id, inner_dict)

    def register_channel(self, req_id, pub):
        self._reverse_channels[req_id] = lambda s: self._capture(req_id, s)
        self._hs_pubs[req_id] = pub

    def _capture(self, req_id, raw):
        frame = json.loads(raw)
        self.sent.append((req_id, frame))


def _bind_hs(fake):
    from src.core import node as node_mod
    for name in (
        '_hs_send_reverse',
        '_hs_terminal_establish', '_hs_terminal_introduce',
        '_rv_terminal_establish', '_rv_terminal_join',
        '_rv_terminal_data', '_rv_terminal_close',
        '_process_hs_frame',
    ):
        setattr(fake, name, types.MethodType(getattr(node_mod.ObscuraNode, name), fake))
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
    _, host_pub = ecc_generate_keypair()
    fake.register_channel('HOST1', host_pub)
    fake._hs_terminal_establish({
        'type': 'hs_establish', 'request_id': 'HOST1',
        'service_addr': 'svc.obscura', 'pub': host_pub,
    })
    assert fake._hs_services['svc.obscura'] == 'HOST1'


def test_introduce_is_relayed_to_host(fake):
    host_priv, host_pub = ecc_generate_keypair()
    fake.register_channel('HOST1', host_pub)
    fake._hs_terminal_establish({
        'type': 'hs_establish', 'request_id': 'HOST1',
        'service_addr': 'svc.obscura', 'pub': host_pub,
    })
    fake._hs_terminal_introduce({
        'type': 'hs_introduce', 'request_id': 'INTRO1',
        'service_addr': 'svc.obscura',
        'introduce_payload': 'OPAQUE_SEALED_BLOB',
    })
    assert len(fake.sent) == 1
    target, frame = fake.sent[0]
    assert target == 'HOST1'
    inner = _decode_reverse(frame, host_priv)
    assert inner == {
        'type': 'hs_introduce',
        'service_addr': 'svc.obscura',
        'introduce_payload': 'OPAQUE_SEALED_BLOB',
    }


def test_introduce_to_unknown_service_is_dropped(fake):
    fake._hs_terminal_introduce({
        'type': 'hs_introduce', 'request_id': 'INTRO1',
        'service_addr': 'missing.obscura',
        'introduce_payload': 'BLOB',
    })
    assert fake.sent == []


def test_rv_join_splices_and_notifies_both_sides(fake):
    host_priv, host_pub = ecc_generate_keypair()
    client_priv, client_pub = ecc_generate_keypair()
    fake.register_channel('CLIENT1', client_pub)

    fake._rv_terminal_establish({
        'type': 'rv_establish', 'request_id': 'CLIENT1',
        'cookie': 'COOKIE123', 'pub': client_pub,
    })
    assert fake._rv_cookies['COOKIE123'] == 'CLIENT1'

    fake.register_channel('HOST_RV1', host_pub)
    fake._rv_terminal_join({
        'type': 'rv_join', 'request_id': 'HOST_RV1',
        'cookie': 'COOKIE123', 'pub': host_pub,
    })
    # Cookie consumed, pair recorded both directions.
    assert 'COOKIE123' not in fake._rv_cookies
    assert fake._rv_pairs['CLIENT1'] == 'HOST_RV1'
    assert fake._rv_pairs['HOST_RV1'] == 'CLIENT1'

    # rv_ready delivered to both sides.
    by_target = {target: frame for target, frame in fake.sent}
    assert set(by_target.keys()) == {'CLIENT1', 'HOST_RV1'}
    client_inner = _decode_reverse(by_target['CLIENT1'], client_priv)
    host_inner = _decode_reverse(by_target['HOST_RV1'], host_priv)
    assert client_inner == {'type': 'rv_ready', 'request_id': 'CLIENT1'}
    assert host_inner == {'type': 'rv_ready', 'request_id': 'HOST_RV1'}


def test_rv_join_with_unknown_cookie_is_dropped(fake):
    _, host_pub = ecc_generate_keypair()
    fake.register_channel('HOST_RV1', host_pub)
    fake._rv_terminal_join({
        'type': 'rv_join', 'request_id': 'HOST_RV1',
        'cookie': 'UNKNOWN', 'pub': host_pub,
    })
    assert fake._rv_pairs == {}
    assert fake.sent == []


def test_data_splices_in_both_directions(fake):
    host_priv, host_pub = ecc_generate_keypair()
    client_priv, client_pub = ecc_generate_keypair()
    fake.register_channel('CLIENT1', client_pub)
    fake.register_channel('HOST_RV1', host_pub)
    fake._rv_terminal_establish({
        'type': 'rv_establish', 'request_id': 'CLIENT1',
        'cookie': 'CK', 'pub': client_pub,
    })
    fake._rv_terminal_join({
        'type': 'rv_join', 'request_id': 'HOST_RV1',
        'cookie': 'CK', 'pub': host_pub,
    })
    fake.sent.clear()

    # Client → host
    fake._rv_terminal_data({
        'type': 'hs_data', 'request_id': 'CLIENT1', 'chunk': 'Zm9v',
    })
    assert len(fake.sent) == 1
    target, frame = fake.sent[0]
    assert target == 'HOST_RV1'
    inner = _decode_reverse(frame, host_priv)
    assert inner == {'type': 'hs_data', 'request_id': 'HOST_RV1', 'chunk': 'Zm9v'}
    fake.sent.clear()

    # Host → client
    fake._rv_terminal_data({
        'type': 'hs_data', 'request_id': 'HOST_RV1', 'chunk': 'YmFy',
    })
    assert len(fake.sent) == 1
    target, frame = fake.sent[0]
    assert target == 'CLIENT1'
    inner = _decode_reverse(frame, client_priv)
    assert inner == {'type': 'hs_data', 'request_id': 'CLIENT1', 'chunk': 'YmFy'}


def test_close_propagates_to_paired_side(fake):
    host_priv, host_pub = ecc_generate_keypair()
    _, client_pub = ecc_generate_keypair()
    fake.register_channel('CLIENT1', client_pub)
    fake.register_channel('HOST_RV1', host_pub)
    fake._rv_terminal_establish({
        'type': 'rv_establish', 'request_id': 'CLIENT1',
        'cookie': 'CK', 'pub': client_pub,
    })
    fake._rv_terminal_join({
        'type': 'rv_join', 'request_id': 'HOST_RV1',
        'cookie': 'CK', 'pub': host_pub,
    })
    fake.sent.clear()

    fake._rv_terminal_close({'type': 'hs_close', 'request_id': 'CLIENT1'})
    assert len(fake.sent) == 1
    target, frame = fake.sent[0]
    assert target == 'HOST_RV1'
    assert frame['type'] == 'reverse_close'
    inner = _decode_reverse(frame, host_priv)
    assert inner == {'type': 'hs_close', 'request_id': 'HOST_RV1'}
    # Pair removed both ways.
    assert 'CLIENT1' not in fake._rv_pairs
    assert 'HOST_RV1' not in fake._rv_pairs
