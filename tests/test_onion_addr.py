import base64
import time

import pytest

from src.core.encryptions import ecc_generate_keypair
from src.utils.onion_addr import (
    ADDR_SUFFIX,
    address_from_pubkey,
    build_descriptor,
    is_obscura_address,
    verify_descriptor,
)


@pytest.fixture
def keypair():
    priv, pub_pem = ecc_generate_keypair()
    return priv, pub_pem


def test_address_is_deterministic(keypair):
    _, pub_pem = keypair
    assert address_from_pubkey(pub_pem) == address_from_pubkey(pub_pem)


def test_address_differs_per_key():
    _, pub_a = ecc_generate_keypair()
    _, pub_b = ecc_generate_keypair()
    assert address_from_pubkey(pub_a) != address_from_pubkey(pub_b)


def test_address_format(keypair):
    _, pub_pem = keypair
    addr = address_from_pubkey(pub_pem)
    assert addr.endswith(ADDR_SUFFIX)
    assert is_obscura_address(addr)
    assert is_obscura_address(addr.upper())  # case-insensitive


def test_rejects_non_obscura_hosts():
    assert not is_obscura_address("example.com")
    assert not is_obscura_address("short.obscura")
    assert not is_obscura_address("toolongaddresslabel.obscura")
    assert not is_obscura_address("")


def test_descriptor_round_trip(keypair):
    priv, pub_pem = keypair
    intro = [{"node_id": "n1", "circuit_id": "c1"}]
    desc = build_descriptor(priv, pub_pem, port=8080, intro_points=intro)
    assert verify_descriptor(desc)
    assert desc["addr"] == address_from_pubkey(pub_pem)


def test_rejects_tampered_descriptor(keypair):
    priv, pub_pem = keypair
    desc = build_descriptor(priv, pub_pem, 80, [])
    desc["port"] = 9999  # tamper after sign
    assert not verify_descriptor(desc)


def test_rejects_wrong_key(keypair):
    priv, pub_pem = keypair
    desc = build_descriptor(priv, pub_pem, 80, [])
    _, other_pub = ecc_generate_keypair()
    desc["pubkey"] = other_pub  # addr no longer matches
    assert not verify_descriptor(desc)


def test_rejects_expired(keypair):
    priv, pub_pem = keypair
    desc = build_descriptor(priv, pub_pem, 80, [], ttl=-10)
    assert not verify_descriptor(desc)


def test_rejects_bad_port(keypair):
    priv, pub_pem = keypair
    desc = build_descriptor(priv, pub_pem, 80, [])
    desc["port"] = 0
    assert not verify_descriptor(desc)


def test_nonce_is_unique(keypair):
    priv, pub_pem = keypair
    a = build_descriptor(priv, pub_pem, 80, [])
    b = build_descriptor(priv, pub_pem, 80, [])
    assert a["nonce"] != b["nonce"]
