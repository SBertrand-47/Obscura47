"""Unit tests for the caller-identity registry."""

from __future__ import annotations

import threading

import pytest

from src.utils.identity import (
    caller_session,
    clear_callers,
    fingerprint_pubkey,
    lookup_caller,
    register_caller,
    unregister_caller,
)


@pytest.fixture(autouse=True)
def _reset_registry():
    clear_callers()
    yield
    clear_callers()


PUB_A = "-----BEGIN PUBLIC KEY-----\nA\n-----END PUBLIC KEY-----\n"
PUB_B = "-----BEGIN PUBLIC KEY-----\nB\n-----END PUBLIC KEY-----\n"


def test_register_and_lookup_returns_pub():
    register_caller(("127.0.0.1", 50001), PUB_A)
    assert lookup_caller(("127.0.0.1", 50001)) == PUB_A


def test_unregister_removes_mapping():
    register_caller(("127.0.0.1", 50001), PUB_A)
    unregister_caller(("127.0.0.1", 50001))
    assert lookup_caller(("127.0.0.1", 50001)) is None


def test_lookup_unknown_returns_none():
    assert lookup_caller(("127.0.0.1", 65535)) is None


def test_lookup_with_none_addr_returns_none():
    assert lookup_caller(None) is None


def test_register_overwrites_previous_pub():
    register_caller(("127.0.0.1", 50001), PUB_A)
    register_caller(("127.0.0.1", 50001), PUB_B)
    assert lookup_caller(("127.0.0.1", 50001)) == PUB_B


def test_register_skips_empty_pub():
    register_caller(("127.0.0.1", 50001), "")
    assert lookup_caller(("127.0.0.1", 50001)) is None


def test_ipv6_loopback_normalises_to_ipv4():
    register_caller(("::1", 50002), PUB_A)
    assert lookup_caller(("127.0.0.1", 50002)) == PUB_A


def test_caller_session_registers_and_cleans_up():
    addr = ("127.0.0.1", 50003)
    with caller_session(addr, PUB_A):
        assert lookup_caller(addr) == PUB_A
    assert lookup_caller(addr) is None


def test_caller_session_cleans_up_on_exception():
    addr = ("127.0.0.1", 50004)
    with pytest.raises(RuntimeError):
        with caller_session(addr, PUB_A):
            assert lookup_caller(addr) == PUB_A
            raise RuntimeError("boom")
    assert lookup_caller(addr) is None


def test_concurrent_register_and_lookup_are_thread_safe():
    addrs = [("127.0.0.1", 50100 + i) for i in range(50)]

    def _writer():
        for a in addrs:
            register_caller(a, PUB_A)

    def _reader():
        for a in addrs:
            lookup_caller(a)

    threads = [threading.Thread(target=_writer) for _ in range(4)]
    threads += [threading.Thread(target=_reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for a in addrs:
        assert lookup_caller(a) == PUB_A


def test_fingerprint_is_deterministic_hex_sha256():
    fp1 = fingerprint_pubkey(PUB_A)
    fp2 = fingerprint_pubkey(PUB_A)
    assert fp1 == fp2
    assert isinstance(fp1, str)
    assert len(fp1) == 64
    assert all(c in "0123456789abcdef" for c in fp1)


def test_fingerprint_different_keys_differ():
    assert fingerprint_pubkey(PUB_A) != fingerprint_pubkey(PUB_B)


def test_fingerprint_none_or_empty_returns_none():
    assert fingerprint_pubkey(None) is None
    assert fingerprint_pubkey("") is None
