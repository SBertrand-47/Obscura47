"""Tests for src/core/mixing.py - timing defenses and cover traffic."""
import json
import time
import threading

import pytest

from src.core import mixing
from src.utils import config
from src.core.encryptions import ecc_generate_keypair, onion_encrypt_for_peer


@pytest.fixture(autouse=True)
def _reset_defenses():
    """Snapshot and restore the timing config around each test."""
    saved = (
        config.MIX_ENABLED, config.MIX_MEAN_DELAY_MS,
        config.MIX_JITTER_ENABLED, config.MIX_JITTER_MAX_MS,
        config.COVER_ENABLED,
    )
    config.MIX_ENABLED = False
    config.MIX_JITTER_ENABLED = False
    config.MIX_JITTER_MAX_MS = 0
    config.COVER_ENABLED = False
    yield
    (config.MIX_ENABLED, config.MIX_MEAN_DELAY_MS,
     config.MIX_JITTER_ENABLED, config.MIX_JITTER_MAX_MS,
     config.COVER_ENABLED) = saved


class TestSynchronousFastPath:
    def test_runs_inline_and_in_order_when_disabled(self):
        """With all defenses off, submit must run synchronously, in order,
        on the calling thread - identical to the pre-mixing behaviour."""
        order = []
        caller = threading.get_ident()
        sched = mixing.MixScheduler()
        for i in range(5):
            sched.submit(lambda i=i: order.append((i, threading.get_ident())))
        # Already done synchronously - no sleep needed.
        assert [i for i, _ in order] == [0, 1, 2, 3, 4]
        assert all(tid == caller for _, tid in order)


class TestPerStreamOrdering:
    def test_same_stream_keeps_fifo_despite_inverted_delays(self, monkeypatch):
        """Even when later cells draw SHORTER delays, cells of the same
        stream must release in submission order. Cross-stream reordering is
        allowed; within-stream reordering would corrupt the byte stream."""
        config.MIX_ENABLED = True
        config.MIX_MEAN_DELAY_MS = 50

        # Force descending delays: item 0 waits longest. Without per-stream
        # FIFO this would invert the order.
        delays = iter([0.30, 0.20, 0.10])
        monkeypatch.setattr(mixing, "_draw_delay", lambda: next(delays))

        sched = mixing.MixScheduler()
        done = []
        ev = threading.Event()
        for i in range(3):
            def fn(i=i):
                done.append(i)
                if len(done) == 3:
                    ev.set()
            sched.submit(fn, stream_key="streamA")

        assert ev.wait(timeout=3.0), "cells did not all release"
        assert done == [0, 1, 2]

    def test_different_streams_may_reorder(self, monkeypatch):
        config.MIX_ENABLED = True
        config.MIX_MEAN_DELAY_MS = 50
        delays = iter([0.30, 0.05])  # second stream fires first
        monkeypatch.setattr(mixing, "_draw_delay", lambda: next(delays))

        sched = mixing.MixScheduler()
        done = []
        ev = threading.Event()
        sched.submit(lambda: (done.append("A"), ev.set() if len(done) == 2 else None),
                     stream_key="A")
        sched.submit(lambda: (done.append("B"), ev.set() if len(done) == 2 else None),
                     stream_key="B")
        assert ev.wait(timeout=3.0)
        assert done[0] == "B"  # shorter delay released first


class TestDropCells:
    def test_is_drop_frame(self):
        assert mixing.is_drop_frame({"type": "drop"}) is True
        assert mixing.is_drop_frame({"type": "data"}) is False
        assert mixing.is_drop_frame("nope") is False

    def test_drop_cell_roundtrip_is_recognised(self):
        """A sealed drop cell decrypts to a frame is_drop_frame accepts."""
        from src.core.encryptions import onion_decrypt_with_priv
        priv, pub = ecc_generate_keypair()
        sealed = onion_encrypt_for_peer(pub, json.dumps({"type": "drop"}))
        layer = json.loads(onion_decrypt_with_priv(priv, sealed))
        assert mixing.is_drop_frame(layer)


class TestNodeDiscardsDropCells:
    def test_process_frame_discards_drop_without_forwarding(self):
        """A relay receiving a drop cell must discard it and never forward."""
        from unittest.mock import MagicMock
        from src.core.encryptions import ecc_generate_keypair as gen

        # Build a minimal stand-in with the real process_frame bound.
        from src.core.node import ObscuraNode
        priv, pub = gen()

        class Stub:
            pass
        stub = Stub()
        stub.priv_key = priv
        stub.host, stub.port = "127.0.0.1", 5001
        stub.router = MagicMock()
        stub._reverse_lock = threading.Lock()
        stub._reverse_channels = {}

        sealed = onion_encrypt_for_peer(pub, json.dumps({"type": "drop"}))
        ObscuraNode.process_frame(stub, {"encrypted_data": sealed})

        # No forward of any kind happened.
        stub.router.send_to_next_hop.assert_not_called()
        stub.router.forward_message.assert_not_called()
