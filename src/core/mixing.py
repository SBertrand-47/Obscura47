"""Timing defenses and cover traffic for traffic-analysis resistance.

This module sits on a relay's forward path and implements the optional
timing layer of the network's traffic-analysis defenses:

* **Jitter** (Layer 3a) - a small uniform random delay before forwarding
  each frame.
* **Poisson mixing** (Layer 4) - each forwarded cell is held in a pool and
  released after an exponential (memoryless) delay, so the timing of cells
  leaving a relay is statistically decoupled from the timing of cells
  arriving. This is what actually defeats end-to-end timing correlation,
  at the cost of latency.
* **Cover traffic** (Layer 3b) - background "drop" cells emitted to random
  neighbours at a Poisson rate. They are ordinary fixed-size onion frames
  that decrypt to ``{"type": "drop"}`` and are silently discarded by the
  receiving relay, so a link observer cannot distinguish them from real
  traffic.

**Ordering guarantee.** Tunnel data is an ordered byte stream chopped into
chunks, so cells carrying the same ``stream_key`` (request_id) must never
overtake one another. The scheduler enforces per-stream FIFO release while
still allowing cells of *different* streams to be reordered - reordering
across flows is exactly what frustrates correlation, whereas reordering
within a flow would corrupt the stream.

All of this is opt-in via config; with every knob off, ``submit`` runs the
send synchronously and in order, so the relay behaves exactly as it did
before this module existed.
"""

import heapq
import random
import threading
import time

from src.core.encryptions import onion_encrypt_for_peer
from src.utils.logger import get_logger
from src.utils import config

log = get_logger(__name__)


def _timing_active() -> bool:
    """True when any delaying defense (jitter or mixing) is enabled."""
    return bool(
        config.MIX_ENABLED
        or (config.MIX_JITTER_ENABLED and config.MIX_JITTER_MAX_MS > 0)
    )


def _draw_delay() -> float:
    """Pick a forward delay (seconds) per the active timing policy.

    Mixing takes precedence over plain jitter when both are enabled, since
    the exponential pool delay subsumes a uniform jitter.
    """
    if config.MIX_ENABLED and config.MIX_MEAN_DELAY_MS > 0:
        mean = config.MIX_MEAN_DELAY_MS / 1000.0
        return random.expovariate(1.0 / mean)
    if config.MIX_JITTER_ENABLED and config.MIX_JITTER_MAX_MS > 0:
        return random.uniform(0, config.MIX_JITTER_MAX_MS / 1000.0)
    return 0.0


class MixScheduler:
    """A delay queue that releases forward operations on a timing schedule.

    Each submitted callable is released either immediately (defenses off) or
    after a drawn delay, with per-stream FIFO preserved.
    """

    def __init__(self):
        self._heap = []                  # (release_ts, seq, fn)
        self._seq = 0
        self._stream_tail = {}           # stream_key -> last scheduled release_ts
        self._cv = threading.Condition()
        self._started = False

    def start(self):
        with self._cv:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._run, daemon=True, name="mix-scheduler").start()

    def submit(self, fn, stream_key=None):
        """Schedule ``fn`` (a zero-arg send) for delayed, ordered release.

        With no timing defense active, ``fn`` runs synchronously and in
        order on the caller's thread - identical to the pre-mixing path.
        ``stream_key`` (e.g. a request_id) preserves FIFO order among cells
        of the same stream; pass ``None`` for order-independent control
        frames.
        """
        if not _timing_active():
            fn()
            return

        self.start()
        delay = _draw_delay()
        now = time.time()
        with self._cv:
            base = now
            if stream_key is not None:
                # Never release before the previous cell of this stream, so
                # within-stream order is preserved despite random delays.
                base = max(now, self._stream_tail.get(stream_key, 0.0))
            release = base + delay
            if stream_key is not None:
                self._stream_tail[stream_key] = release
            heapq.heappush(self._heap, (release, self._seq, fn))
            self._seq += 1
            self._cv.notify()

    def _run(self):
        while True:
            with self._cv:
                while not self._heap:
                    self._cv.wait()
                release, _seq, fn = self._heap[0]
                now = time.time()
                if release > now:
                    self._cv.wait(timeout=release - now)
                    continue
                heapq.heappop(self._heap)
                # Opportunistically prune stale per-stream tails so the map
                # doesn't grow without bound on a long-lived relay.
                if len(self._stream_tail) > 4096:
                    cutoff = now
                    self._stream_tail = {
                        k: v for k, v in self._stream_tail.items() if v > cutoff
                    }
            try:
                fn()
            except Exception as e:
                log.error("mix release error: %s", e)


# Process-wide scheduler shared by every forward path in this node.
SCHEDULER = MixScheduler()


def submit_forward(fn, stream_key=None):
    """Module-level convenience wrapper around the shared scheduler."""
    SCHEDULER.submit(fn, stream_key=stream_key)


# ── Cover traffic (chaff) ──────────────────────────────────────────

def is_drop_frame(layer) -> bool:
    """True if a decrypted onion layer is a cover-traffic drop cell."""
    return isinstance(layer, dict) and layer.get("type") == "drop"


def _send_drop_cell(node, peer) -> bool:
    """Seal and send one indistinguishable drop cell to ``peer``."""
    pub = peer.get("pub")
    if not pub:
        return False
    try:
        import json
        sealed = onion_encrypt_for_peer(pub, json.dumps({"type": "drop"}))
        node.router.send_to_next_hop(peer, sealed)
        return True
    except Exception as e:
        log.debug("cover send failed to %s: %s", peer.get("host"), e)
        return False


def start_cover_traffic(node):
    """Start a background thread emitting Poisson-timed cover cells.

    No-op unless ``COVER_ENABLED``. Picks a random healthy peer for each
    cell so cover is spread across the node's links.
    """
    if not config.COVER_ENABLED:
        return

    def _loop():
        from src.core import peer_health
        mean = max(config.COVER_MEAN_INTERVAL_MS, 1.0) / 1000.0
        while getattr(node, "running", True):
            time.sleep(random.expovariate(1.0 / mean))
            try:
                pool = peer_health.filter_healthy(list(node.peers)) or list(node.peers)
                candidates = [p for p in pool if p.get("pub")]
                if not candidates:
                    continue
                _send_drop_cell(node, random.choice(candidates))
            except Exception as e:
                log.debug("cover loop error: %s", e)

    threading.Thread(target=_loop, daemon=True, name="cover-traffic").start()
    log.info("Cover traffic enabled (mean interval %.0f ms)", config.COVER_MEAN_INTERVAL_MS)
