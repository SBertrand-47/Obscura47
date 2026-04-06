"""
Obscura47 — Guard Node Pinning

A client-side (proxy) mechanism that commits to a small persistent set of
first-hop relays rather than re-sampling every circuit. This mitigates the
statistical "eventually you'll pick a malicious guard" attack: an adversary
who controls X% of the network would, over time, end up on some circuits as
the first hop; pinning caps that exposure per-client.

Design:
  - Select N guards at first run from the available peer pool.
  - Persist them to disk keyed by (host, port) with first_used / last_seen_up.
  - On route build, pick a live guard from the set as the first hop.
  - Replace dead or stale (past GUARD_LIFETIME_DAYS) guards from the pool.
  - Note: guards are a proxy-local commitment. Relays/exits do not use them.
"""

import json
import os
import random
import threading
import time
from typing import Iterable

from src.utils.logger import get_logger

log = get_logger(__name__)


class GuardSet:
    def __init__(self, path: str, count: int,
                 lifetime_days: int, down_seconds: int):
        self.path = path
        self.count = count
        self.lifetime_seconds = lifetime_days * 86400
        self.down_seconds = down_seconds
        self._lock = threading.Lock()
        # list of dicts: {host, port, pub?, ws_port?, ws_tls?, first_used, last_seen_up}
        self._guards: list[dict] = []
        self._load()

    # ── Persistence ──────────────────────────────────────────────

    def _load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self._guards = [g for g in data if self._is_valid_entry(g)]
        except Exception as e:
            log.error(f"Failed to load {self.path}: {e}")

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._guards, f, indent=2)
            os.replace(tmp, self.path)
        except Exception as e:
            log.error(f"Failed to save {self.path}: {e}")

    @staticmethod
    def _is_valid_entry(g) -> bool:
        return (
            isinstance(g, dict)
            and isinstance(g.get("host"), str)
            and isinstance(g.get("port"), int)
            and isinstance(g.get("first_used"), (int, float))
        )

    # ── Selection / rotation ─────────────────────────────────────

    def _is_expired(self, guard: dict, now: float) -> bool:
        """A guard whose first_used is older than lifetime is rotated out."""
        return (now - guard.get("first_used", now)) > self.lifetime_seconds

    def _is_available(self, guard: dict, candidates_by_key: dict) -> bool:
        """A guard is available if it appears in the current candidate pool."""
        key = (guard["host"], guard["port"])
        return key in candidates_by_key

    def _refresh_from_candidates(self, candidates: list[dict]) -> None:
        """
        Sync guard metadata (pub, ws_port, ws_tls, last_seen_up) from fresh
        candidate data. Drop expired guards. Fill up to `count` from candidates
        that aren't already guards. Caller must hold the lock.
        """
        now = time.time()
        cand_by_key = {(c["host"], c["port"]): c for c in candidates}

        # Update metadata on live guards and drop expired ones
        updated = []
        for g in self._guards:
            if self._is_expired(g, now):
                log.info(f"Retiring expired guard {g['host']}:{g['port']}")
                continue
            fresh = cand_by_key.get((g["host"], g["port"]))
            if fresh:
                g["last_seen_up"] = now
                for field in ("pub", "ws_port", "ws_tls"):
                    if fresh.get(field) is not None:
                        g[field] = fresh[field]
            updated.append(g)
        self._guards = updated

        # Fill empty slots from candidates not already in the guard set
        existing_keys = {(g["host"], g["port"]) for g in self._guards}
        remaining = [c for c in candidates if (c["host"], c["port"]) not in existing_keys]
        random.shuffle(remaining)
        while len(self._guards) < self.count and remaining:
            c = remaining.pop()
            new_guard = {
                "host": c["host"],
                "port": c["port"],
                "first_used": now,
                "last_seen_up": now,
            }
            for field in ("pub", "ws_port", "ws_tls"):
                if c.get(field) is not None:
                    new_guard[field] = c[field]
            self._guards.append(new_guard)
            log.info(f"Pinned new guard {c['host']}:{c['port']}")

    def pick_first_hop(self, candidates: list[dict]) -> dict | None:
        """
        Return a live guard to use as the first hop of a new circuit.
        Refreshes the guard set from `candidates` as a side effect.
        Returns None when no candidates are available at all.
        """
        if not candidates:
            return None
        with self._lock:
            self._refresh_from_candidates(candidates)
            cand_by_key = {(c["host"], c["port"]): c for c in candidates}
            live = [g for g in self._guards if self._is_available(g, cand_by_key)]
            self._save()
        if not live:
            return None
        return dict(random.choice(live))

    def snapshot(self) -> list[dict]:
        """Return a copy of the current guard set (for inspection/tests)."""
        with self._lock:
            return [dict(g) for g in self._guards]


# ── Singleton (proxy-local) ──────────────────────────────────────

_GUARDS: GuardSet | None = None
_singleton_lock = threading.Lock()


def get_guards() -> GuardSet | None:
    """Return the process-wide GuardSet, or None if guards are disabled."""
    return _GUARDS


def init_guards() -> GuardSet | None:
    """Initialize the singleton GuardSet from config. Idempotent."""
    global _GUARDS
    from src.utils.config import (
        GUARD_ENABLED, GUARD_COUNT, GUARD_PATH,
        GUARD_LIFETIME_DAYS, GUARD_DOWN_SECONDS,
    )
    if not GUARD_ENABLED:
        return None
    with _singleton_lock:
        if _GUARDS is None:
            _GUARDS = GuardSet(
                path=GUARD_PATH,
                count=GUARD_COUNT,
                lifetime_days=GUARD_LIFETIME_DAYS,
                down_seconds=GUARD_DOWN_SECONDS,
            )
        return _GUARDS


def reset_guards_for_tests(guard_set: GuardSet | None = None) -> None:
    """Test helper: install or clear the singleton."""
    global _GUARDS
    with _singleton_lock:
        _GUARDS = guard_set
