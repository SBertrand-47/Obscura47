"""Unit tests for src/core/guards.py and route integration."""
import json
import time
import pytest

from src.core.guards import GuardSet, reset_guards_for_tests
from src.core.router import build_route47, Router


def _peers(n: int) -> list[dict]:
    return [{"host": f"10.0.0.{i}", "port": 5000 + i} for i in range(1, n + 1)]


@pytest.fixture
def guards_path(tmp_path):
    return str(tmp_path / "guards.json")


@pytest.fixture(autouse=True)
def _clear_singleton():
    """Make sure tests don't leak singleton state into each other."""
    reset_guards_for_tests(None)
    yield
    reset_guards_for_tests(None)


# ── GuardSet logic ────────────────────────────────────────────────

class TestGuardSet:
    def test_initial_selection_fills_count(self, guards_path):
        gs = GuardSet(path=guards_path, count=3, lifetime_days=30, down_seconds=600)
        pool = _peers(10)
        first = gs.pick_first_hop(pool)
        assert first is not None
        snap = gs.snapshot()
        assert len(snap) == 3
        # The picked first-hop must be one of the guards
        assert any(g["host"] == first["host"] and g["port"] == first["port"] for g in snap)

    def test_persisted_across_instances(self, guards_path):
        gs1 = GuardSet(path=guards_path, count=3, lifetime_days=30, down_seconds=600)
        gs1.pick_first_hop(_peers(10))
        snap1 = {(g["host"], g["port"]) for g in gs1.snapshot()}

        # Second instance on same file
        gs2 = GuardSet(path=guards_path, count=3, lifetime_days=30, down_seconds=600)
        snap2 = {(g["host"], g["port"]) for g in gs2.snapshot()}
        assert snap1 == snap2
        assert len(snap2) == 3

    def test_pick_returns_only_live_guards(self, guards_path):
        gs = GuardSet(path=guards_path, count=3, lifetime_days=30, down_seconds=600)
        initial_pool = _peers(5)
        gs.pick_first_hop(initial_pool)
        chosen = {(g["host"], g["port"]) for g in gs.snapshot()}

        # Shrink the pool so only ONE of the three guards remains "live"
        surviving = next(iter(chosen))
        restricted_pool = [{"host": surviving[0], "port": surviving[1]}]
        first = gs.pick_first_hop(restricted_pool)
        assert (first["host"], first["port"]) == surviving

    def test_pick_returns_none_when_all_guards_dead(self, guards_path):
        gs = GuardSet(path=guards_path, count=3, lifetime_days=30, down_seconds=600)
        gs.pick_first_hop(_peers(5))

        # Present a pool of completely different peers: no guard is live,
        # but the set is already full so no new guards get pinned.
        # We expect pick_first_hop to return None (no live guards),
        # NOT fall back to an arbitrary candidate — that would defeat pinning.
        brand_new_pool = [{"host": "192.168.99.1", "port": 9999}]
        # Fill is gated on empty slots; since slots are full, brand_new_pool
        # is ignored. All current guards are absent from the pool → no live.
        result = gs.pick_first_hop(brand_new_pool)
        assert result is None

    def test_expired_guards_are_rotated_out(self, guards_path):
        gs = GuardSet(path=guards_path, count=2, lifetime_days=30, down_seconds=600)
        gs.pick_first_hop(_peers(5))
        # Force-expire all existing guards
        stale_time = time.time() - (40 * 86400)
        for g in gs._guards:
            g["first_used"] = stale_time

        # New pick should retire stale guards and repopulate from pool
        gs.pick_first_hop(_peers(5))
        for g in gs.snapshot():
            assert (time.time() - g["first_used"]) < 86400  # freshly pinned

    def test_empty_candidate_pool_returns_none(self, guards_path):
        gs = GuardSet(path=guards_path, count=3, lifetime_days=30, down_seconds=600)
        assert gs.pick_first_hop([]) is None

    def test_guard_metadata_carries_pub_and_ws(self, guards_path):
        gs = GuardSet(path=guards_path, count=1, lifetime_days=30, down_seconds=600)
        pool = [{"host": "1.2.3.4", "port": 5001, "pub": "PEMDATA",
                 "ws_port": 5002, "ws_tls": True}]
        gs.pick_first_hop(pool)
        g = gs.snapshot()[0]
        assert g["pub"] == "PEMDATA"
        assert g["ws_port"] == 5002
        assert g["ws_tls"] is True

    def test_load_tolerates_corrupt_file(self, tmp_path):
        path = str(tmp_path / "corrupt.json")
        with open(path, "w") as f:
            f.write("{not valid json")
        # Should not raise; starts with empty set
        gs = GuardSet(path=path, count=3, lifetime_days=30, down_seconds=600)
        assert gs.snapshot() == []


# ── Router integration ───────────────────────────────────────────

class TestRouterGuardIntegration:
    def test_build_route47_first_hop_is_guard(self, guards_path):
        gs = GuardSet(path=guards_path, count=2, lifetime_days=30, down_seconds=600)
        reset_guards_for_tests(gs)

        pool = _peers(10)
        # Force guards to a known pair
        gs.pick_first_hop(pool)
        pinned = {(g["host"], g["port"]) for g in gs.snapshot()}

        for _ in range(10):
            route = build_route47(pool, min_hops=4, max_hops=7)
            assert len(route) >= 4
            assert (route[0]["host"], route[0]["port"]) in pinned

    def test_build_random_route_first_hop_is_guard(self, guards_path):
        gs = GuardSet(path=guards_path, count=2, lifetime_days=30, down_seconds=600)
        reset_guards_for_tests(gs)

        pool = _peers(6)
        gs.pick_first_hop(pool)
        pinned = {(g["host"], g["port"]) for g in gs.snapshot()}

        r = Router(node=None, peers=pool)
        for _ in range(10):
            route = r.build_random_route(hops=3)
            assert (route[0]["host"], route[0]["port"]) in pinned
            # No duplicates within the route
            keys = [(h["host"], h["port"]) for h in route]
            assert len(keys) == len(set(keys))

    def test_route_building_falls_through_when_guards_disabled(self, guards_path):
        """With no GuardSet installed, routes are pure random sampling."""
        reset_guards_for_tests(None)
        pool = _peers(10)
        # Just ensure nothing crashes and route length is respected
        route = build_route47(pool, min_hops=4, max_hops=4)
        assert len(route) == 4
