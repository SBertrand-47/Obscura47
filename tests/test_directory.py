"""Tests for src.agent.directory — .obscura discovery surface."""

from __future__ import annotations

import json
import os
import time

import pytest

from src.agent.directory import (
    DirectoryState,
    Listing,
    build_directory_app,
    _listing_dict,
)


VALID_ADDR = "abcdefghijklmnop.obscura"
VALID_ADDR_2 = "zyxwvutsrqponmlk.obscura"
CALLER_A = "aaa" * 22  # 66-char hex
CALLER_B = "bbb" * 22


class TestDirectoryState:
    def test_register_and_get(self):
        ds = DirectoryState()
        listing = ds.register(VALID_ADDR, CALLER_A, title="My Site")
        assert listing.address == VALID_ADDR
        assert listing.title == "My Site"
        assert listing.registered_by == CALLER_A
        got = ds.get(VALID_ADDR)
        assert got is not None
        assert got.address == VALID_ADDR

    def test_register_invalid_address(self):
        ds = DirectoryState()
        with pytest.raises(ValueError, match="invalid"):
            ds.register("not-an-address", CALLER_A)

    def test_register_update_own(self):
        ds = DirectoryState()
        ds.register(VALID_ADDR, CALLER_A, title="v1")
        listing = ds.register(VALID_ADDR, CALLER_A, title="v2")
        assert listing.title == "v2"

    def test_register_reject_other_owner(self):
        ds = DirectoryState()
        ds.register(VALID_ADDR, CALLER_A)
        with pytest.raises(PermissionError):
            ds.register(VALID_ADDR, CALLER_B)

    def test_unregister(self):
        ds = DirectoryState()
        ds.register(VALID_ADDR, CALLER_A)
        assert ds.unregister(VALID_ADDR, CALLER_A)
        assert ds.get(VALID_ADDR) is None

    def test_unregister_not_found(self):
        ds = DirectoryState()
        assert not ds.unregister(VALID_ADDR, CALLER_A)

    def test_unregister_wrong_caller(self):
        ds = DirectoryState()
        ds.register(VALID_ADDR, CALLER_A)
        with pytest.raises(PermissionError):
            ds.unregister(VALID_ADDR, CALLER_B)

    def test_search_all(self):
        ds = DirectoryState()
        ds.register(VALID_ADDR, CALLER_A, title="Alpha")
        ds.register(VALID_ADDR_2, CALLER_B, title="Beta")
        results = ds.search()
        assert len(results) == 2

    def test_search_by_query(self):
        ds = DirectoryState()
        ds.register(VALID_ADDR, CALLER_A, title="Alpha Blog")
        ds.register(VALID_ADDR_2, CALLER_B, title="Beta Shop")
        results = ds.search(query="blog")
        assert len(results) == 1
        assert results[0].title == "Alpha Blog"

    def test_search_by_tag(self):
        ds = DirectoryState()
        ds.register(VALID_ADDR, CALLER_A, tags=["tech", "ai"])
        results = ds.search(query="ai")
        assert len(results) == 1

    def test_search_limit(self):
        ds = DirectoryState()
        ds.register(VALID_ADDR, CALLER_A)
        ds.register(VALID_ADDR_2, CALLER_B)
        results = ds.search(limit=1)
        assert len(results) == 1

    def test_count(self):
        ds = DirectoryState()
        assert ds.count == 0
        ds.register(VALID_ADDR, CALLER_A)
        assert ds.count == 1


class TestPersistence:
    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "dir.json")
        ds1 = DirectoryState(state_path=path)
        ds1.register(VALID_ADDR, CALLER_A, title="Persisted")
        assert os.path.isfile(path)

        ds2 = DirectoryState(state_path=path)
        got = ds2.get(VALID_ADDR)
        assert got is not None
        assert got.title == "Persisted"

    def test_corrupt_file(self, tmp_path):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as f:
            f.write("not json")
        ds = DirectoryState(state_path=path)
        assert ds.count == 0


class TestListingDict:
    def test_keys(self):
        listing = Listing(
            address=VALID_ADDR,
            title="Test",
            description="desc",
            tags=["a"],
            registered_by=CALLER_A,
            registered_at=1.0,
            last_seen=2.0,
        )
        d = _listing_dict(listing)
        assert d["address"] == VALID_ADDR
        assert d["title"] == "Test"
        assert "registered_by" not in d  # private field


class TestBuildDirectoryApp:
    def test_app_has_index(self):
        app, tools = build_directory_app()
        from src.agent.app import Request
        req = Request(method="GET", path="/", headers={}, body=b"")
        resp = app.dispatch(req)
        assert resp.status == 200
        body = json.loads(resp.body)
        assert body["service"] == "directory.obscura"
        assert body["listings"] == 0

    def test_tool_manifest(self):
        app, tools = build_directory_app()
        names = [t.name for t in tools._tools.values()]
        assert "register" in names
        assert "unregister" in names
        assert "list" in names
        assert "get" in names
