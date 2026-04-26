"""Tests for src.agent.directory — .obscura discovery surface."""

from __future__ import annotations

import json
import os
import time

import pytest

from src.agent.directory import (
    DirectoryClient,
    DirectoryState,
    Listing,
    build_directory_app,
    fetch_site_manifest,
    normalize_site_manifest,
    _listing_dict,
)
from src.agent.app import Request


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


class TestManifestHelpers:
    def test_normalize_manifest_accepts_valid_fields(self):
        out = normalize_site_manifest(
            VALID_ADDR,
            {
                "protocol": "obscura.site/1",
                "address": VALID_ADDR,
                "title": "Alpha",
                "description": "Hidden service",
                "tags": ["blog", "blog", " tech "],
            },
        )
        assert out == {
            "title": "Alpha",
            "description": "Hidden service",
            "tags": ["blog", "tech"],
        }

    def test_normalize_manifest_rejects_wrong_address(self):
        with pytest.raises(ValueError, match="does not match"):
            normalize_site_manifest(
                VALID_ADDR,
                {"address": VALID_ADDR_2},
            )

    def test_fetch_site_manifest_uses_client(self):
        class FakeResponse:
            ok = True
            status = 200

            def json(self):
                return {"title": "Alpha", "tags": ["x"]}

        class FakeClient:
            def get(self, addr, path):
                assert addr == VALID_ADDR
                assert path == "/.well-known/obscura.json"
                return FakeResponse()

        out = fetch_site_manifest(VALID_ADDR, client=FakeClient())
        assert out == {"title": "Alpha", "description": "", "tags": ["x"]}


class TestBuildDirectoryApp:
    def test_app_has_index(self):
        app, tools = build_directory_app()
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

    def test_register_tool_fetches_manifest(self):
        app, tools = build_directory_app(
            manifest_fetcher=lambda address: {
                "title": "Alpha",
                "description": "desc",
                "tags": ["blog"],
            }
        )
        req = Request(method="POST", path="/x", headers={}, body=b"")
        req._caller_fingerprint = CALLER_A
        resp = tools.invoke("register", {"address": VALID_ADDR}, req)
        assert resp.status == 200
        body = json.loads(resp.body)
        assert body["ok"] is True
        assert body["result"]["title"] == "Alpha"
        assert body["result"]["tags"] == ["blog"]

    def test_register_tool_rejects_bad_manifest(self):
        app, tools = build_directory_app(
            manifest_fetcher=lambda address: (_ for _ in ()).throw(
                ValueError("manifest address does not match requested address")
            )
        )
        req = Request(method="POST", path="/x", headers={}, body=b"")
        req._caller_fingerprint = CALLER_A
        resp = tools.invoke("register", {"address": VALID_ADDR}, req)
        assert resp.status == 400
        body = json.loads(resp.body)
        assert body["ok"] is False
        assert body["error"]["code"] == "bad_manifest"


class _FakeAgent:
    def __init__(self, tools, caller_fingerprint: str | None):
        self._tools = tools
        self._caller_fingerprint = caller_fingerprint

    def call_tool(self, addr, name, args=None, *, port=80, prefix=None):
        req = Request("POST", f"/tools/{name}", {}, b"")
        if self._caller_fingerprint is not None:
            req._caller_fingerprint = self._caller_fingerprint  # type: ignore[attr-defined]
        resp = self._tools.invoke(name, args or {}, req)
        envelope = json.loads(resp.body)
        if envelope.get("ok") is True:
            return envelope.get("result")
        from src.agent.client import ToolCallError

        err = envelope.get("error") or {}
        raise ToolCallError(
            err.get("code") or "unknown",
            err.get("message") or "fail",
            status=resp.status,
        )


class TestDirectoryClient:
    def test_register_get_list_unregister_round_trip(self):
        _app, tools = build_directory_app(
            manifest_fetcher=lambda address: {
                "title": "Alpha",
                "description": "desc",
                "tags": ["blog"],
            }
        )
        client = DirectoryClient(
            "directory.obscura",
            agent=_FakeAgent(tools, caller_fingerprint=CALLER_A),
        )

        row = client.register(VALID_ADDR)
        assert row["address"] == VALID_ADDR
        assert row["title"] == "Alpha"

        got = client.get(VALID_ADDR)
        assert got["address"] == VALID_ADDR

        rows = client.list(query="alpha")
        assert rows["count"] == 1
        assert rows["listings"][0]["address"] == VALID_ADDR

        removed = client.unregister(VALID_ADDR)
        assert removed == {"removed": True, "address": VALID_ADDR}
