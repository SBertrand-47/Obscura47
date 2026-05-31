"""Tests for the .obscura site discovery helpers (registry /hs/list)."""

from __future__ import annotations

import time

import src.core.internet_discovery as discovery
from src.utils.site_directory import (
    fetch_live_sites,
    enrich_with_manifests,
    format_site_listing,
)


def test_fetch_live_sites_parses_and_filters(monkeypatch):
    rows = [
        {"addr": "alpha234567890123.obscura", "expires": 1, "updated": 2},
        {"addr": "beta2345678901234.obscura", "expires": 3, "updated": 4},
        {"no_addr": True},          # dropped
        "garbage",                  # dropped
    ]
    monkeypatch.setattr(discovery, "registry_request_json", lambda url, **kw: rows)
    sites = fetch_live_sites()
    assert [s["addr"] for s in sites] == [
        "alpha234567890123.obscura",
        "beta2345678901234.obscura",
    ]
    assert sites[0] == {"addr": "alpha234567890123.obscura", "expires": 1, "updated": 2}


def test_fetch_live_sites_non_list_is_empty(monkeypatch):
    monkeypatch.setattr(discovery, "registry_request_json", lambda url, **kw: {"oops": 1})
    assert fetch_live_sites() == []


def test_enrich_swallows_per_site_failures():
    sites = [
        {"addr": "good23456789012a.obscura"},
        {"addr": "bad234567890123b.obscura"},
    ]

    def fetcher(addr):
        if addr.startswith("bad"):
            raise RuntimeError("unreachable")
        return {"title": "Good Site", "description": "hi", "tags": ["x"]}

    out = enrich_with_manifests(sites, fetcher=fetcher)
    assert out[0]["title"] == "Good Site"
    assert out[0]["tags"] == ["x"]
    # Failed site keeps its address, gains no manifest fields.
    assert "title" not in out[1]


def test_enrich_respects_limit():
    sites = [{"addr": f"s{i:015d}.obscura"} for i in range(5)]
    calls = []

    def fetcher(addr):
        calls.append(addr)
        return {"title": "t"}

    enrich_with_manifests(sites, limit=2, fetcher=fetcher)
    assert len(calls) == 2


def test_format_empty_listing():
    text = format_site_listing([])
    assert "No live .obscura sites" in text


def test_format_listing_with_titles_and_age():
    now = 1_000_000.0
    sites = [
        {
            "addr": "alpha234567890123.obscura",
            "title": "Alpha",
            "description": "first site",
            "updated": now - 30,
        },
        {"addr": "beta2345678901234.obscura", "updated": now - 7200},
    ]
    text = format_site_listing(sites, now=now)
    assert "2 live .obscura site(s):" in text
    assert "Alpha  (alpha234567890123.obscura)" in text
    assert "first site" in text
    assert "just now" in text
    assert "2h ago" in text
    # Untitled site still shows its bare address.
    assert "beta2345678901234.obscura" in text
