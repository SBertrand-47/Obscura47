"""Tests for desktop utility helper functions in app.py."""

from __future__ import annotations

from types import SimpleNamespace

from app import format_hosted_site_summary, resolve_hosted_site_selection


def test_format_hosted_site_summary_includes_target_and_mode():
    site = SimpleNamespace(name="alpha", address="alpha.obscura", target="./site")

    summary = format_hosted_site_summary(site, background_enabled=True)

    assert "alpha.obscura" in summary
    assert "Target: ./site" in summary
    assert "Mode: background" in summary


def test_format_hosted_site_summary_uses_placeholder_when_target_missing():
    site = SimpleNamespace(name="alpha", address="alpha.obscura", target=None)

    summary = format_hosted_site_summary(site, background_enabled=False)

    assert "(target not saved yet)" in summary
    assert "Mode: manual" in summary


def test_resolve_hosted_site_selection_accepts_site_name():
    hosted = [SimpleNamespace(name="alpha", address="alpha.obscura")]

    resolved = resolve_hosted_site_selection("alpha", hosted)

    assert resolved == "alpha.obscura"


def test_resolve_hosted_site_selection_accepts_raw_address():
    hosted = [SimpleNamespace(name="alpha", address="alpha.obscura")]

    resolved = resolve_hosted_site_selection("beta.obscura", hosted)

    assert resolved == "beta.obscura"


def test_resolve_hosted_site_selection_rejects_unknown_name():
    hosted = [SimpleNamespace(name="alpha", address="alpha.obscura")]

    try:
        resolve_hosted_site_selection("beta", hosted)
    except ValueError as exc:
        assert "unknown hosted site" in str(exc)
    else:
        raise AssertionError("expected ValueError for unknown site")
