"""Tests for desktop utility helper functions."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from src.utils.app_helpers import (
    build_quick_start_text,
    count_unique_peers,
    format_hosted_site_summary,
    resolve_hosted_site_selection,
)


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

    with pytest.raises(ValueError, match="unknown hosted site"):
        resolve_hosted_site_selection("beta", hosted)


def test_build_quick_start_text_for_disconnected_state():
    text = build_quick_start_text(connected=False)

    assert "Start by pressing Connect" in text
    assert "Visit a site:" in text
    assert "Publish your own site:" in text


def test_build_quick_start_text_for_connected_state():
    text = build_quick_start_text(connected=True)

    assert "You are connected." in text
    assert "Browse discovery:" in text


def test_count_unique_peers_merges_same_pub_across_addresses():
    peers = [
        {"host": "192.168.1.20", "port": 5001, "pub": "node-pub"},
        {"host": "203.0.113.10", "port": 5001, "pub": "node-pub"},
        {"host": "203.0.113.11", "port": 5001, "pub": "other-node"},
    ]

    assert count_unique_peers(peers) == 2


def test_count_unique_peers_falls_back_to_host_and_port():
    peers = [
        {"host": "203.0.113.10", "port": 5001},
        {"host": "203.0.113.10", "port": 5001},
        {"host": "203.0.113.10", "port": 5002},
    ]

    assert count_unique_peers(peers) == 2


# ── GUI-dependent tests (require PySide6 / Qt) ────────────────────────────────

# The GUI is built on PySide6. Run it headless so these tests need no display.
import os  # noqa: E402

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication  # noqa: F401
    _has_qt = True
except ImportError:
    _has_qt = False

_skip_no_qt = pytest.mark.skipif(not _has_qt, reason="PySide6 not available")


@pytest.fixture()
def _stub_app():
    from PySide6.QtWidgets import QApplication
    from app import ObscuraApp

    # A QApplication must exist before any Qt object is created, but we don't
    # build the UI - __new__ gives us a bare instance whose methods we can call
    # with the Qt dialogs monkeypatched out.
    if QApplication.instance() is None:
        QApplication([])
    return ObscuraApp.__new__(ObscuraApp)


@_skip_no_qt
def test_publish_hosted_site_writes_manifest_and_schedules_directory(monkeypatch, _stub_app):
    app = _stub_app

    prompts = iter(["mysite", "directory.obscura"])
    app._prompt_text = lambda *args, **kwargs: next(prompts)
    app._prompt_publish_target = lambda *args, **kwargs: "./site"
    app._log = lambda message: None
    app._address_from_pub = lambda pub: "alpha.obscura"

    infos = []
    errors = []
    monkeypatch.setattr("app.QMessageBox.information", lambda parent, title, message, *a, **k: infos.append((title, message)))
    monkeypatch.setattr("app.QMessageBox.critical", lambda parent, title, message, *a, **k: errors.append((title, message)))

    monkeypatch.setattr("src.utils.sites.load_site_config", lambda name: None)
    monkeypatch.setattr(
        "src.utils.sites.load_or_create_site_key",
        lambda name=None, key=None: (object(), "PUB", "/tmp/mysite.pem", False),
    )

    saved = {}
    monkeypatch.setattr(
        "src.utils.sites.save_site_config",
        lambda name, key_path=None, target=None: saved.update(
            {"name": name, "key_path": key_path, "target": target}
        ),
    )

    manifest = {}
    monkeypatch.setattr("os.path.isdir", lambda path: True)
    monkeypatch.setattr(
        "src.utils.sites.write_site_manifest",
        lambda site_dir, address, title="": manifest.update(
            {"site_dir": site_dir, "address": address, "title": title}
        ),
    )

    installed = {}
    monkeypatch.setattr(
        "src.utils.daemon.install_daemon",
        lambda name, target, key_path=None: installed.update(
            {"name": name, "target": target, "key_path": key_path}
        ) or "/tmp/service",
    )

    scheduled = {}
    monkeypatch.setattr(
        "join_network._schedule_directory_registration",
        lambda site_name, directory_addr: scheduled.update(
            {"site_name": site_name, "directory_addr": directory_addr}
        ),
    )

    app._publish_hosted_site()

    assert saved == {"name": "mysite", "key_path": "/tmp/mysite.pem", "target": "./site"}
    assert manifest["address"] == "alpha.obscura"
    assert manifest["title"] == "mysite"
    assert installed == {"name": "mysite", "target": "./site", "key_path": "/tmp/mysite.pem"}
    assert scheduled == {"site_name": "mysite", "directory_addr": "directory.obscura"}
    assert infos and "alpha.obscura" in infos[0][1]
    assert not errors


@_skip_no_qt
def test_remove_hosted_site_daemon_reports_success(monkeypatch, _stub_app):
    app = _stub_app

    app._prompt_text = lambda *args, **kwargs: "mysite"
    logs = []
    app._log = lambda message: logs.append(message)

    infos = []
    errors = []
    monkeypatch.setattr("app.QMessageBox.information", lambda parent, title, message, *a, **k: infos.append((title, message)))
    monkeypatch.setattr("app.QMessageBox.critical", lambda parent, title, message, *a, **k: errors.append((title, message)))
    monkeypatch.setattr("src.utils.daemon.uninstall_daemon", lambda name: True)
    # Removal now also withdraws the descriptor so the site stops appearing in
    # Discover; stub it to report success.
    monkeypatch.setattr(
        "src.core.hidden_service.withdraw_descriptor_by_name", lambda name: True)

    app._remove_hosted_site_daemon()

    assert infos
    msg = infos[0][1]
    assert "background service removed" in msg
    assert "descriptor withdrawn from the registry" in msg
    assert any("Remove Site" in line for line in logs)
    assert not errors
