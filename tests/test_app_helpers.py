"""Tests for desktop utility helper functions in app.py."""

from __future__ import annotations

from types import SimpleNamespace

from app import ObscuraApp, format_hosted_site_summary, resolve_hosted_site_selection


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


def test_publish_hosted_site_writes_manifest_and_schedules_directory(monkeypatch):
    app = object.__new__(ObscuraApp)

    prompts = iter(["mysite", "./site", "directory.obscura"])
    app._prompt_text = lambda *args, **kwargs: next(prompts)
    app._log = lambda message: None
    app._address_from_pub = lambda pub: "alpha.obscura"

    infos = []
    errors = []
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda title, message, parent=None: infos.append((title, message)))
    monkeypatch.setattr("tkinter.messagebox.showerror", lambda title, message, parent=None: errors.append((title, message)))

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
    assert manifest == {
        "site_dir": "/Users/bertrand/Desktop/Obscura47/site",
        "address": "alpha.obscura",
        "title": "mysite",
    }
    assert installed == {"name": "mysite", "target": "./site", "key_path": "/tmp/mysite.pem"}
    assert scheduled == {"site_name": "mysite", "directory_addr": "directory.obscura"}
    assert infos and "alpha.obscura" in infos[0][1]
    assert not errors


def test_remove_hosted_site_daemon_reports_success(monkeypatch):
    app = object.__new__(ObscuraApp)

    app._prompt_text = lambda *args, **kwargs: "mysite"
    logs = []
    app._log = lambda message: logs.append(message)

    infos = []
    errors = []
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda title, message, parent=None: infos.append((title, message)))
    monkeypatch.setattr("tkinter.messagebox.showerror", lambda title, message, parent=None: errors.append((title, message)))
    monkeypatch.setattr("src.utils.daemon.uninstall_daemon", lambda name: True)

    app._remove_hosted_site_daemon()

    assert infos and "Removed background service for mysite." in infos[0][1]
    assert any("Removed background service" in line for line in logs)
    assert not errors
