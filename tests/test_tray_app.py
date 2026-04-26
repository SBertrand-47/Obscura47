"""Tests for tray_app helper flows."""

from __future__ import annotations

import pytest

pytest.importorskip("PIL")
pytest.importorskip("pystray")

import tray_app


class TestPublishHostedSite:
    def test_publish_hosted_site_writes_manifest_and_schedules_directory(self, monkeypatch):
        app = tray_app.Obscura47Tray()

        prompts = iter(["mysite", "./site", "directory.obscura"])
        monkeypatch.setattr(app, "_prompt_text", lambda *args, **kwargs: next(prompts))

        dialogs = []
        monkeypatch.setattr(app, "_show_dialog", lambda title, message, error=False: dialogs.append((title, message, error)))
        monkeypatch.setattr(app, "_update_menu", lambda: None)
        monkeypatch.setattr(app, "_address_from_pub", lambda pub: "alpha.obscura")

        monkeypatch.setattr(
            "src.utils.sites.load_site_config",
            lambda name: None,
        )
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
        assert manifest == {"site_dir": "/Users/bertrand/Desktop/Obscura47/site", "address": "alpha.obscura", "title": "mysite"}
        assert installed == {"name": "mysite", "target": "./site", "key_path": "/tmp/mysite.pem"}
        assert scheduled == {"site_name": "mysite", "directory_addr": "directory.obscura"}
        assert dialogs and dialogs[0][2] is False
        assert "alpha.obscura" in dialogs[0][1]


class TestBrowseDirectory:
    def test_browse_directory_shows_results(self, monkeypatch):
        app = tray_app.Obscura47Tray()

        prompts = iter(["directory.obscura", "alpha", "alpha.obscura"])
        monkeypatch.setattr(app, "_prompt_text", lambda *args, **kwargs: next(prompts))

        dialogs = []
        monkeypatch.setattr(app, "_show_dialog", lambda title, message, error=False: dialogs.append((title, message, error)))
        opened = []
        monkeypatch.setattr(app, "_open_address_in_browser", lambda address: opened.append(address))

        monkeypatch.setattr("src.utils.visitor.ensure_proxy_running", lambda: True)

        class FakeDirectoryClient:
            def __init__(self, addr):
                assert addr == "directory.obscura"

            def list(self, *, query="", limit=10):
                assert query == "alpha"
                assert limit == 10
                return {
                    "listings": [
                        {"address": "alpha.obscura", "title": "Alpha"},
                        {"address": "beta.obscura", "title": "Beta"},
                    ]
                }

        monkeypatch.setattr("src.agent.directory.DirectoryClient", FakeDirectoryClient)

        app._browse_directory()

        assert dialogs and dialogs[0][2] is False
        assert "Directory: directory.obscura" in dialogs[0][1]
        assert "alpha.obscura" in dialogs[0][1]
        assert "beta.obscura" in dialogs[0][1]
        assert opened == ["alpha.obscura"]


class TestHostedSites:
    def test_show_hosted_sites_displays_address_target_and_mode(self, monkeypatch):
        app = tray_app.Obscura47Tray()

        class Site:
            def __init__(self, name, address, target=None):
                self.name = name
                self.address = address
                self.target = target

        monkeypatch.setattr(app, "_get_hosted_sites", lambda: [Site("alpha", "alpha.obscura", "./site")])
        monkeypatch.setattr("src.utils.daemon.daemon_installed", lambda name: True)

        dialogs = []
        monkeypatch.setattr(app, "_show_dialog", lambda title, message, error=False: dialogs.append((title, message, error)))

        app._show_hosted_sites()

        assert dialogs and dialogs[0][2] is False
        assert "alpha.obscura" in dialogs[0][1]
        assert "Target: ./site" in dialogs[0][1]
        assert "Mode: background" in dialogs[0][1]

    def test_open_hosted_site_resolves_name_and_opens_browser(self, monkeypatch):
        app = tray_app.Obscura47Tray()

        class Site:
            def __init__(self, name, address):
                self.name = name
                self.address = address

        monkeypatch.setattr(app, "_get_hosted_sites", lambda: [Site("alpha", "alpha.obscura")])
        monkeypatch.setattr(app, "_prompt_text", lambda *args, **kwargs: "alpha")

        opened = []
        dialogs = []
        monkeypatch.setattr(app, "_open_address_in_browser", lambda address: opened.append(address))
        monkeypatch.setattr(app, "_show_dialog", lambda title, message, error=False: dialogs.append((title, message, error)))

        app._open_hosted_site()

        assert opened == ["alpha.obscura"]
        assert dialogs and dialogs[0][2] is False
        assert "Opened alpha.obscura" in dialogs[0][1]
