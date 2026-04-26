"""Tests for join_network host UX helpers."""

from __future__ import annotations

import pytest

import join_network
from src.utils.sites import SiteConfig


class TestSavedTargetForSite:
    def test_none_without_site_name(self):
        assert join_network._saved_target_for_site(None) is None

    def test_returns_saved_target(self, monkeypatch):
        monkeypatch.setattr(
            "src.utils.sites.load_site_config",
            lambda name: SiteConfig(name=name, target="./public"),
        )
        assert join_network._saved_target_for_site("alpha") == "./public"


class TestHostArgumentParsing:
    def test_main_allows_saved_target_with_name_only(self, monkeypatch):
        captured = {}

        monkeypatch.setattr(join_network, "check_dependencies", lambda: None)
        monkeypatch.setattr(join_network.signal, "signal", lambda *_args: None)
        monkeypatch.setattr(
            join_network,
            "start_roles",
            lambda roles, host_arg=None, site_name=None, key_path=None: captured.update(
                {
                    "roles": roles,
                    "host_arg": host_arg,
                    "site_name": site_name,
                    "key_path": key_path,
                }
            ),
        )
        monkeypatch.setattr(
            join_network.sys,
            "argv",
            ["join_network.py", "host", "--name", "mysite"],
        )

        join_network.main()

        assert captured == {
            "roles": ["host"],
            "host_arg": None,
            "site_name": "mysite",
            "key_path": None,
        }

    def test_main_requires_name_for_flag_only_host(self, monkeypatch):
        monkeypatch.setattr(join_network, "check_dependencies", lambda: None)
        monkeypatch.setattr(join_network.signal, "signal", lambda *_args: None)
        monkeypatch.setattr(join_network.sys, "argv", ["join_network.py", "host", "--key", "/tmp/site.pem"])

        with pytest.raises(SystemExit):
            join_network.main()

    def test_strip_flags_omits_manifest_option_values(self):
        out = join_network._strip_flags(
            [
                "./site",
                "--name", "mysite",
                "--title", "Alpha",
                "--description", "Desc",
                "--tag", "blog",
                "--tag=search",
            ],
            ("--name", "--key", "--title", "--description", "--tag"),
        )
        assert out == ["./site"]


class TestHostDirectoryRegistration:
    def test_register_directory_uses_saved_site_identity(self, monkeypatch, tmp_path):
        site_dir = tmp_path / "sites"
        site_dir.mkdir()

        saved = {}

        def fake_load_site_config(name):
            return SiteConfig(
                name=name,
                key_path=str(tmp_path / "external.pem"),
                target="./site",
            )

        def fake_load_or_create_site_key(name=None, key=None):
            saved["key"] = key
            return object(), "PUB", key or "/tmp/default.pem", False

        monkeypatch.setattr("src.utils.sites.load_site_config", fake_load_site_config)
        monkeypatch.setattr("src.utils.sites.load_or_create_site_key", fake_load_or_create_site_key)
        monkeypatch.setattr("src.utils.onion_addr.address_from_pubkey", lambda pub: "alpha.obscura")
        monkeypatch.setattr("src.utils.visitor.ensure_proxy_running", lambda: True)

        called = {}

        class FakeDirectoryClient:
            def __init__(self, addr):
                called["addr"] = addr

            def register(self, address):
                called["register"] = address
                return {"title": "Alpha", "tags": ["blog"]}

        monkeypatch.setattr("src.agent.directory.DirectoryClient", FakeDirectoryClient)

        join_network._host_register_directory(
            ["directory.obscura", "--name", "mysite"],
        )

        assert called == {
            "addr": "directory.obscura",
            "register": "alpha.obscura",
        }
        assert saved["key"] == str(tmp_path / "external.pem")
