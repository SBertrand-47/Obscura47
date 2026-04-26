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
