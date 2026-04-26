"""Tests for src.utils.daemon — service template generation."""

from __future__ import annotations

import os

from src.utils.daemon import (
    daemon_reference,
    generate_launchd_plist,
    generate_systemd_unit,
    scheduled_task_name,
)


class TestSystemdUnit:
    def test_contains_name(self):
        unit = generate_systemd_unit("myblog", "./public")
        assert "myblog" in unit
        assert "./public" in unit

    def test_has_install_section(self):
        unit = generate_systemd_unit("s", "t")
        assert "[Install]" in unit
        assert "WantedBy=default.target" in unit

    def test_restart_on_failure(self):
        unit = generate_systemd_unit("s", "t")
        assert "Restart=on-failure" in unit

    def test_contains_python_path(self):
        import sys
        unit = generate_systemd_unit("s", "t")
        assert sys.executable in unit

    def test_includes_key_path_when_provided(self):
        unit = generate_systemd_unit("s", "./site", key_path="~/keys/site.pem")
        assert "--key" in unit
        assert "site.pem" in unit


class TestLaunchdPlist:
    def test_valid_xml(self):
        plist = generate_launchd_plist("myblog", "./site")
        assert plist.startswith("<?xml")
        assert "com.obscura47.host.myblog" in plist

    def test_contains_target(self):
        plist = generate_launchd_plist("shop", "127.0.0.1:8080")
        assert "127.0.0.1:8080" in plist

    def test_run_at_load(self):
        plist = generate_launchd_plist("s", "t")
        assert "<key>RunAtLoad</key>" in plist
        assert "<true/>" in plist

    def test_log_path(self):
        plist = generate_launchd_plist("demo", "t")
        assert "host-demo.log" in plist

    def test_contains_key_path_when_provided(self):
        plist = generate_launchd_plist("demo", "./site", key_path="~/keys/demo.pem")
        assert "<string>--key</string>" in plist
        assert "demo.pem" in plist


class TestDaemonReference:
    def test_linux_reference(self):
        ref = daemon_reference("alpha", system="Linux")
        assert ref.endswith("obscura47-host-alpha.service")

    def test_macos_reference(self):
        ref = daemon_reference("alpha", system="Darwin")
        assert ref.endswith("com.obscura47.host.alpha.plist")

    def test_windows_reference(self):
        assert daemon_reference("alpha", system="Windows") == "Obscura47 Host alpha"


class TestScheduledTaskName:
    def test_contains_site_name(self):
        assert scheduled_task_name("myblog") == "Obscura47 Host myblog"
