"""Tests for src.utils.daemon — service template generation."""

from __future__ import annotations

import os

from src.utils.daemon import (
    generate_launchd_plist,
    generate_systemd_unit,
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
