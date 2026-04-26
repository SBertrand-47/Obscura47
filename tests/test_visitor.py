"""Tests for src.utils.visitor — PAC generation and visitor launcher."""

from __future__ import annotations

import os
import socket

from src.utils.visitor import (
    PAC_TEMPLATE,
    ensure_proxy_running,
    generate_pac,
    normalize_browser_url,
    pac_file_url,
    proxy_is_running,
)


class TestGeneratePac:
    def test_creates_file(self, tmp_path):
        pac = generate_pac(output_dir=str(tmp_path))
        assert os.path.isfile(pac)
        assert pac.endswith(".pac")

    def test_content_routes_obscura(self, tmp_path):
        pac = generate_pac(
            proxy_host="127.0.0.1", proxy_port=9047, output_dir=str(tmp_path),
        )
        with open(pac) as f:
            content = f.read()
        assert "*.obscura" in content
        assert "PROXY 127.0.0.1:9047" in content
        assert "DIRECT" in content

    def test_custom_proxy(self, tmp_path):
        pac = generate_pac(
            proxy_host="10.0.0.1", proxy_port=1234, output_dir=str(tmp_path),
        )
        with open(pac) as f:
            content = f.read()
        assert "PROXY 10.0.0.1:1234" in content

    def test_idempotent(self, tmp_path):
        p1 = generate_pac(output_dir=str(tmp_path))
        p2 = generate_pac(output_dir=str(tmp_path))
        assert p1 == p2


class TestPacFileUrl:
    def test_file_url(self, tmp_path):
        pac = generate_pac(output_dir=str(tmp_path))
        url = pac_file_url(pac)
        assert url.startswith("file://")
        assert url.endswith(".pac")


class TestNormalizeBrowserUrl:
    def test_blank_defaults_to_about_blank(self):
        assert normalize_browser_url("") == "about:blank"

    def test_obscura_host_gets_http_scheme(self):
        assert normalize_browser_url("alpha.obscura") == "http://alpha.obscura"

    def test_existing_scheme_is_preserved(self):
        assert normalize_browser_url("https://example.com") == "https://example.com"


class TestProxyHelpers:
    def test_proxy_is_running_false_on_connection_error(self, monkeypatch):
        def fake_connect(*args, **kwargs):
            raise OSError("down")

        monkeypatch.setattr(socket, "create_connection", fake_connect)
        assert proxy_is_running() is False

    def test_ensure_proxy_running_noop_when_already_listening(self, monkeypatch):
        monkeypatch.setattr(
            "src.utils.visitor.proxy_is_running",
            lambda **kwargs: True,
        )

        called = {"count": 0}

        def fake_popen(*args, **kwargs):
            called["count"] += 1
            raise AssertionError("should not launch subprocess")

        monkeypatch.setattr("subprocess.Popen", fake_popen)
        assert ensure_proxy_running() is True
        assert called["count"] == 0

    def test_ensure_proxy_running_starts_proxy_and_waits(self, monkeypatch):
        states = iter([False, False, True])
        monkeypatch.setattr(
            "src.utils.visitor.proxy_is_running",
            lambda **kwargs: next(states),
        )

        launched = {}

        def fake_popen(args, **kwargs):
            launched["args"] = args
            launched["kwargs"] = kwargs
            return object()

        monkeypatch.setattr("subprocess.Popen", fake_popen)
        monkeypatch.setattr("time.sleep", lambda _secs: None)
        assert ensure_proxy_running(timeout=0.5) is True
        assert launched["args"][-1] == "proxy"
