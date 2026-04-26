"""Tests for src.utils.visitor — PAC generation and visitor launcher."""

from __future__ import annotations

import os

from src.utils.visitor import generate_pac, pac_file_url, PAC_TEMPLATE


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
