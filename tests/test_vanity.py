"""Tests for src.utils.vanity — vanity address miner."""

from __future__ import annotations

import os

import pytest

from src.utils.vanity import (
    VanityResult,
    mine_single,
    mine_parallel,
    save_result,
    validate_prefix,
)
from src.utils.onion_addr import ADDR_SUFFIX


class TestValidatePrefix:
    def test_valid_prefix(self):
        assert validate_prefix("abc") == "abc"

    def test_uppercase_lowered(self):
        assert validate_prefix("ABC") == "abc"

    def test_digits_27(self):
        assert validate_prefix("a2b3") == "a2b3"

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="empty"):
            validate_prefix("")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            validate_prefix("a" * 20)

    def test_rejects_invalid_chars(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_prefix("abc!")

    def test_rejects_digit_8(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_prefix("a8")

    def test_rejects_digit_1(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_prefix("a1")


class TestMineSingle:
    def test_finds_single_char(self):
        result = mine_single("a")
        assert result.address.startswith("a")
        assert result.address.endswith(ADDR_SUFFIX)
        assert result.attempts >= 1
        assert result.elapsed > 0
        assert "PRIVATE KEY" in result.private_pem

    def test_finds_two_char(self):
        result = mine_single("ab")
        label = result.address.replace(ADDR_SUFFIX, "")
        assert label.startswith("ab")


class TestMineParallel:
    def test_finds_single_char(self):
        result = mine_parallel("a", workers=2)
        assert result.address.startswith("a")
        assert result.address.endswith(ADDR_SUFFIX)

    def test_single_worker(self):
        result = mine_parallel("b", workers=1)
        assert result.address.startswith("b")


class TestSaveResult:
    def test_saves_key(self, tmp_path):
        result = mine_single("a")
        out = save_result(result, str(tmp_path / "vanity.pem"))
        assert os.path.isfile(out)
        with open(out) as f:
            assert "PRIVATE KEY" in f.read()
        mode = os.stat(out).st_mode & 0o777
        assert mode == 0o600
