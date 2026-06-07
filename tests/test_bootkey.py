"""Unit tests for crypto/bootkey.py -- boot key parsing, detection, resolution."""

from __future__ import annotations

import pytest

from ntdswolf.crypto.bootkey import auto_detect_system_hive, parse_bootkey_hex, resolve_bootkey

_HEX = "aabbccdd11223344aabbccdd11223344"


def test_parse_bootkey_hex_valid():
    assert parse_bootkey_hex(_HEX) == bytes.fromhex(_HEX)


def test_parse_bootkey_hex_strips_whitespace():
    assert parse_bootkey_hex(f"  {_HEX}  ") == bytes.fromhex(_HEX)


def test_parse_bootkey_hex_wrong_length():
    with pytest.raises(ValueError, match="32 characters"):
        parse_bootkey_hex("aabb")


def test_parse_bootkey_hex_non_hex():
    with pytest.raises(ValueError, match="Invalid hex"):
        parse_bootkey_hex("z" * 32)


def test_auto_detect_finds_system_in_dir(tmp_path):
    (tmp_path / "SYSTEM").write_bytes(b"x")
    assert auto_detect_system_hive(tmp_path) == tmp_path / "SYSTEM"


def test_auto_detect_is_case_insensitive(tmp_path):
    (tmp_path / "system").write_bytes(b"x")
    found = auto_detect_system_hive(tmp_path)
    assert found is not None
    assert found.name == "system"


def test_auto_detect_searches_parent_directory(tmp_path):
    (tmp_path / "SYSTEM").write_bytes(b"x")
    sub = tmp_path / "registry"
    sub.mkdir()
    assert auto_detect_system_hive(sub) == tmp_path / "SYSTEM"


def test_auto_detect_returns_none_when_absent(tmp_path):
    assert auto_detect_system_hive(tmp_path) is None


def test_resolve_bootkey_hex_has_priority():
    assert resolve_bootkey(_HEX, None, None) == bytes.fromhex(_HEX)


def test_resolve_bootkey_bad_hex_returns_none():
    assert resolve_bootkey("nothex", None, None) is None


def test_resolve_bootkey_nothing_available_returns_none():
    assert resolve_bootkey(None, None, None) is None


def test_resolve_bootkey_malformed_system_does_not_crash(tmp_path):
    # A bogus SYSTEM file makes dissect raise EOFError; resolve must return None.
    bad = tmp_path / "SYSTEM"
    bad.write_bytes(b"not a real hive")
    assert resolve_bootkey(None, bad, None) is None
