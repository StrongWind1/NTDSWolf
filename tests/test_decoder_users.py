"""Unit tests for decoders/users.py helpers."""

from __future__ import annotations

from ntdswolf.decoders.users import _history_blob


def test_history_blob_unwraps_dissect_list():
    # dissect returns ntPwdHistory/lmPwdHistory as a one-element list of bytes;
    # the blob must be unwrapped (regression: a list failed an isinstance(bytes)
    # check, so password history was silently dropped for every account).
    assert _history_blob([b"\x13\x00\xab\xcd"]) == b"\x13\x00\xab\xcd"


def test_history_blob_accepts_bytes_directly():
    assert _history_blob(b"\xab\xcd") == b"\xab\xcd"


def test_history_blob_returns_none_for_empty_or_missing():
    assert _history_blob(None) is None
    assert _history_blob([]) is None
    assert _history_blob(b"") is None
    assert _history_blob([b""]) is None
