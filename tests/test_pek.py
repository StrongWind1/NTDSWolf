"""Unit tests for crypto/pek.py -- PEKList lookup and per-attribute secret unwrapping.

``pek_decrypt_secret`` is the live path that unwraps the PEK layer of NT/LM
hashes; production reaches it via ``PEKList.decrypt`` / dissect's ``PEK.decrypt``.
"""

from __future__ import annotations

import hashlib
import struct

import pytest
from Crypto.Cipher import ARC4

from ntdswolf.crypto.pek import BootKeyError, PEKList, pek_decrypt_secret

_SECRET = bytes.fromhex("7facdc498ed1680c4fd1448319a8c04f")
_PK = b"\xcc" * 16


def test_get_key_falls_back_to_index_zero():
    assert PEKList(keys={0: _PK}).get_key(5) == _PK


def test_get_key_raises_without_fallback():
    with pytest.raises(BootKeyError):
        PEKList(keys={3: _PK}).get_key(5)


def test_pek_decrypt_secret_rc4_roundtrip():
    pek_key, salt = b"\x11" * 16, b"\x22" * 16
    rc4_key = hashlib.md5(pek_key + salt).digest()  # noqa: S324 -- NTDS secret key derivation
    blob = struct.pack("<HHI", 0x10, 0, 0) + salt + ARC4.new(rc4_key).encrypt(_SECRET)
    assert pek_decrypt_secret(blob, PEKList(keys={0: pek_key})) == _SECRET


def test_pek_decrypt_secret_unknown_algorithm():
    blob = struct.pack("<HHI", 0x99, 0, 0) + b"\x00" * 16 + b"data"
    with pytest.raises(BootKeyError, match="algorithm"):
        pek_decrypt_secret(blob, PEKList(keys={0: b"\x11" * 16}))
