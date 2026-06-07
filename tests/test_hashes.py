"""Unit tests for crypto/hashes.py -- DES un-obfuscation and NT/LM decryption.

The round-trip tests exercise the live NT/LM decryption path the pipeline uses:
PEK RC4 unwrap (pek_decrypt_secret) followed by per-RID DES un-obfuscation.
"""

from __future__ import annotations

import hashlib
import struct

from Crypto.Cipher import ARC4, DES

from ntdswolf.crypto.hashes import (
    _derive_des_keys,
    _remove_des_layer,
    decrypt_hash_history,
    decrypt_nt_hash,
)
from ntdswolf.crypto.pek import PEKList

_NT = bytes.fromhex("7facdc498ed1680c4fd1448319a8c04f")
_EMPTY = bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")


def _wrap_pek_rc4(plaintext, pek_key=b"\x11" * 16, salt=b"\x22" * 16):
    rc4_key = hashlib.md5(pek_key + salt).digest()  # noqa: S324 -- matches NTDS PEK key derivation
    return struct.pack("<HHI", 0x10, 0, 0) + salt + ARC4.new(rc4_key).encrypt(plaintext)


def _des_obfuscate(hash16, rid):
    # Build the per-RID DES layer with the same key derivation the code uses.
    k1, k2 = _derive_des_keys(rid)
    return DES.new(k1, DES.MODE_ECB).encrypt(hash16[:8]) + DES.new(k2, DES.MODE_ECB).encrypt(hash16[8:])  # noqa: S304 -- DES used to build NTDS hash test vectors


def test_remove_des_layer_roundtrip():
    assert _remove_des_layer(_des_obfuscate(_NT, 1104), 1104) == _NT


def test_decrypt_nt_hash_full_roundtrip():
    pek_key = b"\x11" * 16
    blob = _wrap_pek_rc4(_des_obfuscate(_NT, 1104), pek_key)
    assert decrypt_nt_hash(blob, PEKList(keys={0: pek_key}), 1104) == _NT


def test_decrypt_nt_hash_returns_none_on_garbage():
    assert decrypt_nt_hash(b"\x00\x00", PEKList(keys={0: b"\x11" * 16}), 1104) is None


def test_decrypt_hash_history_roundtrip():
    rid, pek_key = 500, b"\x11" * 16
    obf = _des_obfuscate(_NT, rid) + _des_obfuscate(_EMPTY, rid)
    blob = _wrap_pek_rc4(obf, pek_key)
    assert decrypt_hash_history(blob, PEKList(keys={0: pek_key}), rid) == [_NT, _EMPTY]
