"""Unit tests for crypto/structures.py -- dissect.cstruct wire-format parsing."""

from __future__ import annotations

import struct

from ntdswolf.crypto.structures import cs


def test_enc_secret_rc4_parses_header():
    data = struct.pack("<HHI", 0x10, 0, 5) + b"\xaa" * 16 + b"ciphertext"
    s = cs.ENC_SECRET_RC4(data)
    assert s.AlgorithmId == 0x10
    assert s.PekIndex == 5
    assert bytes(s.Salt) == b"\xaa" * 16


def test_enc_secret_aes_has_secret_length():
    data = struct.pack("<HHI", 0x13, 0, 0) + b"\xbb" * 16 + struct.pack("<I", 32) + b"ct"
    s = cs.ENC_SECRET_AES(data)
    assert s.AlgorithmId == 0x13
    assert s.SecretLength == 32


def test_pek_list_header_parses():
    data = struct.pack("<II", 3, 0) + b"\xcc" * 16
    h = cs.PEK_LIST_HEADER(data)
    assert h.Version == 3
    assert bytes(h.Salt) == b"\xcc" * 16


def test_user_properties_signature_and_count():
    data = struct.pack("<IIHH", 0, 100, 0, 0) + b"\x00" * 96 + struct.pack("<HH", 0x50, 2)
    up = cs.USER_PROPERTIES(data)
    assert up.PropertySignature == 0x50
    assert up.PropertyCount == 2


def test_lsapr_auth_information_parses():
    data = struct.pack("<QII", 0, 2, 8) + b"\x00" * 8
    a = cs.LSAPR_AUTH_INFORMATION(data)
    assert a.AuthType == 2
    assert a.AuthInfoLength == 8
