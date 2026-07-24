# SPDX-License-Identifier: Apache-2.0
"""Unit tests for crypto/gkdi.py gMSA/dMSA managed-password derivation.

A synthetic KDS root key drives a deterministic derivation (no real lab key
material).  Bit-exact correctness was verified separately against real gMSA and
dMSA accounts: every derived password's MD4 equalled the stored unicodePwd NT
hash, and the resulting keys round-trip-authenticate against a live DC.
"""

from __future__ import annotations

import struct
import uuid

from ntdswolf.crypto.gkdi import KdsRootKey, derive_gmsa_password

# A KDFParameters blob naming SHA-512 (the KDF hash GKDI root keys use).
_SHA512_KDF_PARAMETERS = bytes.fromhex("00000000010000000e00000000000000") + "SHA512\0".encode("utf-16-le")


def _managed_password_id(l0: int, l1: int, l2: int, guid: uuid.UUID) -> bytes:
    # KeyIdentifier: Version + Magic + Flags + L0 + L1 + L2 + RootKeyId + trailing lengths.
    # derive_gmsa_password only reads the L-indices (offset 12) and RootKeyId (offset 24).
    header = struct.pack("<III", 1, 0x4B534B44, 2)
    return header + struct.pack("<iii", l0, l1, l2) + guid.bytes_le + struct.pack("<III", 0, 0, 0)


def _root_key(guid: uuid.UUID) -> KdsRootKey:
    return KdsRootKey(
        guid=str(guid),
        root_key_data=bytes((i * 7 + 3) & 0xFF for i in range(64)),
        kdf_parameters=_SHA512_KDF_PARAMETERS,
        secret_agreement_parameters=b"",
        private_key_length=512,
        public_key_length=2048,
    )


def test_derive_is_256_bytes_deterministic_and_sid_sensitive():
    guid = uuid.UUID(int=0x1234)
    rk = _root_key(guid)
    mpid = _managed_password_id(364, 5, 27, guid)
    pw = derive_gmsa_password([rk], mpid, "S-1-5-21-1-2-3-1603")
    assert pw is not None
    assert len(pw) == 256
    assert derive_gmsa_password([rk], mpid, "S-1-5-21-1-2-3-1603") == pw  # deterministic
    assert derive_gmsa_password([rk], mpid, "S-1-5-21-1-2-3-1604") != pw  # SID is mixed in


def test_derive_is_epoch_sensitive():
    guid = uuid.UUID(int=0x1234)
    rk = _root_key(guid)
    sid = "S-1-5-21-1-2-3-1603"
    assert derive_gmsa_password([rk], _managed_password_id(364, 5, 27, guid), sid) != derive_gmsa_password([rk], _managed_password_id(364, 5, 25, guid), sid)


def test_derive_unknown_root_key_returns_none():
    mpid = _managed_password_id(364, 5, 27, uuid.UUID(int=0x9999))
    assert derive_gmsa_password([_root_key(uuid.UUID(int=0x1234))], mpid, "S-1-5-21-1-2-3-1") is None


def test_derive_short_id_returns_none():
    assert derive_gmsa_password([], b"\x00" * 10, "S-1-5-21-1-2-3-1") is None
