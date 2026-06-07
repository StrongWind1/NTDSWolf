"""Unit tests for crypto/laps.py and crypto/gkdi.py.

Covers all three LAPS forms:

* v1 plaintext (``ms-Mcs-AdmPwd`` UTF-16LE),
* v2 cleartext (``msLAPS-Password`` JSON envelope),
* v2 encrypted (``msLAPS-EncryptedPassword`` CMS + GKDI), exercised with a
  synthetic KDS root key via a dpapi-ng encrypt/decrypt round-trip so no real
  lab key material is committed.  (The same code path was separately verified
  against a real domain: an offline decrypt reproduced the live
  ``Get-LapsADPassword`` value exactly.)
"""

from __future__ import annotations

import struct
import uuid

import dpapi_ng
from dpapi_ng._gkdi import KDFParameters

from ntdswolf.crypto.gkdi import KdsRootKey, build_kds_cache
from ntdswolf.crypto.laps import extract_laps_v1, extract_laps_v2, parse_laps_cleartext


def test_parse_cleartext_envelope():
    env = '{"n":"Administrator","t":"1dcf5f431c9570b","p":"L@ps-Cleartext-Pw-9912"}'
    assert parse_laps_cleartext(env) == {
        "username": "Administrator",
        "password": "L@ps-Cleartext-Pw-9912",
        "timestamp": "1dcf5f431c9570b",
    }


def test_parse_cleartext_accepts_bytes():
    assert parse_laps_cleartext(b'{"n":"a","t":"1","p":"pw"}')["password"] == "pw"


def test_parse_cleartext_rejects_garbage():
    assert parse_laps_cleartext("not json") is None
    assert parse_laps_cleartext(b"\xff\xfe\x00\x01") is None


def test_extract_v1_utf16le():
    assert extract_laps_v1("S3cr3t!".encode("utf-16-le")) == {"password": "S3cr3t!"}


def test_extract_v1_strips_trailing_nulls():
    assert extract_laps_v1("pw\x00\x00".encode("utf-16-le"))["password"] == "pw"


def test_extract_v2_without_cache_returns_none():
    assert extract_laps_v2(b"\x00" * 64, None) is None


def test_extract_v2_roundtrip_with_synthetic_root_key():
    # A fabricated KDS root key -- never real lab material.
    root_key_id = uuid.UUID(int=0x4B445334_0000_0000_0000_000000000001)
    root_key = KdsRootKey(
        guid=str(root_key_id),
        root_key_data=bytes((i * 7 + 3) & 0xFF for i in range(64)),
        kdf_parameters=KDFParameters("SHA512").pack(),
        secret_agreement_parameters=b"",  # build/load defaults to the RFC 5114 DH group
        private_key_length=512,
        public_key_length=2048,
    )
    cache = build_kds_cache([root_key])

    envelope = '{"n":"Administrator","t":"1","p":"R0undTr1p!"}'.encode("utf-16-le")
    # root_key_identifier + cache keeps encryption fully offline (no RPC/SRV lookup).
    cms = dpapi_ng.ncrypt_protect_secret(envelope, "S-1-5-21-1-2-3-512", root_key_identifier=root_key_id, cache=cache)

    # msLAPS-EncryptedPassword header: Timestamp_lower + Timestamp_upper + Length + Flags, then the CMS blob.
    blob = struct.pack("<LLLL", 0, 0, len(cms), 0) + cms

    decrypted = extract_laps_v2(blob, cache)
    assert decrypted == {"username": "Administrator", "password": "R0undTr1p!", "timestamp": "1"}
