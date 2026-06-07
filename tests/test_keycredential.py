"""Unit tests for crypto/keycredential.py -- KEYCREDENTIALLINK_BLOB parsing.

Mirrors the real [MS-ADTS] 2.2.20 layout: a Version DWORD followed by
``Length(WORD) + Identifier(BYTE) + Value`` entries, optionally with the 4-byte
link_table length prefix.
"""

from __future__ import annotations

import struct
import uuid

from ntdswolf.crypto.keycredential import parse_key_credential


def _entry(identifier: int, value: bytes) -> bytes:
    return struct.pack("<HB", len(value), identifier) + value


def _blob(*entries: bytes, version: int = 0x0200, prefix: bool = False) -> bytes:
    body = struct.pack("<I", version) + b"".join(entries)
    return struct.pack("<I", len(body)) + body if prefix else body


def test_parses_device_id_big_endian_and_usage():
    dev = uuid.UUID("bf8c10c5-fc0b-44ff-ac51-2721bb47576a")
    blob = _blob(_entry(0x01, b"\xaa" * 32), _entry(0x06, dev.bytes), _entry(0x04, b"\x01"))
    kc = parse_key_credential(blob)
    assert kc is not None
    assert kc["Version"] == 0x0200
    assert kc["DeviceId"] == "bf8c10c5-fc0b-44ff-ac51-2721bb47576a"
    assert kc["KeyUsage"] == "NGC"


def test_skips_link_table_length_prefix():
    blob = _blob(_entry(0x01, b"\xbb" * 32), prefix=True)
    kc = parse_key_credential(blob)
    assert kc is not None
    assert kc["KeyID"]  # present (hex of the non-UTF-8 KeyID bytes)


def test_returns_none_without_key_id_or_material():
    # A blob with only a usage entry carries no KeyID/KeyMaterial -> unusable.
    assert parse_key_credential(_blob(_entry(0x04, b"\x01"))) is None


def test_returns_none_on_garbage():
    assert parse_key_credential(b"\x00\x00") is None
