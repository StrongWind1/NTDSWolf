"""Unit tests for trust credential parsing (crypto/trusts.py) and trust-key output.

Uses synthetic LSAPR_AUTH_INFORMATION blobs with a known cleartext password so
no real trust material is committed.  The same parsing + key derivation was
separately verified against a real inter-forest trust (the current incoming
auth info reproduced the stored trust account's NT hash + AES-256/AES-128 keys exactly).
"""

from __future__ import annotations

import struct

from Crypto.Hash import MD4

from ntdswolf.crypto.trusts import parse_trust_auth
from ntdswolf.output.credfiles import trust_credential_lines

TRUST_AUTH_TYPE_NT4OWF = 1
TRUST_AUTH_TYPE_CLEAR = 2


def _auth_info(auth_type: int, info: bytes) -> bytes:
    # LastUpdateTime(8) + AuthType(4) + AuthInfoLength(4) + AuthInfo, padded to 4 bytes.
    return struct.pack("<QII", 0, auth_type, len(info)) + info + b"\x00" * (-len(info) % 4)


def _blob(current: bytes, previous: bytes = b"") -> bytes:
    # Count + CurrentAuthInfoOffset + PreviousAuthInfoOffset + sections.
    return struct.pack("<III", 1, 12, 12 + len(current)) + current + previous


def test_clear_entry_derives_rc4_and_aes():
    password = "Tr0ust-P@ssw0rd-Example".encode("utf-16-le")
    salt = "EXAMPLE.LABkrbtgtPARTNER"
    entry = parse_trust_auth(_blob(_auth_info(TRUST_AUTH_TYPE_CLEAR, password)), salt)["authInfo"][0]
    assert entry["authType"] == "TRUST_AUTH_TYPE_CLEAR"
    assert entry["cleartextPassword"] == password.hex()
    assert entry["rc4_hmac"] == MD4.new(password).hexdigest()  # noqa: S303 -- MD4 is the RC4-HMAC construction under test
    # Fixed RFC 3962 string-to-key oracle for pw="Tr0ust-P@ssw0rd-Example", the salt above,
    # 4096 iterations (cross-checked against the RFC 3962 App. B vectors in test_kerberos.py).
    assert entry["aes256"] == "43abf28029d79bf95cefda73294ae75d3c83364ff6b3dc6833cddd5f87115ba4"
    assert entry["aes128"] == "72b395cb70741422c3ea53524e1d37f3"


def test_nt4owf_entry_returns_hash():
    nt = bytes.fromhex("12e1a4973a799c44e958e39f2d30fc3c")
    entry = parse_trust_auth(_blob(_auth_info(TRUST_AUTH_TYPE_NT4OWF, nt)), "X")["authInfo"][0]
    assert entry["rc4_hmac"] == nt.hex()


def test_current_and_previous_sections():
    cur = _auth_info(TRUST_AUTH_TYPE_CLEAR, "current".encode("utf-16-le"))
    prev = _auth_info(TRUST_AUTH_TYPE_CLEAR, "previous".encode("utf-16-le"))
    parsed = parse_trust_auth(_blob(cur, prev), "X")
    assert len(parsed["authInfo"]) == 1
    assert len(parsed["previousAuthInfo"]) == 1


def test_too_short_returns_empty():
    assert parse_trust_auth(b"\x00\x00", "X") == {}


def test_trust_credential_lines_both_directions():
    obj = {
        "_object_class": "trustedDomain",
        "distinguishedName": "CN=test.example.lab,CN=System,DC=example,DC=lab",
        "flatName": "TEST",
        "trustCredentials": {
            "incoming": {"authInfo": [{"rc4_hmac": "aa" * 16, "aes256": "bb" * 32, "aes128": "cc" * 16}], "previousAuthInfo": []},
            "outgoing": {"authInfo": [{"rc4_hmac": "dd" * 16}], "previousAuthInfo": [{"rc4_hmac": "ee" * 16}]},
        },
    }
    lines = trust_credential_lines(obj)
    assert "EXAMPLE\\TEST$:RC4-HMAC:" + "aa" * 16 in lines
    assert "EXAMPLE\\TEST$:AES256-CTS-HMAC-SHA1-96:" + "bb" * 32 in lines
    assert "TEST\\EXAMPLE$:RC4-HMAC:" + "dd" * 16 in lines
    assert "TEST\\EXAMPLE$__previous:RC4-HMAC:" + "ee" * 16 in lines


def test_trust_credential_lines_ignores_non_trust():
    assert trust_credential_lines({"_object_class": "user", "credentials": {}}) == []
