# SPDX-License-Identifier: Apache-2.0
"""Unit tests for decoders/_supplemental.py -- surfacing dissect's supplementalCredentials."""

from __future__ import annotations

from ntdswolf.decoders._supplemental import merge_supplemental

_SALT = b"S\x00A\x00L\x00T\x00"


def test_merge_captures_old_and_service_kerberos_key_sets():
    # KERB_STORED_CREDENTIAL_NEW has four key arrays; all but the current set were
    # previously dropped. Old/Older/Service must surface under their own keys.
    supp = {
        "Primary:Kerberos-Newer-Keys": {
            "DefaultSalt": _SALT,
            "Credentials": [{"KeyType": 18, "Key": b"\xaa" * 32, "IterationCount": 4096}],
            "OldCredentials": [{"KeyType": 18, "Key": b"\xbb" * 32, "IterationCount": 4096}],
            "ServiceCredentials": [{"KeyType": 18, "Key": b"\xcc" * 32, "IterationCount": 4096}],
            "OlderCredentials": [],
        },
    }
    creds: dict = {}
    merge_supplemental(supp, creds)
    assert [k["key"] for k in creds["kerberos"]] == ["aa" * 32]
    assert [k["key"] for k in creds["kerberosOld"]] == ["bb" * 32]
    assert [k["key"] for k in creds["kerberosService"]] == ["cc" * 32]
    assert creds["kerberosOld"][0]["etypeName"] == "AES256-CTS-HMAC-SHA1-96"
    assert "kerberosOlder" not in creds  # empty arrays are omitted, not emitted as []


def test_merge_omits_extra_key_sets_when_absent():
    supp = {"Primary:Kerberos-Newer-Keys": {"DefaultSalt": b"", "Credentials": [{"KeyType": 18, "Key": b"\xaa" * 32}]}}
    creds: dict = {}
    merge_supplemental(supp, creds)
    assert creds["kerberos"]
    assert "kerberosOld" not in creds
    assert "kerberosService" not in creds


def test_merge_captures_wdigest_and_ntowf():
    supp = {"Primary:WDigest": [b"\x01" * 16, b"\x02" * 16], "Primary:NTLM-Strong-NTOWF": b"\x09" * 16}
    creds: dict = {}
    merge_supplemental(supp, creds)
    assert creds["wdigest"] == ["01" * 16, "02" * 16]
    assert creds["ntlmStrongNTOWF"] == "09" * 16


def test_raw_dump_preserves_complete_structure_verbatim():
    # The complete decoded structure is always surfaced, including the otherwise
    # curated-away legacy package, Packages metadata, and default iteration count.
    supp = {
        "Primary:Kerberos-Newer-Keys": {"DefaultSalt": b"S\x00", "DefaultIterationCount": 4096, "Credentials": [{"KeyType": 18, "Key": b"\xaa" * 32}]},
        "Primary:Kerberos": {"DefaultSalt": b"S\x00", "Credentials": [{"KeyType": 3, "Key": b"\xbb" * 8}]},
        "Packages": ["Kerberos-Newer-Keys", "Kerberos"],
        "Primary:WDigest": [b"\x01" * 16],
    }
    creds: dict = {}
    merge_supplemental(supp, creds)
    raw = creds["supplementalCredentialsRaw"]
    assert raw["Primary:Kerberos"]["Credentials"][0]["Key"] == "bb" * 8  # legacy package kept (bytes -> hex)
    assert raw["Packages"] == ["Kerberos-Newer-Keys", "Kerberos"]  # metadata kept
    assert raw["Primary:Kerberos-Newer-Keys"]["DefaultIterationCount"] == 4096  # default iteration count kept
    assert raw["Primary:WDigest"] == ["01" * 16]


def test_raw_dump_is_always_present():
    creds: dict = {}
    merge_supplemental({"Primary:WDigest": [b"\x01" * 16]}, creds)
    assert creds["supplementalCredentialsRaw"]["Primary:WDigest"] == ["01" * 16]
