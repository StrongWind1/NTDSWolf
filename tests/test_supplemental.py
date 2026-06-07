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
