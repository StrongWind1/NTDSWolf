"""Unit tests for output/pwdump.py -- pwdump line formatting and helpers."""

from __future__ import annotations

from ntdswolf.output.pwdump import (
    PwdumpWriter,
    _extract_rid,
    _validate_hash,
)

_NT = "7facdc498ed1680c4fd1448319a8c04f"
_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def test_extract_rid_from_sid():
    assert _extract_rid({"objectSid": "S-1-5-21-1-2-3-500"}) == 500


def test_extract_rid_missing_sid_defaults_zero():
    assert _extract_rid({}) == 0


def test_extract_rid_non_numeric_tail_defaults_zero():
    assert _extract_rid({"objectSid": "S-1-5-21-1-2-3-abc"}) == 0


def test_validate_hash_accepts_32_hex():
    assert _validate_hash(_NT) == _NT


def test_validate_hash_rejects_wrong_length():
    assert _validate_hash("abc") is None


def test_validate_hash_rejects_non_str():
    assert _validate_hash(None) is None


def test_pwdump_admin_line(tmp_path):
    writer = PwdumpWriter()
    writer.open(tmp_path, "user")
    writer.write(
        {
            "_object_class": "user",
            "sAMAccountName": "Administrator",
            "objectSid": "S-1-5-21-1-2-3-500",
            "credentials": {"ntHash": _NT},
        }
    )
    writer.close()
    assert (tmp_path / "hashes.pwdump").read_text() == f"Administrator:500:{_EMPTY_LM}:{_NT}:::\n"


def test_pwdump_skips_object_without_credentials(tmp_path):
    writer = PwdumpWriter()
    writer.open(tmp_path, "user")
    writer.write({"_object_class": "user", "sAMAccountName": "x", "objectSid": "S-1-5-21-1-2-3-1"})
    writer.close()
    assert not (tmp_path / "hashes.pwdump").exists()


def test_pwdump_history_goes_to_separate_file(tmp_path):
    writer = PwdumpWriter()
    writer.open(tmp_path, "user")
    writer.write(
        {
            "_object_class": "user",
            "sAMAccountName": "u",
            "objectSid": "S-1-5-21-1-2-3-1105",
            "credentials": {"ntHash": _NT, "ntHistory": [_NT, _NT]},
        }
    )
    writer.close()
    hist = (tmp_path / "hashes_history.pwdump").read_text().splitlines()
    assert hist[0].startswith("u__history0:1105:")
    assert hist[1].startswith("u__history1:1105:")


def test_pwdump_kerberos_keys_file(tmp_path):
    # Kerberos keys belong in the pwdump output too, not just hashcat.
    writer = PwdumpWriter()
    writer.open(tmp_path, "user")
    writer.write(
        {
            "_object_class": "user",
            "sAMAccountName": "svc",
            "distinguishedName": "CN=svc,DC=corp,DC=local",
            "objectSid": "S-1-5-21-1-2-3-1200",
            "credentials": {"kerberos": [{"etype": 18, "etypeName": "AES256-CTS-HMAC-SHA1-96", "key": "ab" * 32}]},
        }
    )
    writer.close()
    assert (tmp_path / "kerberos_keys.txt").read_text() == f"CORP\\svc:AES256-CTS-HMAC-SHA1-96:{'ab' * 32}\n"
