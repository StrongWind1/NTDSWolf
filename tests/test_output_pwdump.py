# SPDX-License-Identifier: Apache-2.0
"""Unit tests for output/pwdump.py -- secretsdump-format .ntds / .ntds.kerberos / .ntds.cleartext."""

from __future__ import annotations

from ntdswolf.output.pwdump import PwdumpWriter, _extract_rid, _secretsdump_username, _validate_hash

_NT = "7facdc498ed1680c4fd1448319a8c04f"
_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def test_extract_rid():
    assert _extract_rid({"objectSid": "S-1-5-21-1-2-3-500"}) == 500
    assert _extract_rid({}) == 0
    assert _extract_rid({"objectSid": "S-1-5-21-1-2-3-abc"}) == 0


def test_validate_hash():
    assert _validate_hash(_NT) == _NT
    assert _validate_hash("abc") is None
    assert _validate_hash(None) is None


def test_secretsdump_username_prefixes_upn_domain_only():
    # secretsdump prefixes <UPN-domain>\ only when a userPrincipalName is present.
    assert _secretsdump_username({"sAMAccountName": "Administrator"}) == "Administrator"
    assert _secretsdump_username({"sAMAccountName": "test2", "userPrincipalName": "test2@TEST.corp"}) == "TEST.corp\\test2"


def test_ntds_line(tmp_path):
    w = PwdumpWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "Administrator", "objectSid": "S-1-5-21-1-2-3-500", "credentials": {"ntHash": _NT}})
    w.close()
    assert (tmp_path / "hashes.ntds").read_text() == f"Administrator:500:{_EMPTY_LM}:{_NT}:::\n"


def test_history_is_inline_with_single_underscore(tmp_path):
    # History lines are inline (single underscore), paired NT/LM by count, with the
    # LM field forced to the empty-LM constant (secretsdump's noLMHash default) even
    # when lmHistory carries real values.
    w = PwdumpWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "objectSid": "S-1-5-21-1-2-3-1105", "credentials": {"ntHash": _NT, "ntHistory": [_NT, _NT], "lmHistory": ["1122334455667788aabbccddeeff0011", "1122334455667788aabbccddeeff0011"]}})
    w.close()
    lines = (tmp_path / "hashes.ntds").read_text().splitlines()
    assert lines[0] == f"u:1105:{_EMPTY_LM}:{_NT}:::"
    assert lines[1] == f"u_history0:1105:{_EMPTY_LM}:{_NT}:::"
    assert lines[2] == f"u_history1:1105:{_EMPTY_LM}:{_NT}:::"


def test_history_count_is_min_of_nt_and_lm(tmp_path):
    # secretsdump zips NT/LM history (shortest wins): NT history with no matching
    # LM history produces no history lines at all.
    w = PwdumpWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "objectSid": "S-1-5-21-1-2-3-1105", "credentials": {"ntHash": _NT, "ntHistory": [_NT, _NT]}})
    w.close()
    assert (tmp_path / "hashes.ntds").read_text() == f"u:1105:{_EMPTY_LM}:{_NT}:::\n"


def test_kerberos_etypes_match_secretsdump_keytype_table(tmp_path):
    # Keyed on the numeric KeyType, mirroring impacket's KERBEROS_TYPE: the five
    # Windows supplementalCredentials KeyTypes get secretsdump's labels (incl. the
    # "dec-cbc-crc" spelling and rc4_hmac for the 0xFFFFFF74 marker, both present in
    # Server 2008 DBs), in stored order. A KeyType outside the table is emitted with
    # its hex form, exactly as secretsdump does.
    w = PwdumpWriter()
    w.open(tmp_path, "user")
    w.write(
        {
            "_object_class": "user",
            "sAMAccountName": "svc",
            "objectSid": "S-1-5-21-1-2-3-1106",
            "credentials": {
                "ntHash": _NT,
                "kerberos": [
                    {"etype": 18, "key": "ab" * 32},
                    {"etype": 17, "key": "ef" * 16},
                    {"etype": 3, "key": "cd" * 8},
                    {"etype": 1, "key": "cd" * 8},
                    {"etype": 0xFFFFFF74, "key": _NT},
                    {"etype": 19, "key": "12" * 16},  # not in the table -> hex label
                ],
            },
        }
    )
    w.close()
    assert (tmp_path / "hashes.ntds.kerberos").read_text().splitlines() == [
        f"svc:aes256-cts-hmac-sha1-96:{'ab' * 32}",
        f"svc:aes128-cts-hmac-sha1-96:{'ef' * 16}",
        f"svc:des-cbc-md5:{'cd' * 8}",
        f"svc:dec-cbc-crc:{'cd' * 8}",
        f"svc:rc4_hmac:{_NT}",
        f"svc:0x13:{'12' * 16}",
    ]


def test_cleartext_file(tmp_path):
    w = PwdumpWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "objectSid": "S-1-5-21-1-2-3-1107", "credentials": {"ntHash": _NT, "cleartextPassword": "P@ssw0rd!"}})
    w.close()
    assert (tmp_path / "hashes.ntds.cleartext").read_text() == "u:CLEARTEXT:P@ssw0rd!\n"


def test_skips_object_without_credentials(tmp_path):
    w = PwdumpWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u"})
    w.close()
    assert not (tmp_path / "hashes.ntds").exists()
