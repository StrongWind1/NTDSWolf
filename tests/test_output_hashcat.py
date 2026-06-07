"""Unit tests for output/hashcat.py -- NT/LM hashcat output and user mapping."""

from __future__ import annotations

from ntdswolf.output.hashcat import HashcatWriter

_NT = "7facdc498ed1680c4fd1448319a8c04f"
_LM = "aad3b435b51404eeaad3b435b51404ee"


def test_hashcat_nt_hash_and_user_map(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write(
        {
            "_object_class": "user",
            "sAMAccountName": "Administrator",
            "distinguishedName": "CN=Administrator,CN=Users,DC=corp,DC=local",
            "credentials": {"ntHash": _NT},
        }
    )
    w.close()
    assert (tmp_path / "hashes_nt.hashcat").read_text() == f"{_NT}\n"
    assert (tmp_path / "hashes_nt.hashcat.users").read_text() == f"{_NT}:CORP\\Administrator\n"


def test_hashcat_lm_hash_split_into_two_halves(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "credentials": {"lmHash": _LM}})
    w.close()
    assert (tmp_path / "hashes_lm.hashcat").read_text().splitlines() == [_LM[:16], _LM[16:]]


def test_hashcat_skips_object_without_credentials(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u"})
    w.close()
    assert not (tmp_path / "hashes_nt.hashcat").exists()


def test_hashcat_nt_history_file(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "credentials": {"ntHistory": [_NT, _NT]}})
    w.close()
    assert (tmp_path / "hashes_nt_history.hashcat").read_text() == f"{_NT}\n{_NT}\n"


def test_hashcat_kerberos_keys_file(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write(
        {
            "_object_class": "user",
            "sAMAccountName": "svc",
            "distinguishedName": "CN=svc,DC=corp,DC=local",
            "credentials": {
                "kerberos": [
                    {"etype": 18, "etypeName": "AES256-CTS-HMAC-SHA1-96", "key": "ab" * 32},
                    {"etype": 17, "etypeName": "AES128-CTS-HMAC-SHA1-96", "key": "cd" * 16},
                ],
            },
        }
    )
    w.close()
    assert (tmp_path / "kerberos_keys.txt").read_text().splitlines() == [
        f"CORP\\svc:AES256-CTS-HMAC-SHA1-96:{'ab' * 32}",
        f"CORP\\svc:AES128-CTS-HMAC-SHA1-96:{'cd' * 16}",
    ]


def test_hashcat_kerberos_falls_back_to_numeric_etype(tmp_path):
    # When etypeName is absent the numeric etype is used so no key is dropped.
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "credentials": {"kerberos": [{"etype": 23, "key": "ff" * 16}]}})
    w.close()
    assert (tmp_path / "kerberos_keys.txt").read_text() == f"u:23:{'ff' * 16}\n"


def test_hashcat_no_kerberos_file_without_keys(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "credentials": {"ntHash": _NT}})
    w.close()
    assert not (tmp_path / "kerberos_keys.txt").exists()
