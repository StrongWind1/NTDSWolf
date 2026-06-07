"""Unit tests for output/hashcat.py -- per-class username:hash files for `hashcat --username`."""

from __future__ import annotations

from ntdswolf.output.hashcat import HashcatWriter

_NT = "7facdc498ed1680c4fd1448319a8c04f"
_LM = "1122334455667788aabbccddeeff0011"


def test_nt_current_is_username_hash(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "alice", "credentials": {"ntHash": _NT}})
    w.close()
    assert (tmp_path / "ntlm_user_current.txt").read_text() == f"alice:{_NT}\n"


def test_lm_is_split_into_two_halves(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "credentials": {"lmHash": _LM}})
    w.close()
    assert (tmp_path / "lm_user_current.txt").read_text().splitlines() == [f"u:{_LM[:16]}", f"u:{_LM[16:]}"]


def test_history_goes_to_history_file(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "credentials": {"ntHistory": [_NT, _NT]}})
    w.close()
    assert (tmp_path / "ntlm_user_history.txt").read_text() == f"u:{_NT}\nu:{_NT}\n"


def test_filenames_are_per_object_type(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "computer")
    w.write({"_object_class": "computer", "sAMAccountName": "PC$", "credentials": {"ntHash": _NT}})
    w.write({"_object_class": "msDS-GroupManagedServiceAccount", "sAMAccountName": "svc$", "credentials": {"ntHash": _NT}})
    w.close()
    assert (tmp_path / "ntlm_computer_current.txt").read_text() == f"PC$:{_NT}\n"
    assert (tmp_path / "ntlm_gmsa_current.txt").read_text() == f"svc$:{_NT}\n"


def test_username_field_rid(tmp_path):
    w = HashcatWriter(username_field="rid")
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "objectSid": "S-1-5-21-1-2-3-1105", "credentials": {"ntHash": _NT}})
    w.close()
    assert (tmp_path / "ntlm_user_current.txt").read_text() == f"1105:{_NT}\n"


def test_username_field_upn_and_sid(tmp_path):
    sid = "S-1-5-21-1-2-3-1105"
    w_upn = HashcatWriter(username_field="upn")
    w_upn.open(tmp_path / "upn", "user")
    (tmp_path / "upn").mkdir()
    w_upn.write({"_object_class": "user", "sAMAccountName": "u", "userPrincipalName": "u@corp.local", "objectSid": sid, "credentials": {"ntHash": _NT}})
    w_upn.close()
    assert (tmp_path / "upn" / "ntlm_user_current.txt").read_text() == f"u@corp.local:{_NT}\n"

    (tmp_path / "sid").mkdir()
    w_sid = HashcatWriter(username_field="sid")
    w_sid.open(tmp_path / "sid", "user")
    w_sid.write({"_object_class": "user", "sAMAccountName": "u", "objectSid": sid, "credentials": {"ntHash": _NT}})
    w_sid.close()
    assert (tmp_path / "sid" / "ntlm_user_current.txt").read_text() == f"{sid}:{_NT}\n"


def test_kerberos_keys_are_not_emitted(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "credentials": {"ntHash": _NT, "kerberos": [{"etype": 18, "etypeName": "AES256-CTS-HMAC-SHA1-96", "key": "ab" * 32}]}})
    w.close()
    assert not (tmp_path / "kerberos_keys.txt").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ntlm_user_current.txt"]


def test_skips_object_without_credentials(tmp_path):
    w = HashcatWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u"})
    w.close()
    assert list(tmp_path.iterdir()) == []
