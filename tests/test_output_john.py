"""Unit tests for output/john.py -- John the Ripper NT hash output."""

from __future__ import annotations

from ntdswolf.output.john import JohnWriter

_NT = "7facdc498ed1680c4fd1448319a8c04f"


def test_john_nt_line(tmp_path):
    w = JohnWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "Administrator", "credentials": {"ntHash": _NT}})
    w.close()
    assert (tmp_path / "hashes.john").read_text() == f"Administrator:$NT${_NT}\n"


def test_john_skips_object_without_credentials(tmp_path):
    w = JohnWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u"})
    w.close()
    assert not (tmp_path / "hashes.john").exists()


def test_john_history_file(tmp_path):
    w = JohnWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "u", "credentials": {"ntHash": _NT, "ntHistory": [_NT]}})
    w.close()
    assert (tmp_path / "hashes_history.john").read_text() == f"u__history0:$NT${_NT}\n"
