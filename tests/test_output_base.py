"""Unit tests for output/base.py -- OutputManager dispatch and class filtering.

The extract-class filter test is the output half of the --extract fix: given the
canonical set ``{"user"}``, only user objects are written.
"""

from __future__ import annotations

import pytest

from ntdswolf.output.base import SUPPORTED_FORMATS, OutputManager, output_filename

_NT = "7facdc498ed1680c4fd1448319a8c04f"


def test_supported_formats_present():
    assert {"ndjson", "json", "csv", "hashcat", "pwdump"} <= SUPPORTED_FORMATS


def test_output_filename_friendly_names():
    assert output_filename("user", "ndjson") == "users.ndjson"
    assert output_filename("computer", "csv") == "computers.csv"
    assert output_filename("trustedDomain", "json") == "trusts.json"


def test_output_filename_sanitizes_unknown_class():
    # No naive "+s" pluralization: dHCPClass must not become "dHCPClasss".
    assert output_filename("dHCPClass", "ndjson") == "dhcpclass.ndjson"
    assert output_filename("ms-DS-Some/Weird Class", "csv") == "ms-ds-some_weird_class.csv"


def test_output_filename_empty_class_falls_back():
    assert output_filename("", "ndjson") == "objects.ndjson"


def test_unsupported_format_raises(tmp_path):
    with pytest.raises(ValueError, match="Unsupported output format"):
        OutputManager("nope", tmp_path)


def test_routes_each_class_to_its_own_file(tmp_path):
    mgr = OutputManager("ndjson", tmp_path)
    mgr.write({"_object_class": "user", "sAMAccountName": "a"})
    mgr.write({"_object_class": "group", "name": "g"})
    assert mgr.finalize() == {"user": 1, "group": 1}
    assert (tmp_path / "users.ndjson").exists()
    assert (tmp_path / "groups.ndjson").exists()


def test_extract_classes_filter_drops_other_classes(tmp_path):
    mgr = OutputManager("ndjson", tmp_path, extract_classes={"user"})
    mgr.write({"_object_class": "user", "sAMAccountName": "a"})
    mgr.write({"_object_class": "group", "name": "g"})
    assert mgr.finalize() == {"user": 1}
    assert (tmp_path / "users.ndjson").exists()
    assert not (tmp_path / "groups.ndjson").exists()


def test_object_missing_class_key_is_skipped(tmp_path):
    mgr = OutputManager("ndjson", tmp_path)
    mgr.write({"sAMAccountName": "no-class"})
    assert mgr.finalize() == {}


def test_hash_format_writes_single_combined_file(tmp_path):
    mgr = OutputManager("pwdump", tmp_path)
    mgr.write({"_object_class": "user", "sAMAccountName": "a", "objectSid": "S-1-5-21-1-2-3-500", "credentials": {"ntHash": _NT}})
    mgr.write({"_object_class": "computer", "sAMAccountName": "b$", "objectSid": "S-1-5-21-1-2-3-1000", "credentials": {"ntHash": _NT}})
    assert mgr.finalize() == {"user": 1, "computer": 1}
    assert len((tmp_path / "hashes.ntds").read_text().splitlines()) == 2
