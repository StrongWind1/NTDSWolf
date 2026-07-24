# SPDX-License-Identifier: Apache-2.0
"""Unit tests for output/ndjson.py -- newline-delimited JSON output."""

from __future__ import annotations

import json

import pytest

from ntdswolf.output.ndjson import NDJSONWriter


def test_ndjson_one_object_per_line(tmp_path):
    w = NDJSONWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "a"})
    w.write({"_object_class": "user", "sAMAccountName": "b"})
    w.close()
    lines = (tmp_path / "users.ndjson").read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["sAMAccountName"] == "a"
    assert json.loads(lines[1])["sAMAccountName"] == "b"


def test_ndjson_filename_is_pluralized(tmp_path):
    w = NDJSONWriter()
    w.open(tmp_path, "computer")
    w.write({"_object_class": "computer"})
    w.close()
    assert (tmp_path / "computers.ndjson").exists()


def test_ndjson_write_before_open_raises():
    w = NDJSONWriter()
    with pytest.raises(RuntimeError):
        w.write({"_object_class": "user"})


def test_ndjson_non_native_types_are_stringified(tmp_path):
    w = NDJSONWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "blob": b"\x00\x01"})
    w.close()
    obj = json.loads((tmp_path / "users.ndjson").read_text().strip())
    assert "blob" in obj
