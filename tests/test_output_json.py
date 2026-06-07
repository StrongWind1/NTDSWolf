"""Unit tests for output/json_.py -- pretty-printed JSON array output."""

from __future__ import annotations

import json

from ntdswolf.output.json_ import JSONWriter


def test_json_produces_valid_array(tmp_path):
    w = JSONWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "n": 1})
    w.write({"_object_class": "user", "n": 2})
    w.close()
    data = json.loads((tmp_path / "users.json").read_text())
    assert isinstance(data, list)
    assert [d["n"] for d in data] == [1, 2]


def test_json_empty_is_valid_empty_array(tmp_path):
    w = JSONWriter()
    w.open(tmp_path, "user")
    w.close()
    assert json.loads((tmp_path / "users.json").read_text()) == []
