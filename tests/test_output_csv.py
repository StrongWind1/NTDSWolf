"""Unit tests for output/csv_.py -- flattening and CSV output."""

from __future__ import annotations

import csv

from ntdswolf.output.csv_ import CSVWriter, _flatten_dict, _is_flag_dict


def test_is_flag_dict_true():
    assert _is_flag_dict({"value": 1, "flags": ["A"]})


def test_is_flag_dict_false_missing_flags():
    assert not _is_flag_dict({"value": 1})


def test_is_flag_dict_false_extra_keys():
    assert not _is_flag_dict({"value": 1, "flags": [], "extra": 2})


def test_flatten_flag_dict_emits_value_and_flags_columns():
    flat = _flatten_dict({"userAccountControl": {"value": 66048, "flags": ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWD"]}})
    assert flat["userAccountControl"] == "66048"
    assert flat["userAccountControl_flags"] == "NORMAL_ACCOUNT|DONT_EXPIRE_PASSWD"


def test_flatten_nested_dict_uses_dot_notation():
    flat = _flatten_dict({"credentials": {"ntHash": "abc"}})
    assert flat["credentials.ntHash"] == "abc"


def test_flatten_list_pipe_joined():
    flat = _flatten_dict({"memberOf": ["CN=A,DC=x", "CN=B,DC=x"]})
    assert flat["memberOf"] == "CN=A,DC=x|CN=B,DC=x"


def test_flatten_none_becomes_empty_string():
    assert _flatten_dict({"x": None}) == {"x": ""}


def test_csv_writer_discovers_headers(tmp_path):
    w = CSVWriter()
    w.open(tmp_path, "user")
    w.write({"_object_class": "user", "sAMAccountName": "a", "credentials": {"ntHash": "h"}})
    w.close()
    rows = list(csv.DictReader((tmp_path / "users.csv").read_text().splitlines()))
    assert rows[0]["sAMAccountName"] == "a"
    assert rows[0]["credentials.ntHash"] == "h"
