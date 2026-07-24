# SPDX-License-Identifier: Apache-2.0
"""Tests for the raw-attribute passthrough (decoders/base.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ntdswolf.core.pipeline import ExtractionConfig, PipelineOrchestrator
from ntdswolf.decoders.base import _encode_passthrough

_FIXTURES = Path(__file__).parent / "fixtures" / "aesedb"


def test_encode_passthrough_ascii_kept_binary_hexed():
    assert _encode_passthrough("CN=foo,DC=bar") == "CN=foo,DC=bar"  # printable ASCII string kept
    assert _encode_passthrough(b"hello") == "hello"  # printable bytes decode to text
    assert _encode_passthrough(b"\x00\x01\xff") == "0001ff"  # binary bytes -> hex
    assert _encode_passthrough("caf\xe9") == "caf\xe9".encode("utf-8", "surrogatepass").hex()  # non-ASCII -> hex
    assert _encode_passthrough(b"\ttab") == b"\ttab".hex()  # control char (0x09) is not printable -> hex


def test_encode_passthrough_scalars_and_containers():
    true_value = True
    assert _encode_passthrough(513) == 513
    assert _encode_passthrough(true_value) is true_value
    assert _encode_passthrough(None) is None
    assert _encode_passthrough(["a", b"\xff"]) == ["a", "ff"]
    assert _encode_passthrough({"k": b"\x01"}) == {"k": "01"}


def test_passthrough_dumps_unmapped_attrs_without_duplicating_curated(tmp_path):
    fx = _FIXTURES / "win2016_64"
    if not (fx / "ntds.dit").is_file() or not (fx / "SYSTEM").is_file():
        pytest.skip("aesedb fixture win2016_64 not present")
    out = tmp_path / "out"
    PipelineOrchestrator(ExtractionConfig(ntds_path=fx / "ntds.dit", system_path=fx / "SYSTEM", output_dir=out, output_format="ndjson", quiet=True)).run()
    krbtgt = next(o for o in (json.loads(line) for line in (out / "users.ndjson").read_text().splitlines()) if o.get("sAMAccountName") == "krbtgt")
    unmapped = krbtgt["_unmapped"]
    # Previously-dropped raw LDAP attributes are now surfaced.
    assert "primaryGroupID" in unmapped
    assert "codePage" in unmapped
    # Curated attributes and dissect-internal structural columns are NOT re-emitted here.
    assert not ({"sAMAccountName", "objectClass", "nTSecurityDescriptor", "unicodePwd", "Pdnt", "Ncdnt", "Ancestors"} & set(unmapped))


def test_generic_class_object_uses_passthrough_not_internal_columns(tmp_path):
    # Generic (unmapped) classes go through the same passthrough as everything else:
    # common attrs at top level, real attrs under _unmapped, and dissect's internal
    # structural columns (Obj/Time/CNT/...) are not leaked at top level.
    fx = _FIXTURES / "win2016_64"
    if not (fx / "ntds.dit").is_file() or not (fx / "SYSTEM").is_file():
        pytest.skip("aesedb fixture win2016_64 not present")
    out = tmp_path / "out"
    PipelineOrchestrator(ExtractionConfig(ntds_path=fx / "ntds.dit", system_path=fx / "SYSTEM", output_dir=out, output_format="ndjson", quiet=True)).run()
    obj = json.loads((out / "msdfsr-subscription.ndjson").read_text().splitlines()[0])
    assert not ({"Obj", "Time", "CNT", "AB_cnt", "RdnType", "Ncdnt", "Pdnt"} & set(obj))
    assert obj["_unmapped"]
    assert any(k.startswith("msDFSR-") for k in obj["_unmapped"])
