# SPDX-License-Identifier: Apache-2.0
"""Unit tests for cli/callbacks.py -- argument validation.

The --extract tests pin down the plural-name fix: decoders emit singular
class names (``user``), so the documented ``--extract users`` must normalize
to ``{"user"}`` or it silently selects nothing.
"""

from __future__ import annotations

import pytest
import typer

from ntdswolf.cli.callbacks import validate_bootkey, validate_extract_classes


def test_bootkey_valid_passthrough():
    assert validate_bootkey("aabbccdd11223344aabbccdd11223344") == "aabbccdd11223344aabbccdd11223344"


def test_bootkey_strips_whitespace():
    assert validate_bootkey("  aabbccdd11223344aabbccdd11223344  ") == "aabbccdd11223344aabbccdd11223344"


def test_bootkey_none():
    assert validate_bootkey(None) is None


def test_bootkey_too_short_rejected():
    with pytest.raises(typer.BadParameter):
        validate_bootkey("aabb")


def test_bootkey_non_hex_rejected():
    with pytest.raises(typer.BadParameter):
        validate_bootkey("z" * 32)


def test_extract_plural_maps_to_singular():
    assert validate_extract_classes(["users"]) == {"user"}


def test_extract_comma_separated_within_one_arg():
    assert validate_extract_classes(["users,groups"]) == {"user", "group"}


def test_extract_friendly_trusts_and_domains():
    assert validate_extract_classes(["trusts", "domains"]) == {"trustedDomain", "domainDNS"}


def test_extract_all_means_no_filter():
    assert validate_extract_classes(["all"]) is None


def test_extract_all_wins_over_other_names():
    assert validate_extract_classes(["users", "all"]) is None


def test_extract_canonical_name_passthrough():
    assert validate_extract_classes(["trustedDomain"]) == {"trustedDomain"}


def test_extract_case_insensitive():
    assert validate_extract_classes(["USERS", "Groups"]) == {"user", "group"}


def test_extract_unknown_class_passthrough():
    assert validate_extract_classes(["customClass"]) == {"customClass"}


def test_extract_none():
    assert validate_extract_classes(None) is None


def test_extract_empty_list():
    assert validate_extract_classes([]) is None


def test_extract_only_blanks_returns_none():
    assert validate_extract_classes(["  , ,"]) is None
