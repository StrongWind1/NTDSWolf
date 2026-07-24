# SPDX-License-Identifier: Apache-2.0
"""Unit tests for output/credfiles.py -- shared identity and Kerberos-key formatting."""

from __future__ import annotations

from ntdswolf.output.credfiles import account_domain, account_username, credential_principal, kerberos_key_lines


def test_account_username_prefers_sam():
    assert account_username({"sAMAccountName": "jsmith", "name": "John"}) == "jsmith"


def test_account_username_falls_back_to_name():
    assert account_username({"name": "John"}) == "John"


def test_account_username_unknown():
    assert account_username({}) == "unknown"


def test_account_domain_from_dn():
    assert account_domain({"distinguishedName": "CN=jsmith,OU=Users,DC=corp,DC=local"}) == "CORP"


def test_account_domain_missing_dn():
    assert account_domain({}) == ""


def test_credential_principal_with_domain():
    assert credential_principal("CORP", "svc") == "CORP\\svc"


def test_credential_principal_without_domain():
    assert credential_principal("", "svc") == "svc"


def test_kerberos_key_lines_prefers_etype_name():
    creds = {"kerberos": [{"etype": 18, "etypeName": "AES256-CTS-HMAC-SHA1-96", "key": "ab" * 32}]}
    assert kerberos_key_lines(creds, "CORP\\svc") == [f"CORP\\svc:AES256-CTS-HMAC-SHA1-96:{'ab' * 32}"]


def test_kerberos_key_lines_falls_back_to_numeric_etype():
    creds = {"kerberos": [{"etype": 23, "key": "ff" * 16}]}
    assert kerberos_key_lines(creds, "u") == [f"u:23:{'ff' * 16}"]


def test_kerberos_key_lines_empty_without_keys():
    assert kerberos_key_lines({"ntHash": "x"}, "u") == []


def test_kerberos_key_lines_skips_non_dict_entries():
    creds = {"kerberos": ["garbage", {"etype": 17, "etypeName": "AES128-CTS-HMAC-SHA1-96", "key": "cd" * 16}]}
    assert kerberos_key_lines(creds, "u") == [f"u:AES128-CTS-HMAC-SHA1-96:{'cd' * 16}"]
