# SPDX-License-Identifier: Apache-2.0
"""Unit tests for models/flags.py -- enum definitions and decode_flags."""

from __future__ import annotations

from ntdswolf.models.flags import (
    GroupType,
    KerberosKeyType,
    PwdProperties,
    SAMAccountType,
    SupportedEncryptionTypes,
    TrustAttributes,
    TrustDirection,
    TrustType,
    UserAccountControl,
    decode_flags,
)


def test_decode_uac_normal_dont_expire():
    # 66048 = 0x10200 = NORMAL_ACCOUNT (0x200) | DONT_EXPIRE_PASSWD (0x10000)
    assert decode_flags(66048, UserAccountControl) == {"value": 66048, "flags": ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWD"]}


def test_decode_flags_order_is_bit_order_not_input_order():
    # ACCOUNTDISABLE (0x2) is defined before NORMAL_ACCOUNT (0x200).
    assert decode_flags(0x202, UserAccountControl)["flags"] == ["ACCOUNTDISABLE", "NORMAL_ACCOUNT"]


def test_decode_flags_zero_is_empty():
    assert decode_flags(0, UserAccountControl) == {"value": 0, "flags": []}


def test_decode_multibit_named_member_not_emitted():
    # TrustDirection.BIDIRECTIONAL (0x3) is multi-bit; IntFlag iteration yields
    # only single-bit canonical members, so 0x3 decodes to INBOUND + OUTBOUND.
    assert decode_flags(0x3, TrustDirection)["flags"] == ["INBOUND", "OUTBOUND"]


def test_group_type_security_and_global():
    assert decode_flags(0x8000_0002, GroupType)["flags"] == ["GLOBAL_GROUP", "SECURITY_ENABLED"]


def test_supported_enc_types_aes_pair():
    assert decode_flags(0x18, SupportedEncryptionTypes)["flags"] == ["AES128_CTS_HMAC_SHA1_96", "AES256_CTS_HMAC_SHA1_96"]


def test_supported_enc_types_ws2025_bits():
    assert SupportedEncryptionTypes.AES128_CTS_HMAC_SHA256_128 == 0x40
    assert SupportedEncryptionTypes.AES256_CTS_HMAC_SHA384_192 == 0x80


def test_sam_account_type_values():
    assert SAMAccountType.SAM_USER_OBJECT == 0x3000_0000
    assert SAMAccountType.SAM_MACHINE_ACCOUNT == 0x3000_0001
    assert SAMAccountType.SAM_TRUST_ACCOUNT == 0x3000_0002


def test_trust_type_values():
    assert (TrustType.DOWNLEVEL, TrustType.UPLEVEL, TrustType.MIT, TrustType.DCE) == (1, 2, 3, 4)


def test_kerberos_key_types_including_ws2025():
    assert KerberosKeyType.AES128_CTS_HMAC_SHA1_96 == 17
    assert KerberosKeyType.AES256_CTS_HMAC_SHA1_96 == 18
    assert KerberosKeyType.AES128_CTS_HMAC_SHA256_128 == 19
    assert KerberosKeyType.AES256_CTS_HMAC_SHA384_192 == 20
    assert KerberosKeyType.RC4_HMAC == 23


def test_pwd_properties_complex():
    assert decode_flags(0x1, PwdProperties)["flags"] == ["DOMAIN_PASSWORD_COMPLEX"]


def test_trust_attributes_forest_transitive():
    assert decode_flags(0x8, TrustAttributes)["flags"] == ["FOREST_TRANSITIVE"]


def test_trust_attributes_combo():
    assert set(decode_flags(0x28, TrustAttributes)["flags"]) == {"FOREST_TRANSITIVE", "WITHIN_FOREST"}
