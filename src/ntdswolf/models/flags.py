"""IntFlag and IntEnum definitions for Active Directory attribute values.

Every enumeration corresponds to a specific field in the AD schema and is
annotated with its authoritative Microsoft specification section.  Decoders
use these types to convert raw integer values into structured
``{"value": int, "flags": list[str]}`` output dictionaries.

Import rules: this module imports only from the standard library.
"""

from __future__ import annotations

from enum import IntEnum, IntFlag

# ---------------------------------------------------------------------------
# UserAccountControl — [MS-ADTS] §2.2.16
# ---------------------------------------------------------------------------


class UserAccountControl(IntFlag):
    """Bit flags stored in the userAccountControl attribute.

    Controls account behaviour such as logon restrictions, delegation, and
    password policy overrides.  Per [MS-ADTS] §2.2.16 (ADS_UF_* constants).
    """

    SCRIPT = 0x0000_0001  # Logon script is executed
    ACCOUNTDISABLE = 0x0000_0002  # Account is disabled
    # 0x0000_0004 is reserved/unused
    HOMEDIR_REQUIRED = 0x0000_0008  # Home directory is required
    LOCKOUT = 0x0000_0010  # Account is locked out
    PASSWD_NOTREQD = 0x0000_0020  # No password required
    PASSWD_CANT_CHANGE = 0x0000_0040  # Cannot change password (enforced by ACL, not flag)
    ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0000_0080  # Store password using reversible encryption
    # 0x0000_0100 is TEMP_DUPLICATE_ACCOUNT -- undocumented, included for completeness
    TEMP_DUPLICATE_ACCOUNT = 0x0000_0100  # Local user account in a domain
    NORMAL_ACCOUNT = 0x0000_0200  # Default account type for users
    # 0x0000_0400 is reserved/unused
    INTERDOMAIN_TRUST_ACCOUNT = 0x0000_0800  # Trust account for inter-domain trusts
    WORKSTATION_TRUST_ACCOUNT = 0x0000_1000  # Computer account
    SERVER_TRUST_ACCOUNT = 0x0000_2000  # Domain controller account
    # 0x0000_4000 and 0x0000_8000 are reserved
    DONT_EXPIRE_PASSWD = 0x0001_0000  # Password never expires
    MNS_LOGON_ACCOUNT = 0x0002_0000  # MNS logon account (Majority Node Set)
    SMARTCARD_REQUIRED = 0x0004_0000  # Smart card required for logon
    TRUSTED_FOR_DELEGATION = 0x0008_0000  # Trusted for Kerberos unconstrained delegation
    NOT_DELEGATED = 0x0010_0000  # Account cannot be delegated
    USE_DES_KEY_ONLY = 0x0020_0000  # Restrict to DES encryption types
    DONT_REQUIRE_PREAUTH = 0x0040_0000  # Kerberos pre-authentication not required (AS-REP roastable)
    PASSWORD_EXPIRED = 0x0080_0000  # Password has expired (read-only, set by DC)
    TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x0100_0000  # Trusted for Kerberos constrained delegation (S4U2Self)
    NO_AUTH_DATA_REQUIRED = 0x0200_0000  # Bit 25 reserved; no authorization data in Kerberos tickets
    PARTIAL_SECRETS_ACCOUNT = 0x0400_0000  # Read-Only Domain Controller (RODC) account


# ---------------------------------------------------------------------------
# GroupType — [MS-ADTS] §2.2.12
# ---------------------------------------------------------------------------


class GroupType(IntFlag):
    """Bit flags stored in the groupType attribute.

    Combines scope (global/domain-local/universal) with the security/
    distribution distinction.  The high bit (SECURITY_ENABLED) determines
    whether the group creates a security principal.
    Per [MS-ADTS] §2.2.12.
    """

    # 0x0000_0001 is a built-in group created by the system.
    BUILTIN_LOCAL_GROUP = 0x0000_0001  # System-created local group
    GLOBAL_GROUP = 0x0000_0002  # Global scope
    DOMAIN_LOCAL_GROUP = 0x0000_0004  # Domain-local scope
    UNIVERSAL_GROUP = 0x0000_0008  # Universal scope
    # Bit 31 -- when set, the group is security-enabled (creates a SID).
    # When clear, the group is a distribution group only.
    # This is a negative value in signed 32-bit representation.
    SECURITY_ENABLED = 0x8000_0000  # Security group (vs. distribution)


# ---------------------------------------------------------------------------
# SAMAccountType — [MS-SAMR] §2.2.6
# ---------------------------------------------------------------------------


class SAMAccountType(IntEnum):
    """Enumeration stored in the sAMAccountType attribute.

    Unlike userAccountControl (which is a bitmask), this is a single value
    indicating the object's SAM type.  Per [MS-SAMR] §2.2.6.
    """

    SAM_DOMAIN_OBJECT = 0x0000_0000  # Domain object
    SAM_GROUP_OBJECT = 0x1000_0000  # Group object
    SAM_NON_SECURITY_GROUP = 0x1000_0001  # Non-security group (distribution)
    SAM_ALIAS_OBJECT = 0x2000_0000  # Alias (domain-local group)
    SAM_NON_SECURITY_ALIAS = 0x2000_0001  # Non-security alias
    SAM_USER_OBJECT = 0x3000_0000  # Normal user account
    SAM_MACHINE_ACCOUNT = 0x3000_0001  # Machine (computer) account
    SAM_TRUST_ACCOUNT = 0x3000_0002  # Interdomain trust account
    SAM_APP_BASIC_GROUP = 0x4000_0000  # App basic group
    SAM_APP_QUERY_GROUP = 0x4000_0001  # App query group


# ---------------------------------------------------------------------------
# TrustType — [MS-ADTS] §6.1.6.9.1
# ---------------------------------------------------------------------------


class TrustType(IntEnum):
    """Enumeration stored in the trustType attribute.

    Indicates the type of remote domain in the trust relationship.
    Per [MS-ADTS] §6.1.6.9.1.
    """

    DOWNLEVEL = 1  # Windows NT 4.0 domain (no AD)
    UPLEVEL = 2  # Active Directory domain
    MIT = 3  # Non-Windows Kerberos realm (RFC 4120)
    DCE = 4  # DCE realm (rarely used)


# ---------------------------------------------------------------------------
# TrustDirection — [MS-ADTS] §6.1.6.9.1
# ---------------------------------------------------------------------------


class TrustDirection(IntFlag):
    """Bit flags stored in the trustDirection attribute.

    Specifies whether the trust allows inbound authentication, outbound
    authentication, or both.  Per [MS-ADTS] §6.1.6.9.1.
    """

    DISABLED = 0x0000_0000  # Trust is disabled
    INBOUND = 0x0000_0001  # Inbound trust (remote domain trusts us)
    OUTBOUND = 0x0000_0002  # Outbound trust (we trust remote domain)
    BIDIRECTIONAL = 0x0000_0003  # Both directions (INBOUND | OUTBOUND)


# ---------------------------------------------------------------------------
# TrustAttributes — [MS-ADTS] §6.1.6.7.9
# ---------------------------------------------------------------------------


class TrustAttributes(IntFlag):
    """Bit flags stored in the trustAttributes attribute.

    Controls trust behaviour such as SID filtering, transitivity, and
    selective authentication.  Per [MS-ADTS] §6.1.6.7.9.
    """

    NON_TRANSITIVE = 0x0000_0001  # Trust is non-transitive
    UPLEVEL_ONLY = 0x0000_0002  # Only Windows 2000+ DCs can use
    QUARANTINED_DOMAIN = 0x0000_0004  # SID filtering enabled (quarantine)
    FOREST_TRANSITIVE = 0x0000_0008  # Forest trust (cross-forest transitive)
    CROSS_ORGANIZATION = 0x0000_0010  # Selective authentication enabled
    WITHIN_FOREST = 0x0000_0020  # Trust within the same forest (parent-child)
    TREAT_AS_EXTERNAL = 0x0000_0040  # Treat as external trust for SID filtering
    USES_RC4_ENCRYPTION = 0x0000_0080  # RC4 encryption for Kerberos tickets
    USES_AES_KEYS = 0x0000_0100  # AES keys for Kerberos cross-realm TGTs (WS2012+)
    CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x0000_0200  # No TGT delegation across org boundary
    PIM_TRUST = 0x0000_0400  # Privileged Identity Management trust (WS2016+)
    CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x0000_0800  # Enable TGT delegation for cross-org


# ---------------------------------------------------------------------------
# InstanceType — [MS-ADTS] §3.1.1.2.4.8
# ---------------------------------------------------------------------------


class InstanceType(IntFlag):
    """Bit flags stored in the instanceType attribute.

    Indicates how the object participates in replication.
    Per [MS-ADTS] §3.1.1.2.4.8.
    """

    HEAD_OF_NC = 0x0000_0001  # Object is the head of a naming context
    REPLICA = 0x0000_0002  # Replica, not the master (unused in modern AD -- always 0)
    NOT_INSTANTIATED = 0x0000_0004  # Object is a placeholder for a naming context not yet replicated
    WRITE = 0x0000_0008  # Object is writable on this DC
    NC_ABOVE = 0x0000_0010  # NC above this one is held on this DC
    NC_BEING_CONSTRUCTED = 0x0000_0020  # NC is being constructed (initial replication)
    NC_BEING_REMOVED = 0x0000_0040  # NC is being removed


# ---------------------------------------------------------------------------
# SystemFlags — [MS-ADTS] §3.1.1.2.4.10
# ---------------------------------------------------------------------------


class SystemFlags(IntFlag):
    """Bit flags stored in the systemFlags attribute.

    Controls system-level object properties such as replication scope,
    moveability, and rename restrictions.
    Per [MS-ADTS] §3.1.1.2.4.10.
    """

    FLAG_ATTR_NOT_REPLICATED = 0x0000_0001  # Attribute is not replicated
    FLAG_ATTR_REQ_PARTIAL_SET_MEMBER = 0x0000_0002  # Attribute is part of the partial attribute set (GC)
    FLAG_ATTR_IS_CONSTRUCTED = 0x0000_0004  # Attribute is constructed (computed, not stored)
    FLAG_ATTR_IS_OPERATIONAL = 0x0000_0008  # Attribute is operational (not returned by default)
    FLAG_DISALLOW_DELETE = 0x8000_0000  # Object cannot be deleted
    FLAG_CONFIG_ALLOW_RENAME = 0x4000_0000  # Object can be renamed in the configuration NC
    FLAG_CONFIG_ALLOW_MOVE = 0x2000_0000  # Object can be moved within the configuration NC
    FLAG_CONFIG_ALLOW_LIMITED_MOVE = 0x1000_0000  # Object can be moved with restrictions
    FLAG_DOMAIN_DISALLOW_RENAME = 0x0800_0000  # Object cannot be renamed in domain NCs
    FLAG_DOMAIN_DISALLOW_MOVE = 0x0400_0000  # Object cannot be moved in domain NCs
    FLAG_DISALLOW_MOVE_ON_DELETE = 0x0200_0000  # Object cannot be moved to the Deleted Objects container
    # CR_NTDS_* flags for cross-ref objects
    FLAG_CR_NTDS_NC = 0x0000_0001  # Cross-ref points to an NC
    FLAG_CR_NTDS_DOMAIN = 0x0000_0002  # Cross-ref points to a domain NC
    FLAG_CR_NTDS_NOT_GC_REPLICATED = 0x0000_0004  # NC is not replicated to GCs


# ---------------------------------------------------------------------------
# SupportedEncryptionTypes — [MS-KILE] §2.2.6
# ---------------------------------------------------------------------------


class SupportedEncryptionTypes(IntFlag):
    """Bit flags stored in msDS-SupportedEncryptionTypes.

    Advertises which Kerberos encryption types the principal supports.
    Per [MS-KILE] §2.2.6.
    """

    DES_CBC_CRC = 0x0000_0001  # DES-CBC-CRC (deprecated)
    DES_CBC_MD5 = 0x0000_0002  # DES-CBC-MD5 (deprecated)
    RC4_HMAC = 0x0000_0004  # RC4-HMAC (NTLM-derived key)
    AES128_CTS_HMAC_SHA1_96 = 0x0000_0008  # AES128-CTS-HMAC-SHA1-96
    AES256_CTS_HMAC_SHA1_96 = 0x0000_0010  # AES256-CTS-HMAC-SHA1-96
    AES256_CTS_HMAC_SHA1_96_SK = 0x0000_0020  # AES256 with session key (reserved)
    # Windows Server 2025 SHA-2 based types
    AES128_CTS_HMAC_SHA256_128 = 0x0000_0040  # AES128-CTS-HMAC-SHA256-128 (WS2025)
    AES256_CTS_HMAC_SHA384_192 = 0x0000_0080  # AES256-CTS-HMAC-SHA384-192 (WS2025)
    # Compound identity / FAST support flags (high bits)
    COMPOUND_IDENTITY_SUPPORTED = 0x0000_0100  # Compound identity supported
    CLAIMS_SUPPORTED = 0x0000_0200  # Claims supported
    RESOURCE_SID_COMPRESSION_DISABLED = 0x0000_0400  # Resource SID compression disabled


# ---------------------------------------------------------------------------
# PwdProperties — [MS-ADTS] §3.1.1.5.2.5
# ---------------------------------------------------------------------------


class PwdProperties(IntFlag):
    """Bit flags stored in the pwdProperties attribute on domain objects.

    Controls domain-wide password policy behaviour.
    Per [MS-ADTS] §3.1.1.5.2.5.
    """

    DOMAIN_PASSWORD_COMPLEX = 0x0000_0001  # Password must meet complexity requirements
    DOMAIN_PASSWORD_NO_ANON_CHANGE = 0x0000_0002  # Anonymous users cannot change passwords
    DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 0x0000_0004  # Cannot change password in cleartext (over non-SSL)
    DOMAIN_LOCKOUT_ADMINS = 0x0000_0008  # Built-in admin accounts can be locked out
    DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x0000_0010  # Store passwords using reversible encryption
    DOMAIN_REFUSE_PASSWORD_CHANGE = 0x0000_0020  # Refuse password changes (domain is read-only)


# ---------------------------------------------------------------------------
# KerberosKeyType — [MS-KILE] §2.2.6
# ---------------------------------------------------------------------------


class KerberosKeyType(IntEnum):
    """Kerberos encryption type values (etype) as stored in supplementalCredentials.

    Maps the integer etype to a symbolic name.  Used by the supplemental
    credentials parser and output formatters.
    Per [MS-KILE] §2.2.6 and RFC 3961 §8.
    """

    DES_CBC_CRC = 1  # Deprecated -- legacy Windows 2000
    DES_CBC_MD5 = 3  # Deprecated -- legacy
    AES128_CTS_HMAC_SHA1_96 = 17  # Per RFC 3962
    AES256_CTS_HMAC_SHA1_96 = 18  # Per RFC 3962
    AES128_CTS_HMAC_SHA256_128 = 19  # Windows Server 2025 -- per [MS-KILE] update
    AES256_CTS_HMAC_SHA384_192 = 20  # Windows Server 2025 -- per [MS-KILE] update
    RC4_HMAC = 23  # Uses the NT hash as the key
    RC4_HMAC_EXP = 24  # 40-bit export version -- deprecated


# ---------------------------------------------------------------------------
# Helper function
# ---------------------------------------------------------------------------


def decode_flags(value: int, flag_class: type[IntFlag]) -> dict[str, int | list[str]]:
    """Decode a raw integer into a structured flag dictionary.

    Returns the format used in JSON output::

        {"value": 66048, "flags": ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWD"]}

    This function exists because output formatters need both the raw numeric
    value (for downstream tools that operate on integers) and the human-readable
    flag names (for analysts reading the output).

    Args:
        value: Raw integer value from the AD attribute.
        flag_class: The IntFlag subclass to decode against.

    Returns:
        Dictionary with ``"value"`` (int) and ``"flags"`` (list of set flag names).

    """
    # Check each defined flag bit.  Skip zero-valued pseudo-members.
    # IntFlag iteration yields only single-bit members by default in Python 3.11+.
    flags = [member.name for member in flag_class if member.value != 0 and (value & member.value) == member.value]
    return {"value": value, "flags": flags}
