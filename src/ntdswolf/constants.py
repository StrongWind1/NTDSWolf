"""Well-known constants used across NTDSWolf.

This module centralizes all protocol constants, magic values, and well-known
identifiers needed for NTDS.dit parsing and credential extraction.  Every
constant is annotated with its authoritative Microsoft specification section
so that values are traceable, not guessed.

Import rules: this module imports only from the Python standard library.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# PEK (Password Encryption Key) constants
# ---------------------------------------------------------------------------

# GUID embedded in every PEK blob; validated after decryption to confirm the
# boot key was correct.  A mismatch means the wrong SYSTEM hive / boot key
# was supplied.  Per [MS-ADTS] §3.1.1.3.1.6.
PEK_AUTHENTICATOR_GUID: str = "4881d956-91ec-11d1-905a-00c04fc2d4cf"

# ---------------------------------------------------------------------------
# Encryption algorithm identifiers
# ---------------------------------------------------------------------------

# Algorithm IDs found in the ENC_SECRET header that wraps every encrypted
# attribute value (unicodePwd, dBCSPwd, supplementalCredentials, etc.).
# Per [MS-SAMR] §2.2.11.1.
ENC_ALGORITHM_RC4: int = 0x6609  # RC4 stream cipher
ENC_ALGORITHM_AES: int = 0x6610  # AES-128-CBC

# ---------------------------------------------------------------------------
# Empty / well-known hash constants
# ---------------------------------------------------------------------------

# MD4 of an empty UTF-16LE string.  Indicates the account has no password set
# (or an empty password).  Every NT hash comparison should check against this.
# Not from a spec -- this is the deterministic output of MD4(b"").
EMPTY_NT_HASH: str = "31d6cfe0d16ae931b73c59d7e0c089c0"

# DES-based LM hash of an empty password.  LM hashing splits the password
# into two 7-byte halves and DES-encrypts a constant; both halves of an empty
# password produce the same result, yielding this well-known 32-hex value.
EMPTY_LM_HASH: str = "aad3b435b51404eeaad3b435b51404ee"

# ---------------------------------------------------------------------------
# Timestamp sentinel values
# ---------------------------------------------------------------------------

# 0x7FFFFFFFFFFFFFFF -- the maximum positive 64-bit signed integer.
# Used by AD for "never expires" on accountExpires, pwdLastSet, etc.
# Per [MS-ADTS] §3.1.1.5.5.2 (Account-Expires).
NEVER_EXPIRES: int = 0x7FFF_FFFF_FFFF_FFFF  # 9223372036854775807

# Alternate "never expires" sentinel observed in some domain functional
# levels.  This is 0x7FFFFFFFFFFFFFFF minus a small offset corresponding
# to a FILETIME rounding difference in older AD implementations.
NEVER_EXPIRES_ALT: int = 0x7FFF_FFFF_BFFF_FF7F  # 9223372032559808511

# Zero means "not set" or "never" for timestamp-type attributes.
TIMESTAMP_NOT_SET: int = 0

# ---------------------------------------------------------------------------
# supplementalCredentials structure constants
# ---------------------------------------------------------------------------

# The PropertySignature field in USER_PROPERTIES must equal 0x50 (ASCII 'P').
# Used to validate that PEK decryption produced a valid plaintext blob.
# Per [MS-SAMR] §2.2.10.
USER_PROPERTIES_SIGNATURE: int = 0x50

# ---------------------------------------------------------------------------
# Boot key extraction constants
# ---------------------------------------------------------------------------

# The four LSA registry subkey names whose class values, concatenated and
# permuted, yield the 16-byte boot key (SYSKEY).  Located under
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\.
# Per Microsoft KB and well-known documentation.
BOOTKEY_LSA_KEYS: tuple[str, ...] = ("JD", "Skew1", "GBG", "Data")

# Permutation table applied to the raw 16-byte value extracted from the four
# LSA subkey class names.  The scrambled bytes are reordered using this table
# to produce the actual boot key.  This is a fixed, well-known constant
# documented in multiple public references.
BOOTKEY_PERMUTATION_TABLE: tuple[int, ...] = (
    0x08,
    0x05,
    0x04,
    0x02,
    0x0B,
    0x09,
    0x0D,
    0x03,
    0x00,
    0x06,
    0x01,
    0x0C,
    0x0E,
    0x0A,
    0x0F,
    0x07,
)

# ---------------------------------------------------------------------------
# Trust authentication type constants
# ---------------------------------------------------------------------------

# AuthType values within LSAPR_AUTH_INFORMATION entries in trustAuthIncoming
# and trustAuthOutgoing attributes.
# Per [MS-LSAD] §2.2.7.21.
TRUST_AUTH_TYPE_NONE: int = 0  # No authentication data
TRUST_AUTH_TYPE_NT4OWF: int = 1  # 16-byte NT4 OWF (MD4) hash
TRUST_AUTH_TYPE_CLEAR: int = 2  # Cleartext password (UTF-16LE encoded)
TRUST_AUTH_TYPE_VERSION: int = 3  # Version number (not an auth method)

# ---------------------------------------------------------------------------
# Kerberos encryption type constants — [MS-KILE] §2.2.6
# ---------------------------------------------------------------------------

# These are the etype values used in KERB_STORED_CREDENTIAL structures within
# supplementalCredentials, and also in msDS-SupportedEncryptionTypes.

KERBEROS_ETYPE_DES_CBC_CRC: int = 1  # DES-CBC(CRC) -- deprecated, legacy
KERBEROS_ETYPE_DES_CBC_MD5: int = 3  # DES-CBC(MD5) -- deprecated, legacy
KERBEROS_ETYPE_RC4_HMAC: int = 23  # RC4-HMAC (NTLM hash as key)
KERBEROS_ETYPE_RC4_HMAC_EXP: int = 24  # RC4-HMAC export (40-bit) -- deprecated

# Internal KeyType Windows stores for the RC4 key inside Kerberos-Newer-Keys
# supplementalCredentials (not the wire etype 23); its value is the account NT
# hash. impacket's NTDSHashes.KERBEROS_TYPE maps this marker to "rc4_hmac".
KERBEROS_KEYTYPE_RC4_MS: int = 0xFFFFFF74  # 4294967156
KERBEROS_ETYPE_AES128_CTS_HMAC_SHA1_96: int = 17  # AES128-CTS-HMAC-SHA1-96 -- per RFC 3962
KERBEROS_ETYPE_AES256_CTS_HMAC_SHA1_96: int = 18  # AES256-CTS-HMAC-SHA1-96 -- per RFC 3962

# Windows Server 2025 introduced SHA-2 based Kerberos key types.
# Per [MS-KILE] §2.2.6 (updated for WS2025).
KERBEROS_ETYPE_AES128_CTS_HMAC_SHA256_128: int = 19  # AES128-CTS-HMAC-SHA256-128
KERBEROS_ETYPE_AES256_CTS_HMAC_SHA384_192: int = 20  # AES256-CTS-HMAC-SHA384-192

# Human-readable names for Kerberos encryption types, keyed by etype integer.
# Used by output formatters to label kerberos key entries.
KERBEROS_ETYPE_NAMES: dict[int, str] = {
    KERBEROS_ETYPE_DES_CBC_CRC: "DES-CBC-CRC",
    KERBEROS_ETYPE_DES_CBC_MD5: "DES-CBC-MD5",
    KERBEROS_ETYPE_RC4_HMAC: "RC4-HMAC",
    KERBEROS_KEYTYPE_RC4_MS: "RC4-HMAC",
    KERBEROS_ETYPE_RC4_HMAC_EXP: "RC4-HMAC-EXP",
    KERBEROS_ETYPE_AES128_CTS_HMAC_SHA1_96: "AES128-CTS-HMAC-SHA1-96",
    KERBEROS_ETYPE_AES256_CTS_HMAC_SHA1_96: "AES256-CTS-HMAC-SHA1-96",
    KERBEROS_ETYPE_AES128_CTS_HMAC_SHA256_128: "AES128-CTS-HMAC-SHA256-128",
    KERBEROS_ETYPE_AES256_CTS_HMAC_SHA384_192: "AES256-CTS-HMAC-SHA384-192",
}

# ---------------------------------------------------------------------------
# Well-known object class names
# ---------------------------------------------------------------------------

# Object class strings used for decoder registration and output routing.
# These match the lDAPDisplayName of the corresponding classSchema objects.
OBJECT_CLASS_USER: str = "user"
OBJECT_CLASS_COMPUTER: str = "computer"
OBJECT_CLASS_GROUP: str = "group"
OBJECT_CLASS_DOMAIN_DNS: str = "domainDNS"
OBJECT_CLASS_TRUSTED_DOMAIN: str = "trustedDomain"
OBJECT_CLASS_OU: str = "organizationalUnit"
OBJECT_CLASS_GPO: str = "groupPolicyContainer"
OBJECT_CLASS_GMSA: str = "msDS-GroupManagedServiceAccount"
OBJECT_CLASS_MSA: str = "msDS-ManagedServiceAccount"
OBJECT_CLASS_DMSA: str = "msDS-DelegatedManagedServiceAccount"
OBJECT_CLASS_KDS_ROOT_KEY: str = "msKds-ProvRootKey"
OBJECT_CLASS_BITLOCKER: str = "msFVE-RecoveryInformation"

# ---------------------------------------------------------------------------
# Wire-format size constants
# ---------------------------------------------------------------------------

# These are well-known byte sizes for binary structures found in AD attributes
# and registry blobs.  Using named constants makes size checks self-documenting
# and avoids magic-number linter violations (PLR2004).

UUID_BYTE_LENGTH: int = 16  # GUID / UUID is exactly 16 bytes ([MS-DTYP] section 2.3.4)
FILETIME_BYTE_LENGTH: int = 8  # FILETIME is 8 bytes ([MS-DTYP] section 2.3.3)
DWORD_SIZE: int = 4  # 32-bit unsigned integer (4 bytes)
MD4_HEX_LENGTH: int = 32  # MD4/LM hash output is 16 bytes = 32 hex characters
NT4OWF_HASH_LENGTH: int = 16  # NT4 OWF (MD4) hash is exactly 16 bytes
BOOTKEY_HEX_LENGTH: int = 32  # Boot key is 16 bytes = 32 hex characters

# Trust auth blob minimum: two offset DWORDs (current + previous) = 8 bytes.
TRUST_AUTH_MIN_LENGTH: int = 8

# GKDI KDFParameter minimum: 4 DWORDs = 16 bytes.
KDF_PARAM_MIN_LENGTH: int = 16

# GKDI FFCDHKey minimum: 4-byte magic + 4-byte KeyLength = 8 bytes.
FFCDH_KEY_HEADER_SIZE: int = 8

# Key credential TLV format changed at version 2 (16-bit tag + 16-bit length).
KEY_CREDENTIAL_V2: int = 2

# SID rsplit("-", 1) always produces exactly 2 parts for a valid SID string.
SID_RSPLIT_PART_COUNT: int = 2

# Flag dict detection: a flag dict has exactly 2 keys ("value" and "flags").
FLAG_DICT_KEY_COUNT: int = 2

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_SUCCESS: int = 0
EXIT_GENERAL_ERROR: int = 1
EXIT_INVALID_DATABASE: int = 2
EXIT_BOOTKEY_FAILED: int = 3
EXIT_PARTIAL_EXTRACTION: int = 4
