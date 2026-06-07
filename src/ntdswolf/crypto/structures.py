"""Binary wire format structures for NTDS.dit credential decryption.

All structures are defined using dissect.cstruct with C-like definitions.
Each mirrors the on-disk layout documented in the referenced Microsoft
specification section.  The module exposes a single ``cstruct`` instance
(``cs``) so callers can parse raw bytes via ``cs.<StructName>(data)``.
"""

from __future__ import annotations

from dissect.cstruct import cstruct

cs = cstruct()

# ---------------------------------------------------------------------------
# ENC_SECRET -- encrypted attribute blob header
# [MS-SAMR] section 2.2.11.1
#
# Win2k/2003/2008 (RC4):  AlgorithmId, Flags, PekIndex, Salt, then ciphertext
# Win2016+       (AES):   same header but followed by a 4-byte SecretLength
#                          before the ciphertext
#
# We define two variants; the caller picks based on AlgorithmId.
# ---------------------------------------------------------------------------
cs.load("""
struct ENC_SECRET_RC4 {
    uint16  AlgorithmId;        /* 0x10 = DB_RC4, 0x11 = DB_RC4_SALT, 0x12 = REP_RC4_SALT */
    uint16  Flags;
    uint32  PekIndex;
    char    Salt[16];
    /* remainder is EncryptedData -- variable length, parsed manually */
};

struct ENC_SECRET_AES {
    uint16  AlgorithmId;        /* 0x13 = DB_AES */
    uint16  Flags;
    uint32  PekIndex;
    char    Salt[16];
    uint32  SecretLength;
    /* remainder is EncryptedData -- variable length, parsed manually */
};
""")

# ---------------------------------------------------------------------------
# PEK_LIST_HEADER + PEK_KEY -- Password Encryption Key list
#
# The PEK list is stored in the ATTk590689 (Pek-List) attribute on the
# domainDNS object.  The first 8 bytes are the encrypted-blob header
# (Version + Flags as two DWORDs), followed by a 16-byte salt (KeyMaterial),
# then the encrypted PEK entries.  After decryption a 32-byte authenticator
# header precedes the array of PEK_KEY entries.
# ---------------------------------------------------------------------------
cs.load("""
struct PEK_LIST_HEADER {
    uint32  Version;            /* 0x02 = RC4 era, 0x03 = AES era */
    uint32  Flags;
    char    Salt[16];
    /* remainder is EncryptedPek -- variable length */
};

struct PEK_KEY {
    uint32  PekId;
    char    PekKey[16];
};
""")

# ---------------------------------------------------------------------------
# USER_PROPERTIES / USER_PROPERTY -- supplementalCredentials blob
# [MS-SAMR] section 2.2.10
#
# The outer USER_PROPERTIES header is followed by PropertyCount instances
# of USER_PROPERTY, each of which has a variable-length name and value.
# ---------------------------------------------------------------------------
cs.load("""
struct USER_PROPERTIES {
    uint32  Reserved1;          /* must be 0 */
    uint32  Length;             /* total length of structure in bytes */
    uint16  Reserved2;          /* must be 0 */
    uint16  Reserved3;          /* must be 0 */
    char    Reserved4[96];      /* must be zeros */
    uint16  PropertySignature;  /* must be 0x50 ('P') */
    uint16  PropertyCount;
    /* followed by PropertyCount x USER_PROPERTY entries (variable) */
};

struct USER_PROPERTY {
    uint16  NameLength;
    uint16  ValueLength;
    uint16  Reserved;           /* must be 0 */
    /* followed by NameLength bytes of PropertyName (UTF-16LE) */
    /* followed by ValueLength bytes of PropertyValue (hex-encoded UTF-16LE) */
};
""")

# ---------------------------------------------------------------------------
# KERB_STORED_CREDENTIAL / KERB_KEY_DATA -- Kerberos keys (legacy)
# [MS-KILE] Appendix A
# ---------------------------------------------------------------------------
cs.load("""
struct KERB_STORED_CREDENTIAL {
    uint16  Revision;           /* must be 3 */
    uint16  Flags;
    uint16  CredentialCount;
    uint16  OldCredentialCount;
    uint16  DefaultSaltLength;
    uint16  DefaultSaltMaximumLength;
    uint32  DefaultSaltOffset;
    /* followed by CredentialCount x KERB_KEY_DATA */
    /* followed by OldCredentialCount x KERB_KEY_DATA */
    /* followed by DefaultSalt at DefaultSaltOffset */
    /* followed by key data at their respective offsets */
};

struct KERB_KEY_DATA {
    uint16  Reserved1;
    uint16  Reserved2;
    uint32  Reserved3;
    int32   KeyType;            /* Kerberos encryption type (e.g. 17=AES128, 18=AES256) */
    uint32  KeyLength;
    uint32  KeyOffset;          /* offset from start of KERB_STORED_CREDENTIAL */
};
""")

# ---------------------------------------------------------------------------
# KERB_STORED_CREDENTIAL_NEW / KERB_KEY_DATA_NEW -- Kerberos newer keys
# [MS-KILE] Appendix A
#
# Introduced in Windows Server 2008; carries AES keys plus iteration count.
# ---------------------------------------------------------------------------
cs.load("""
struct KERB_STORED_CREDENTIAL_NEW {
    uint16  Revision;           /* must be 4 */
    uint16  Flags;
    uint16  CredentialCount;
    uint16  ServiceCredentialCount;
    uint16  OldCredentialCount;
    uint16  OlderCredentialCount;
    uint16  DefaultSaltLength;
    uint16  DefaultSaltMaximumLength;
    uint32  DefaultSaltOffset;
    uint32  DefaultIterationCount;
    /* followed by CredentialCount x KERB_KEY_DATA_NEW */
    /* followed by ServiceCredentialCount x KERB_KEY_DATA_NEW */
    /* followed by OldCredentialCount x KERB_KEY_DATA_NEW */
    /* followed by OlderCredentialCount x KERB_KEY_DATA_NEW */
};

struct KERB_KEY_DATA_NEW {
    uint16  Reserved1;
    uint16  Reserved2;
    uint32  Reserved3;
    uint32  IterationCount;
    int32   KeyType;
    uint32  KeyLength;
    uint32  KeyOffset;
};
""")

# ---------------------------------------------------------------------------
# LSAPR_AUTH_INFORMATION -- trust authentication blob entries
# [MS-LSAD] section 2.2.7.21
#
# Each entry carries one authentication method for a trust relationship.
# The array is preceded by a TRUST_AUTH_INFO header (Count + offsets).
# ---------------------------------------------------------------------------
cs.load("""
struct LSAPR_AUTH_INFORMATION {
    uint64  LastUpdateTime;     /* FILETIME */
    uint32  AuthType;           /* 0=NONE, 1=NT4OWF, 2=CLEAR, 3=VERSION */
    uint32  AuthInfoLength;
    /* followed by AuthInfoLength bytes of AuthInfo */
    /* followed by padding to 4-byte boundary */
};
""")

# ---------------------------------------------------------------------------
# REPL_PROPERTY_META_DATA -- replication metadata stamps
# [MS-DRSR] section 4.1.10.2.11
#
# Each attribute in the replicated partial attribute set carries metadata
# describing its replication state (originating DSA, USN, version, timestamp).
# ---------------------------------------------------------------------------
cs.load("""
struct REPLMD_HEADER {
    uint32  Version;            /* must be 1 */
    uint32  Reserved;           /* must be 0 */
    uint32  cNumEntries;
    /* followed by cNumEntries x REPLMD_ENTRY */
};

struct REPLMD_ENTRY {
    uint32  AttId;              /* attribute ID */
    uint32  Version;            /* attribute version */
    uint64  TimeChanged;        /* FILETIME -- originating write time */
    char    UuidDsaOriginating[16]; /* GUID of originating DSA */
    uint64  UsnOriginating;     /* originating USN */
    uint64  UsnLocal;           /* local USN */
};
""")
