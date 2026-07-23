# NTDSWolf -- Design Document

> **Historical design document (2025-05-22).** This captures the original v0.1.0 design. The implementation has since evolved: the decoder registry and worker pool are live, Kerberos/WDigest/cleartext extract via dissect, and output is cross-validated as byte-identical to secretsdump. See the [CHANGELOG](../CHANGELOG.md) for the current state.

**Version:** 0.1.0
**Date:** 2025-05-22
**Status:** Draft
**Upstream:** [REQUIREMENTS.md](REQUIREMENTS.md)

## 1. Design Overview

NTDSWolf is a CLI-only Python 3.14 tool built on a phase-based processing pipeline. It uses `dissect.database` for ESE parsing, `dissect.cstruct` for binary structure definitions, `typer` for CLI, and `multiprocessing.Pool` for parallel object extraction. The codebase is organized into layered subpackages: `cli/`, `core/`, `crypto/`, `output/`, and `models/`.

### 1.1 Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| CLI framework | typer | Type-hint-driven argument definitions, rich help formatting, decorator-based commands. Sits on click for robustness. |
| Processing model | Phase-based pipeline | Four sequential phases: schema → PEK → links → parallel extraction. Clean separation of concerns, easy to reason about ordering constraints. |
| Concurrency | `multiprocessing.Pool` | True parallelism for CPU-bound decryption. Each worker opens its own file handle to the ESE database. Proven approach from ntdissector. |
| Binary structures | `dissect.cstruct` | Consistent with `dissect.database` internals. C-like structure definitions that map directly to spec wire formats. Avoids impacket dependency entirely. |
| Link table storage | Adaptive (memory or SQLite) | In-memory dict for link tables under 5M entries (~500MB), automatic fallback to SQLite temp database above that threshold. Same `LinkResolver` interface either way. |
| Module structure | Layered subpackages | `cli/`, `core/`, `crypto/`, `output/`, `models/` -- separates concerns cleanly. Crypto is isolated from I/O; output formatters are pluggable; models are shared across layers. |
| Raw encrypted values | Only with `--raw` flag | Default output contains only decrypted values. `--raw` adds `RAW_` prefixed fields alongside. Keeps output manageable for large directories. |

### 1.2 Dependency Architecture

```
ntdswolf
  ├── dissect.database      # ESE parsing, NTDS object model, schema
  │   └── dissect.cstruct   # Binary structure definitions (transitive)
  │   └── dissect.util      # Compression, SID, timestamps (transitive)
  ├── pycryptodome           # AES, DES, RC4, MD4, HMAC, PBKDF2
  ├── cryptography           # ECDH, KBKDF, ConcatKDF, X.509
  ├── pyasn1-modules         # CMS/ASN.1 for LAPS v2
  ├── typer                  # CLI framework
  │   └── click              # Underlying CLI engine (transitive)
  └── rich (optional)        # Progress bars, colored output
```

No dependency on `impacket`, `ldap3`, or `six`. All SAMR structures, trust auth blobs, and credential formats are implemented directly using `dissect.cstruct` with spec references.

## 2. Processing Pipeline

### 2.1 Phase Architecture

NTDSWolf processes an NTDS.dit file in four strictly sequential phases followed by a parallel extraction phase. Each phase completes fully before the next begins.

```
┌──────────────────────────────────────────────────────────────┐
│                    NTDSWolf Pipeline                         │
│                                                              │
│  Phase 1: Schema Loading              [sequential, ~5s]     │
│    ├── Open ESE database via dissect.database                │
│    ├── Read bootstrap schema (70+ hardcoded entries)         │
│    ├── Scan datatable for classSchema/attributeSchema        │
│    ├── Build attribute indices (by ID, name, column, linkId) │
│    └── Resolve OID prefix table                              │
│                                                              │
│  Phase 2: Boot Key & PEK Decryption   [sequential, <1s]     │
│    ├── Locate boot key (--bootkey > --system > auto-detect)  │
│    ├── Extract boot key from SYSTEM hive (if needed)         │
│    ├── Find domain object in datatable                       │
│    ├── Decrypt pekList with boot key                         │
│    ├── Validate PEK authenticator GUID                       │
│    └── Store PEK array for worker access                     │
│                                                              │
│  Phase 3: Link Table Loading           [sequential, ~10s]    │
│    ├── Count link_table records                              │
│    ├── If count < 5M → in-memory dict[int, list[Link]]      │
│    │   Else → SQLite temp DB with indices                    │
│    ├── Stream all link_table records into chosen backend     │
│    ├── Build LinkResolver interface                          │
│    └── Also load sd_table → SecurityDescriptorCache          │
│                                                              │
│  Phase 4: Object Extraction            [parallel, bulk]      │
│    ├── Partition datatable by DNT range across workers       │
│    ├── Each worker: open own ESE handle                      │
│    │   ├── Iterate assigned datatable range                  │
│    │   ├── Classify object by objectClass                    │
│    │   ├── Decode attributes per type                        │
│    │   ├── Decrypt credentials with PEK                      │
│    │   ├── Resolve links from LinkResolver                   │
│    │   ├── Build distinguished name from PDNT chain          │
│    │   └── Serialize to output format                        │
│    ├── Coordinator collects serialized output                │
│    └── Writers flush to per-class output files               │
│                                                              │
│  Summary & Cleanup                                           │
│    ├── Print extraction statistics                            │
│    ├── Report errors/warnings                                │
│    └── Clean up temp files (SQLite, etc.)                    │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Phase 1: Schema Loading

Schema loading leverages `dissect.database`'s built-in schema resolution. The `NTDS` class from `dissect.database.ese.ntds` already:
- Bootstraps 70+ core attributes without a datatable scan.
- Loads full schema from `classSchema` and `attributeSchema` records.
- Builds indices by attribute ID, LDAP name, column name, and linkId.
- Resolves OID prefixes using the stored prefix table.

NTDSWolf wraps this in its own `NTDSDatabase` class that:
- Opens the ESE file and constructs the `NTDS` object.
- Validates the ESE magic number and version.
- Exposes schema lookup methods needed by decoders.
- Reports schema statistics (attribute count, class count, unresolved count).

**Design note:** `dissect.database` performs schema loading eagerly during `NTDS.__init__()`. This is acceptable since schema is required before any other phase.

### 2.3 Phase 2: Boot Key & PEK Decryption

Boot key resolution follows a priority chain:

```
1. --bootkey "aabbccdd..."  →  parse hex string directly
2. --system /path/to/SYSTEM  →  extract from registry hive
3. Auto-detect:
   a. Look for "SYSTEM" (case-insensitive) in same dir as ntds.dit
   b. Look for "SYSTEM" in parent directory of ntds.dit
   c. Look for "SYSTEM" in common relative paths (../registry/)
4. No boot key found  →  warn and proceed without decryption
```

SYSTEM hive parsing uses `dissect.regf` (part of the dissect ecosystem) to read the registry, extract class names from the four LSA subkeys, and unscramble them into the 16-byte boot key.

PEK decryption uses the `dissect.database.ese.ntds.pek` module which already handles both RC4 (pre-2012R2) and AES (2016+) encryption schemes. NTDSWolf validates the authenticator GUID after decryption and aborts with exit code 3 if validation fails.

The decrypted PEK list is stored as a `PEKList` dataclass that can be pickled for transfer to worker processes.

### 2.4 Phase 3: Link Table & Security Descriptors

#### Link Table

The `LinkResolver` is an abstract interface with two concrete implementations:

```
LinkResolver (Protocol)
  ├── get_forward_links(dnt: int) → list[ResolvedLink]
  ├── get_back_links(dnt: int) → list[ResolvedLink]
  ├── get_all_links(dnt: int) → dict[str, list[ResolvedLink]]
  └── close() → None

MemoryLinkResolver
  └── dict[int, list[LinkRecord]] indexed by link_DNT and backlink_DNT

SqliteLinkResolver
  └── Temporary SQLite DB with indices on link_DNT and backlink_DNT
```

Selection logic:
1. Stream `link_table` records, counting as we go.
2. If final count < 5,000,000 entries: build `MemoryLinkResolver`.
3. If count >= 5,000,000: stream into a `SqliteLinkResolver` (temp file in output directory).

Each `LinkRecord` stores: `link_dnt`, `backlink_dnt`, `link_base` (attribute ID), `link_deltime`, `link_deactivetime`, `link_data`. The `link_base` is resolved to an attribute name via the schema.

**Design note:** We stream the link_table in a single pass. For `MemoryLinkResolver`, we accumulate into lists. For `SqliteLinkResolver`, we batch-insert with `executemany()` every 10,000 records, then create indices after all inserts.

#### Security Descriptor Cache

Security descriptors from `sd_table` are loaded into a `dict[int, bytes]` mapping `sd_id` to raw SD bytes. These are typically much smaller than the link table (one SD may be shared by thousands of objects). Parsing to SDDL is deferred to object extraction time.

### 2.5 Phase 4: Parallel Object Extraction

#### Worker Pool Design

```
                    Main Process
                         │
            ┌────────────┼────────────┐
            │            │            │
         Worker 0     Worker 1    Worker N
            │            │            │
        ┌───┴───┐    ┌───┴───┐    ┌───┴───┐
        │ ESE   │    │ ESE   │    │ ESE   │
        │ handle│    │ handle│    │ handle│
        └───┬───┘    └───┬───┘    └───┬───┘
            │            │            │
        iterate      iterate      iterate
        datatable    datatable    datatable
        (range)      (range)      (range)
            │            │            │
            └────────────┼────────────┘
                         │
                  ┌──────┴──────┐
                  │  Output     │
                  │  Writers    │
                  │  (main      │
                  │  process)   │
                  └─────────────┘
```

**Partitioning strategy:** The datatable is not partitioned by DNT range (DNTs are sparse and non-contiguous). Instead, the main process iterates the datatable index and distributes record positions (page numbers + tag indices) to workers via a `multiprocessing.Queue`. Workers pull batches of record positions from the queue and process them independently.

**Worker initialization:** Each worker receives via its initializer:
- Path to the NTDS.dit file (opens its own file handle).
- The serialized `PEKList` (pickled, since `pycryptodome` objects need reconstruction).
- A reference to the `LinkResolver` (for `MemoryLinkResolver`, this is shared via `multiprocessing.Manager`; for `SqliteLinkResolver`, each worker opens its own read-only connection to the same temp file).
- The schema (serialized attribute maps).

**Worker processing per record:**
1. Read record from ESE by position.
2. Classify by `objectClass` attribute.
3. Select appropriate decoder (UserDecoder, ComputerDecoder, GroupDecoder, etc.).
4. Decode all attributes per the type map (FR-21).
5. If credentials are present and PEK is available: decrypt.
6. Resolve linked attributes from LinkResolver.
7. Build distinguished name by walking PDNT chain (uses a shared DN cache or per-worker local cache with main-process DN resolution for cache misses).
8. Serialize to the selected output format.
9. Return serialized bytes to main process via result queue.

**Output collection:** The main process reads serialized records from the result queue and dispatches them to per-class output writers. Writers handle file I/O, buffering, and format-specific framing (JSON array delimiters, CSV headers, etc.).

#### DN Resolution Challenge

Distinguished name construction requires walking the PDNT (parent DNT) chain to the root. This is a recursive lookup that crosses worker boundaries. Two approaches:

**Chosen approach: Two-pass with prebuilt DN cache.**

During Phase 3 (or as a sub-phase of Phase 4), the main process performs a single-threaded scan of the datatable to build a `dict[int, str]` mapping `DNT → DN`. This scan only reads `DNT_col`, `PDNT_col`, `RDNtyp_col`, and the RDN value (name) -- no attribute decoding, no decryption. For a 1M-object database, this cache is approximately 200MB (average 200 bytes per DN string).

This DN cache is then shared with workers (read-only) via `multiprocessing.shared_memory` or passed as a pickled dict to each worker's initializer.

**Trade-off:** This adds memory proportional to object count, but DN strings are essential for output and cannot be computed in isolation by workers. The memory cost is acceptable given the enterprise-scale requirement (bounded by the total DN string size, not the full object size).

## 3. Module Design

### 3.1 Package Layout

```
ntdswolf/
├── __init__.py                    # Package version (__version__)
├── __main__.py                    # Entry point: `python -m ntdswolf`
├── cli/
│   ├── __init__.py
│   ├── app.py                     # typer.Typer() app definition, main command
│   └── callbacks.py               # Argument validation callbacks (boot key format, paths)
├── core/
│   ├── __init__.py
│   ├── database.py                # NTDSDatabase: wraps dissect.database NTDS
│   ├── schema.py                  # Schema extensions beyond dissect.database defaults
│   ├── pipeline.py                # PipelineOrchestrator: phases 1-4 coordination
│   ├── links.py                   # LinkResolver protocol + Memory/Sqlite implementations
│   ├── dn_cache.py                # DN reconstruction and caching
│   └── workers.py                 # Worker pool management, record distribution
├── crypto/
│   ├── __init__.py
│   ├── bootkey.py                 # SYSTEM hive boot key extraction + auto-detect
│   ├── pek.py                     # PEK list decryption (wraps dissect.database.ese.ntds.pek)
│   ├── hashes.py                  # NT/LM hash decryption, history arrays
│   ├── supplemental.py            # USER_PROPERTIES / supplementalCredentials parsing
│   ├── trusts.py                  # Trust auth info decryption + Kerberos key derivation
│   ├── dpapi.py                   # DPAPI backup key extraction (PVK + PEM)
│   ├── laps.py                    # LAPS v1 decoding + LAPS v2 decryption
│   ├── gkdi.py                    # MS-GKDI group key derivation for LAPS v2 / gMSA
│   ├── keycredential.py           # msDS-KeyCredentialLink parsing (WHfB / FIDO2)
│   └── structures.py              # dissect.cstruct definitions for all crypto wire formats
├── output/
│   ├── __init__.py
│   ├── base.py                    # OutputWriter protocol, OutputManager dispatcher
│   ├── ndjson.py                  # NDJSON writer (one JSON object per line)
│   ├── json_.py                   # Pretty-printed JSON array writer
│   ├── csv_.py                    # CSV writer with header management
│   ├── hashcat.py                 # Hashcat-format hash writer (mode 1000/3000)
│   ├── john.py                    # John the Ripper format writer
│   └── pwdump.py                  # pwdump format writer
├── models/
│   ├── __init__.py
│   ├── objects.py                 # Frozen dataclasses: ADUser, ADComputer, ADGroup, ADTrust, etc.
│   ├── credentials.py             # NTHash, KerberosKey, WDigestHash, SupplementalCredentials, etc.
│   ├── flags.py                   # IntFlag/StrEnum: UserAccountControl, GroupType, TrustAttrs, etc.
│   ├── links.py                   # LinkRecord, ResolvedLink dataclasses
│   └── metadata.py                # ReplicationMetadata, SecurityDescriptor dataclasses
├── decoders/
│   ├── __init__.py
│   ├── registry.py                # DecoderRegistry: maps objectClass → Decoder
│   ├── base.py                    # BaseDecoder: common attribute decoding logic
│   ├── users.py                   # UserDecoder: user/computer-specific attribute handling
│   ├── groups.py                  # GroupDecoder: group membership resolution
│   ├── trusts.py                  # TrustDecoder: trust attribute handling
│   ├── domains.py                 # DomainDecoder: domain policy attributes
│   ├── gpo.py                     # GPODecoder: group policy container attributes
│   ├── gmsa.py                    # GMSADecoder: managed service account handling
│   ├── bitlocker.py               # BitLockerDecoder: FVE recovery info
│   ├── kds.py                     # KDSDecoder: KDS root key extraction
│   └── generic.py                 # GenericDecoder: fallback for unknown object classes
└── constants.py                   # Well-known GUIDs, empty hashes, attribute OIDs, spec constants
```

### 3.2 Import DAG

The import dependency graph is strictly layered with no circular dependencies:

```
cli/
  └── imports: core/, models/

core/
  ├── imports: crypto/, models/, decoders/, output/
  └── does NOT import: cli/

crypto/
  ├── imports: models/, constants
  └── does NOT import: core/, cli/, output/, decoders/

decoders/
  ├── imports: crypto/, models/, constants
  └── does NOT import: core/, cli/, output/

output/
  ├── imports: models/, constants
  └── does NOT import: core/, cli/, crypto/, decoders/

models/
  ├── imports: constants
  └── does NOT import: anything else in ntdswolf

constants.py
  └── imports: nothing (stdlib only)
```

The key invariant: `crypto/` never imports from `core/` (protocol logic is independent of transport/orchestration). `output/` never imports from `crypto/` (output formatting is independent of decryption logic). `models/` is the shared vocabulary across all layers.

### 3.3 Key Classes

#### `core/database.py` -- NTDSDatabase

Wraps `dissect.database.ese.ntds.NTDS` with additional functionality:

```python
class NTDSDatabase:
    """Primary interface to an NTDS.dit database.

    Wraps dissect.database's NTDS class and adds boot key management,
    schema statistics, and worker-friendly serialization.
    """

    ntds: NTDS                          # dissect.database NTDS instance
    pek_list: PEKList | None            # Decrypted PEK array (None if no boot key)
    schema_stats: SchemaStats           # Attribute/class counts for reporting
    db_path: Path                       # Path to ntds.dit for worker initialization

    def open(path: Path) -> NTDSDatabase: ...
    def unlock(bootkey: bytes) -> None: ...
    def iter_datatable() -> Iterator[Record]: ...
    def iter_link_table() -> Iterator[Record]: ...
    def iter_sd_table() -> Iterator[Record]: ...
    def domain() -> Record | None: ...
```

#### `core/pipeline.py` -- PipelineOrchestrator

Coordinates the four phases:

```python
class PipelineOrchestrator:
    """Runs the four-phase extraction pipeline.

    Each phase completes fully before the next begins.
    Phases are: schema → PEK → links → parallel extraction.
    """

    db: NTDSDatabase
    config: ExtractionConfig            # CLI args as a frozen dataclass
    link_resolver: LinkResolver
    dn_cache: dict[int, str]
    output_manager: OutputManager

    def run() -> ExtractionResult: ...
    def _phase_schema() -> None: ...
    def _phase_pek() -> None: ...
    def _phase_links() -> None: ...
    def _phase_extract() -> None: ...
```

#### `core/links.py` -- LinkResolver

```python
class LinkResolver(Protocol):
    """Resolves linked attribute values for an object by its DNT."""

    def forward_links(self, dnt: int) -> dict[str, list[ResolvedLink]]: ...
    def back_links(self, dnt: int) -> dict[str, list[ResolvedLink]]: ...
    def close(self) -> None: ...

class MemoryLinkResolver:
    """In-memory link resolution for databases with < 5M links."""
    _forward: dict[int, list[LinkRecord]]
    _backward: dict[int, list[LinkRecord]]

class SqliteLinkResolver:
    """SQLite-backed link resolution for very large databases."""
    _db_path: Path
    _conn: sqlite3.Connection
```

#### `crypto/structures.py` -- Wire Format Definitions

All binary structures defined with `dissect.cstruct`, directly mapped from Microsoft specs:

```python
from dissect.cstruct import cstruct

cdef = cstruct()
cdef.load("""
/* [MS-SAMR] §2.2.11.1 - Encrypted secret header */
struct ENC_SECRET {
    WORD   AlgorithmId;      /* 0x6609 = RC4, 0x6610 = AES */
    WORD   Flags;
    DWORD  PekIndex;         /* Index into PEK list */
    BYTE   Salt[16];
    /* Followed by encrypted data (variable length) */
};

/* [MS-SAMR] §2.2.10 - USER_PROPERTIES header */
struct USER_PROPERTIES {
    DWORD  Reserved1;
    DWORD  Length;
    WORD   Reserved2;
    WORD   Reserved3;
    BYTE   Reserved4[96];
    WORD   PropertySignature;   /* Must be 0x50 ('P') */
    WORD   PropertyCount;
    /* Followed by PropertyCount USER_PROPERTY entries */
};

/* [MS-SAMR] §2.2.10 - Individual property */
struct USER_PROPERTY {
    WORD   NameLength;
    WORD   ValueLength;
    WORD   Reserved;
    /* Followed by Name (NameLength bytes, UTF-16LE) */
    /* Followed by Value (ValueLength bytes) */
};

/* [MS-KILE] - Kerberos stored credential */
struct KERB_STORED_CREDENTIAL {
    WORD   Revision;           /* Must be 3 */
    WORD   Flags;
    WORD   CredentialCount;
    WORD   OldCredentialCount;
    WORD   DefaultSaltLength;
    WORD   DefaultSaltMaximumLength;
    DWORD  DefaultSaltOffset;
    /* Followed by KERB_KEY_DATA entries */
};

/* ... additional structures for trusts, DPAPI, LAPS, etc. */
""")
```

#### `models/objects.py` -- AD Object Models

Frozen dataclasses representing extracted AD objects:

```python
@dataclass(frozen=True)
class ADObject:
    """Base class for all extracted AD objects."""
    dn: str
    dnt: int
    object_class: str
    object_guid: str | None
    object_sid: str | None
    when_created: datetime | None
    when_changed: datetime | None
    is_deleted: bool
    raw_attributes: dict[str, Any]     # All non-decoded attributes

@dataclass(frozen=True)
class ADUser(ADObject):
    """Extracted AD user account."""
    sam_account_name: str
    user_principal_name: str | None
    display_name: str | None
    user_account_control: UserAccountControl
    pwd_last_set: datetime | None
    last_logon_timestamp: datetime | None
    account_expires: datetime | None
    admin_count: int | None
    credentials: UserCredentials | None
    member_of: list[str]               # List of group DNs
    sid_history: list[str]             # List of SID strings
    replication_metadata: list[ReplicationMetadataEntry] | None

@dataclass(frozen=True)
class ADComputer(ADObject):
    """Extracted AD computer account."""
    sam_account_name: str
    dns_host_name: str | None
    operating_system: str | None
    operating_system_version: str | None
    user_account_control: UserAccountControl
    credentials: UserCredentials | None
    laps_password: LAPSPassword | None
    allowed_to_delegate_to: list[str]
    allowed_to_act_on_behalf: list[str]   # SIDs from msDS-AllowedToActOnBehalfOfOtherIdentity

@dataclass(frozen=True)
class ADGroup(ADObject):
    """Extracted AD security or distribution group."""
    sam_account_name: str
    group_type: GroupType
    members: list[str]                 # List of member DNs
    member_of: list[str]               # List of parent group DNs
    admin_count: int | None

@dataclass(frozen=True)
class ADTrust(ADObject):
    """Extracted AD trust relationship."""
    trust_partner: str
    trust_type: TrustType
    trust_direction: TrustDirection
    trust_attributes: TrustAttributes
    flat_name: str | None
    security_identifier: str | None
    trust_credentials: TrustCredentials | None
```

#### `models/credentials.py` -- Credential Models

```python
@dataclass(frozen=True)
class NTHash:
    """NT (NTLM) password hash -- MD4 of UTF-16LE password."""
    hash: bytes                        # 16 bytes
    def hex(self) -> str: ...

@dataclass(frozen=True)
class KerberosKey:
    """Single Kerberos encryption key from supplementalCredentials."""
    key_type: KerberosKeyType          # IntEnum: AES256, AES128, RC4, DES
    key_value: bytes
    salt: str
    iteration_count: int

@dataclass(frozen=True)
class UserCredentials:
    """All credential material for a user or computer account."""
    nt_hash: NTHash | None
    lm_hash: NTHash | None
    nt_history: list[NTHash]
    lm_history: list[NTHash]
    kerberos_keys: list[KerberosKey]
    wdigest_hashes: list[bytes]        # 29 × 16-byte MD5 hashes
    cleartext_password: str | None
    ntlm_strong_ntowf: NTHash | None

@dataclass(frozen=True)
class TrustCredentials:
    """Decrypted trust authentication info."""
    cleartext_password: str | None
    nt4owf_hash: bytes | None
    rc4_hmac_key: bytes | None
    aes128_key: bytes | None
    aes256_key: bytes | None
    previous: TrustCredentials | None  # Previous auth info (key rotation)

@dataclass(frozen=True)
class LAPSPassword:
    """LAPS password (v1 plaintext or v2 decrypted)."""
    version: int                       # 1 or 2
    password: str
    expiration: datetime | None
    account_name: str | None           # LAPS v2 managed account name
```

#### `models/flags.py` -- Enumerations and Flags

Every flag and enumeration is defined as an `IntFlag` or `IntEnum` with the spec section in the docstring:

```python
class UserAccountControl(IntFlag):
    """Account control flags. Per [MS-ADTS] §2.2.16."""
    SCRIPT                                 = 0x0000_0001
    ACCOUNTDISABLE                         = 0x0000_0002
    HOMEDIR_REQUIRED                       = 0x0000_0008
    LOCKOUT                                = 0x0000_0010
    PASSWD_NOTREQD                         = 0x0000_0020
    PASSWD_CANT_CHANGE                     = 0x0000_0040
    ENCRYPTED_TEXT_PASSWORD_ALLOWED         = 0x0000_0080
    NORMAL_ACCOUNT                         = 0x0000_0200
    INTERDOMAIN_TRUST_ACCOUNT              = 0x0000_0800
    WORKSTATION_TRUST_ACCOUNT              = 0x0000_1000
    SERVER_TRUST_ACCOUNT                   = 0x0000_2000
    DONT_EXPIRE_PASSWD                     = 0x0001_0000
    MNS_LOGON_ACCOUNT                      = 0x0002_0000
    SMARTCARD_REQUIRED                     = 0x0004_0000
    TRUSTED_FOR_DELEGATION                 = 0x0008_0000
    NOT_DELEGATED                          = 0x0010_0000
    USE_DES_KEY_ONLY                       = 0x0020_0000
    DONT_REQUIRE_PREAUTH                   = 0x0040_0000
    PASSWORD_EXPIRED                       = 0x0080_0000
    TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x0100_0000
    PARTIAL_SECRETS_ACCOUNT                = 0x0400_0000

class GroupType(IntFlag):
    """Group type flags. Per [MS-ADTS] §2.2.12."""
    GLOBAL_GROUP        = 0x0000_0002
    DOMAIN_LOCAL_GROUP  = 0x0000_0004
    UNIVERSAL_GROUP     = 0x0000_0008
    SECURITY_ENABLED    = 0x8000_0000

class TrustType(IntEnum):
    """Trust type values. Per [MS-ADTS] §6.1.6.9.1."""
    DOWNLEVEL  = 1   # Windows NT
    UPLEVEL    = 2   # Active Directory
    MIT        = 3   # Non-Windows Kerberos
    DCE        = 4   # DCE realm

class TrustDirection(IntFlag):
    """Trust direction flags. Per [MS-ADTS] §6.1.6.9.1."""
    DISABLED  = 0
    INBOUND   = 1
    OUTBOUND  = 2
    BIDIRECTIONAL = 3
```

### 3.4 Decoder Architecture

Decoders are responsible for transforming raw ESE records into typed `ADObject` instances. Each decoder handles one or more object classes.

```
DecoderRegistry
  ├── register(object_class: str, decoder: type[BaseDecoder])
  ├── get(object_class: str) -> BaseDecoder
  └── default -> GenericDecoder

BaseDecoder
  ├── decode(record, schema, pek, link_resolver, dn_cache) -> ADObject
  ├── _decode_common_attrs(record, schema) -> dict
  ├── _decode_timestamps(record, schema) -> dict
  └── _decode_security_descriptor(record, sd_cache) -> str | None

UserDecoder(BaseDecoder)
  ├── decode() -> ADUser
  ├── _decode_credentials(record, pek) -> UserCredentials | None
  └── _decode_delegation(record) -> list[str]

GroupDecoder(BaseDecoder)
  ├── decode() -> ADGroup
  └── _resolve_members(dnt, link_resolver) -> list[str]

TrustDecoder(BaseDecoder)
  ├── decode() -> ADTrust
  └── _decode_trust_auth(encrypted, pek) -> TrustCredentials

GenericDecoder(BaseDecoder)
  └── decode() -> ADObject  # All attributes as raw key-value pairs
```

**Registration:**

```python
registry = DecoderRegistry()
registry.register("user", UserDecoder)
registry.register("computer", UserDecoder)       # Computers are users with extra attrs
registry.register("group", GroupDecoder)
registry.register("trustedDomain", TrustDecoder)
registry.register("domainDNS", DomainDecoder)
registry.register("groupPolicyContainer", GPODecoder)
registry.register("msDS-GroupManagedServiceAccount", GMSADecoder)
registry.register("msKds-ProvRootKey", KDSDecoder)
registry.register("msFVE-RecoveryInformation", BitLockerDecoder)
# All unregistered classes fall through to GenericDecoder
```

### 3.5 Output Writer Architecture

Output writers implement a common protocol and are selected by the `--format` flag. The `OutputManager` coordinates multiple writers (e.g., when `--format ndjson` is selected, it opens per-class `.ndjson` files).

```python
class OutputWriter(Protocol):
    """Writes extracted objects to a specific output format."""
    def open(self, output_dir: Path, object_class: str) -> None: ...
    def write(self, obj: ADObject) -> None: ...
    def close(self) -> None: ...

class OutputManager:
    """Dispatches objects to per-class output writers."""
    def __init__(self, format: str, output_dir: Path, extract_classes: set[str]): ...
    def write(self, obj: ADObject) -> None: ...
    def finalize(self) -> OutputStats: ...
```

Hash-format writers (hashcat, john, pwdump) only process objects with credentials (ADUser, ADComputer). They produce a single output file rather than per-class files.

## 4. Data Flow Details

### 4.1 Attribute Decoding Flow

```
ESE Record
    │
    ├── record.get("ATTm589970")  →  raw bytes
    │
    ▼
Schema Lookup
    │
    ├── schema.lookup_attribute(column="ATTm589970")
    │   → Attribute(name="cn", syntax=DirectoryString, ...)
    │
    ▼
Type Decoder
    │
    ├── SYNTAX_DECODER_MAP[DirectoryString](raw_bytes, codepage)
    │   → "Administrator"
    │
    ▼
Semantic Decoder (attribute-specific)
    │
    ├── ATTRIBUTE_DECODER_MAP.get("userAccountControl")
    │   → UserAccountControl(0x10200)
    │   → UserAccountControl.NORMAL_ACCOUNT | UserAccountControl.DONT_EXPIRE_PASSWD
    │
    ▼
ADObject field assignment
```

Two-level decoding: first the raw bytes are decoded by AD syntax type (string, integer, SID, GUID, timestamp), then certain attributes get a second semantic decoding pass (flags → named flags, SIDs → string format, etc.).

### 4.2 Credential Decryption Flow

```
record.get("unicodePwd")  →  encrypted bytes
    │
    ▼
Parse ENC_SECRET header
    ├── algorithm_id: 0x6609 (RC4) or 0x6610 (AES)
    ├── pek_index: 0
    └── salt: 16 random bytes
    │
    ▼
Key derivation
    ├── HMAC-SHA1(PEK[pek_index], salt)
    └── 1000 PBKDF2 rounds
    │
    ▼
Decrypt
    ├── RC4: rc4_decrypt(derived_key, ciphertext)
    └── AES: aes_128_cbc_decrypt(derived_key, iv=salt, ciphertext)
    │
    ▼
Validate
    ├── Check length == 16 bytes (for NT/LM hash)
    └── Store as NTHash(hash=decrypted_bytes)
```

### 4.3 Supplemental Credentials Flow

```
record.get("supplementalCredentials")  →  encrypted bytes
    │
    ▼
PEK decrypt (same as above)  →  USER_PROPERTIES blob
    │
    ▼
Parse USER_PROPERTIES header
    ├── Validate PropertySignature == 0x50
    └── Read PropertyCount
    │
    ▼
Iterate properties
    ├── "Primary:Kerberos-Newer-Keys"
    │     ├── Parse KERB_STORED_CREDENTIAL_NEW
    │     ├── Extract AES256, AES128, DES, RC4 keys
    │     └── → list[KerberosKey]
    │
    ├── "Primary:WDigest"
    │     ├── Read 29 × 16-byte MD5 hashes
    │     └── → list[bytes]
    │
    ├── "Primary:CLEARTEXT"
    │     ├── Decode UTF-16LE
    │     └── → str
    │
    ├── "Primary:NTLM-Strong-NTOWF"
    │     └── → NTHash
    │
    └── "Primary:Kerberos" (legacy)
          ├── Parse KERB_STORED_CREDENTIAL
          └── → list[KerberosKey] (DES + RC4 only)
```

### 4.4 Trust Password Key Derivation Flow

```
record.get("trustAuthOutgoing")  →  encrypted bytes
    │
    ▼
PEK decrypt  →  LSAPR_AUTH_INFORMATION array
    │
    ▼
Parse each LSAPR_AUTH_INFORMATION entry
    ├── AuthType == CLEAR (1)
    │     ├── Extract UTF-16LE password bytes
    │     ├── Derive RC4 key: MD4(password_utf16le)
    │     ├── Derive AES128 key: string_to_key(password, salt, AES128)
    │     ├── Derive AES256 key: string_to_key(password, salt, AES256)
    │     └── Salt = "DOMAIN.COMkrbtgtTRUSTED.COM" (uppercase realm names)
    │
    └── AuthType == NT4OWF (2)
          └── Extract 16-byte NT hash directly
```

## 5. Error Handling Strategy

### 5.1 Error Categories

| Category | Handling | User Impact |
|---|---|---|
| **Fatal errors** | Abort with clear message and exit code | Missing ntds.dit, invalid ESE format, wrong boot key |
| **Record errors** | Log + skip record, increment error counter | Corrupted individual record, malformed attribute |
| **Decode errors** | Log + use fallback value, continue | Unparseable timestamp, unknown encoding, invalid SID |
| **Crypto errors** | Log + output encrypted hex, continue | Single secret decryption failure (corrupt blob) |

### 5.2 Error Reporting

Errors are collected during processing and summarized at completion:

```
NTDSWolf extraction complete.
  Objects extracted: 125,432
  Errors: 3
    DNT 45021: Failed to decode supplementalCredentials: invalid property signature 0x00
    DNT 67834: Failed to decode objectSid: unexpected length 8 (expected >= 12)
    DNT 99012: Failed to decrypt unicodePwd: AES decryption produced 0 bytes
  Output: ./ntdswolf_output/
```

All error messages include the DNT (object identifier), the attribute name, and a description of the failure. No bare `except:` clauses anywhere. Every handler catches the most specific exception type possible.

### 5.3 Graceful Degradation

When the boot key is unavailable:
- All credential attributes are output as hex-encoded ciphertext.
- Field names are suffixed with `_encrypted` (e.g., `"unicodePwd_encrypted": "0102ab..."`).
- A warning is printed once at the start, not per-record.
- Hash-format outputs (hashcat, john, pwdump) are skipped entirely with an explanatory message.

When a specific decoder fails:
- The object falls through to `GenericDecoder` and is output with raw attribute values.
- The error is logged and counted.

## 6. Performance Considerations

### 6.1 Memory Budget

| Component | Estimated Size (1M objects) | Notes |
|---|---|---|
| ESE page cache | ~32MB (4096 × 8KB pages) | Per-process LRU, managed by dissect |
| Schema indices | ~5MB | Small, loaded once |
| DN cache | ~200MB | Shared across workers, read-only |
| Link table (memory) | ~500MB | Only if < 5M links |
| Link table (SQLite) | ~0 (on disk) | Used if >= 5M links |
| Worker overhead | ~50MB × N workers | File handles, crypto state |
| **Total (4 workers)** | **~940MB** | Well within enterprise server capacity |

### 6.2 I/O Optimization

- ESE pages are read via `dissect.database`'s LRU cache (4096 entries). B-tree traversal patterns produce good cache hit rates.
- Output writers buffer writes (64KB default) and flush periodically.
- SQLite link resolver uses WAL mode for concurrent read access by workers.
- SYSTEM hive is read once during Phase 2 and closed immediately.

### 6.3 CPU Optimization

- Decryption (RC4/AES/DES) is the primary CPU cost. `pycryptodome` uses C extensions for all cipher operations.
- Attribute decoding is Python-bound but lightweight (string decode, struct unpack).
- Worker count defaults to CPU count. Decryption-heavy workloads scale linearly with cores.

## 7. Testing Strategy

### 7.1 Test Categories

| Category | Scope | Approach |
|---|---|---|
| **Unit tests** | Individual decoders, crypto functions, flag parsing | Isolated tests with known input/output pairs from spec examples |
| **Structure tests** | `dissect.cstruct` definitions against known wire samples | Hex blobs from Wireshark/spec appendices parsed and validated |
| **Integration tests** | Full pipeline against test NTDS.dit files | Known-good databases with verified hash outputs |
| **Format tests** | Output writers produce valid JSON/CSV/hashcat/john/pwdump | Parse output with standard tools and validate structure |
| **Error tests** | Corrupted records, wrong boot key, missing attributes | Verify graceful degradation and correct error messages |

### 7.2 Test Data

Test NTDS.dit files with known credentials are maintained in `tests/fixtures/`. These are small, synthetic databases created with known passwords so hash outputs can be verified deterministically.

### 7.3 Coverage Target

90%+ coverage for `crypto/`, `decoders/`, `models/`, and `output/`. Lower coverage acceptable for `core/workers.py` (multiprocessing coordination is tested via integration tests) and `cli/` (tested via subprocess invocation).

## 8. Extensibility Points

### 8.1 Adding New Object Classes

1. Create a new decoder in `decoders/` (e.g., `decoders/dns.py`).
2. Create a model in `models/objects.py` (e.g., `ADDnsZone`).
3. Register in `decoders/registry.py`.
4. No changes to pipeline, output, or CLI needed.

### 8.2 Adding New Output Formats

1. Create a new writer in `output/` implementing `OutputWriter`.
2. Register in `cli/app.py`'s format choices.
3. No changes to pipeline, decoders, or models needed.

### 8.3 Adding New Credential Types

1. Add `dissect.cstruct` definition to `crypto/structures.py`.
2. Add extraction logic to the appropriate `crypto/` module.
3. Add a model to `models/credentials.py`.
4. Update the relevant decoder to call the new extraction.

### 8.4 Future: ADAM/AD LDS Support

The architecture supports ADAM by:
- `NTDSDatabase` can detect ADAM databases by the presence of different PEK storage locations (schema/configuration containers instead of domain object).
- Decoders already handle unknown object classes via `GenericDecoder`.
- ADAM-specific decoders can be added without modifying existing code.
- Boot key derivation for ADAM (from PEK bytes) would be a new method in `crypto/bootkey.py`.
