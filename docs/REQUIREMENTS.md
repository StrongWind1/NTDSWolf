# NTDSWolf -- Requirements Specification

> **Historical design document (2025-05-22).** This captures the original v0.1.0 requirements. See the [CHANGELOG](../CHANGELOG.md) for the current state.

**Version:** 0.1.0
**Date:** 2025-05-22
**Status:** Draft

## 1. Overview

NTDSWolf is a Python 3.14 command-line tool for offline parsing and credential extraction from Windows Active Directory NTDS.dit database files. It targets forensic investigators, penetration testers, and security auditors who need complete, accurate, and fast extraction of all security-relevant data from domain controller database snapshots.

NTDSWolf replaces and improves upon existing tools (ntdissector, secretsdump) by combining the mature ESE parsing of `dissect.database` with the credential extraction breadth of ntdissector and DSInternals, wrapped in a professional CLI with enterprise-scale streaming support.

### 1.1 Goals

- **Completeness:** Extract every security-relevant attribute, credential type, and relationship from NTDS.dit -- no data left behind.
- **Correctness:** Every decoded value must be traceable to a Microsoft specification section. No heuristic guessing.
- **Scale:** Handle multi-GB databases with millions of objects using bounded memory and streaming I/O.
- **Speed:** Parallel processing with configurable worker counts. Faster than ntdissector on equivalent hardware.
- **Usability:** Rich CLI with progress reporting, multiple output formats, and sensible defaults.

### 1.2 Non-Goals

- NTDSWolf is **not** a network tool. It performs no remote registry access, LDAP queries, or SMB connections. All input is local files.
- NTDSWolf does **not** perform security auditing or analysis (duplicate password detection, password age reports, privilege path analysis). It extracts data; analysis is left to downstream tools.
- NTDSWolf does **not** modify NTDS.dit files. It is strictly read-only.
- ADAM/AD LDS support is **not** in scope for v1 but the architecture must not preclude it.

## 2. Functional Requirements

### 2.1 Input Handling

#### FR-1: NTDS.dit Database Parsing
NTDSWolf shall open and parse NTDS.dit files in the Extensible Storage Engine (ESE / JET Blue) format. It shall support all ESE page sizes (4KB, 8KB, 16KB, 32KB) and both legacy and modern ESE format versions. Parsing shall use the `dissect.database` library as the ESE backend.

**Spec reference:** [MS-ESENT] Extensible Storage Engine File Format.

#### FR-2: SYSTEM Hive Boot Key Extraction
NTDSWolf shall accept the boot key (SYSKEY) via three methods, tried in this order:
1. **Raw hex string:** 32-character hex string passed via `--bootkey` argument.
2. **SYSTEM hive file:** Path to a SYSTEM registry hive file passed via `--system` argument. The boot key shall be extracted from `ControlSet00X\Control\Lsa\{JD, Skew1, GBG, Data}` class names and unscrambled per the documented permutation table.
3. **Auto-detect:** If neither `--bootkey` nor `--system` is provided, NTDSWolf shall search for a file named `SYSTEM` (case-insensitive) in the same directory as the provided ntds.dit file and in the parent directory.

If no boot key source is found or provided, NTDSWolf shall proceed without decryption and emit a warning. Encrypted attributes shall be output as hex-encoded ciphertext with a `_encrypted` suffix on the field name.

**Spec reference:** Boot key storage is documented in [MS-GKDI] and Microsoft KB articles. The permutation table is a fixed, well-known constant.

#### FR-3: Schema Resolution
NTDSWolf shall build the AD attribute schema from the NTDS.dit database itself by reading `classSchema` and `attributeSchema` records from the datatable. It shall:
- Map ESE column names (`ATTm589970`, etc.) to LDAP display names (`cn`, `sAMAccountName`, etc.).
- Resolve OID prefixes using the prefix table stored in the database.
- Support both LDAP naming (lowercase, hyphenated) and CN naming modes.
- Fall back to numeric attribute IDs for any attribute that cannot be resolved.

Schema resolution shall use `dissect.database`'s built-in schema handling (70+ bootstrap entries) augmented with full runtime schema loading from the database.

**Spec reference:** [MS-ADTS] §3.1.1.2 (Schema), [MS-DRSR] §5.16.4 (OID Prefix Mapping).

### 2.2 Object Extraction

#### FR-4: Object Classes
NTDSWolf shall extract all objects from the datatable. At minimum, it shall produce typed output for the following object classes:

| Object Class | Key Attributes |
|---|---|
| `user` | sAMAccountName, userPrincipalName, objectSid, userAccountControl, pwdLastSet, lastLogonTimestamp, accountExpires, adminCount, all credential attributes |
| `computer` | sAMAccountName, dNSHostName, objectSid, operatingSystem, operatingSystemVersion, userAccountControl, msDS-AllowedToDelegateTo, all credential attributes |
| `group` | sAMAccountName, objectSid, groupType, member list (from link_table), adminCount |
| `domainDNS` | Domain SID, domain functional level, password policy attributes (minPwdLength, maxPwdAge, lockoutThreshold, etc.), pekList |
| `trustedDomain` | trustPartner, trustType, trustDirection, trustAttributes, securityIdentifier, flatName, trustAuthIncoming, trustAuthOutgoing |
| `organizationalUnit` | ou, description, gPLink |
| `groupPolicyContainer` | displayName, gPCFileSysPath, versionNumber, gPCMachineExtensionNames, gPCUserExtensionNames |
| `msDS-GroupManagedServiceAccount` | sAMAccountName, objectSid, msDS-ManagedPasswordId, msDS-ManagedPasswordInterval, msDS-GroupMSAMembership |
| `msKds-ProvRootKey` | msKds-RootKeyData, msKds-CreateTime, msKds-UseStartTime, msKds-KDFParam, msKds-SecretAgreementParam |
| `msFVE-RecoveryInformation` | msFVE-RecoveryPassword, msFVE-VolumeGuid, msFVE-KeyPackage |

All other object classes shall be extracted with their raw attributes as generic objects.

#### FR-5: Distinguished Name Reconstruction
NTDSWolf shall reconstruct the full distinguished name (DN) for every object by walking the `DNT_col` / `PDNT_col` parent chain. The RDN type shall be determined from `RDNtyp_col` to correctly produce `CN=`, `OU=`, `DC=`, etc. prefixes.

**Spec reference:** [MS-ADTS] §3.1.1.3.1.2 (Object Naming).

#### FR-6: Linked Value Resolution
NTDSWolf shall parse the `link_table` to resolve all multi-valued linked attributes. This includes:
- Group membership (`member` / `memberOf`)
- Manager relationships (`manager` / `directReports`)
- Delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`)
- Any other linked attributes defined in the schema

Both forward links and backlinks shall be resolved. Deleted and deactivated links shall be tracked with their timestamps and included by default (with a flag to exclude them).

**Spec reference:** [MS-ADTS] §3.1.1.2.3 (Link Value Stamps).

#### FR-7: Security Descriptor Parsing
NTDSWolf shall parse security descriptors from the `sd_table` and associate them with objects via the `nTSecurityDescriptor` attribute. Security descriptors shall be output in both binary and SDDL string format.

**Spec reference:** [MS-DTYP] §2.4.6 (SECURITY_DESCRIPTOR).

### 2.3 Credential Extraction

#### FR-8: PEK Decryption
NTDSWolf shall decrypt the Password Encryption Key (PEK) list from the domain object's `pekList` attribute using the boot key. Both encryption versions shall be supported:
- **Pre-Windows Server 2012 R2:** RC4 with MD5-PBKDF (1000 iterations), salt from PEK header.
- **Windows Server 2016+:** AES-128-CBC with PBKDF2-HMAC-SHA1.

The PEK authenticator GUID (`4881d956-91ec-11d1-905a-00c04fc2d4cf`) shall be validated after decryption to confirm correctness. Multiple PEK entries shall be supported (key rotation).

**Spec reference:** [MS-ADTS] §3.1.1.3.1.6 (Password Encryption Key).

#### FR-9: Password Hash Extraction
NTDSWolf shall decrypt and extract the following password-related attributes for every user and computer object:
- `unicodePwd` -- NT hash (MD4 of UTF-16LE password), 16 bytes.
- `dBCSPwd` -- LM hash (DES-based), 16 bytes. Legacy, often empty.
- `ntPwdHistory` -- Array of historical NT hashes.
- `lmPwdHistory` -- Array of historical LM hashes.

Each encrypted secret shall be decrypted by: (1) selecting the correct PEK by index from the encrypted blob header, (2) deriving a decryption key via HMAC-SHA1(PEK, salt) with 1000 PBKDF2 rounds, (3) decrypting with RC4 or AES-128-CBC depending on the algorithm ID (0x6609 = RC4, 0x6610 = AES).

Hashes shall be output as lowercase hex strings. Empty/missing hashes shall use the well-known empty hash constants (`31d6cfe0d16ae931b73c59d7e0c089c0` for NT, `aad3b435b51404eeaad3b435b51404ee` for LM).

**Spec reference:** [MS-SAMR] §2.2.11.1 (ENCRYPTED_NT_OWF_PASSWORD).

#### FR-10: Supplemental Credentials Parsing
NTDSWolf shall decrypt and parse the `supplementalCredentials` attribute (USER_PROPERTIES structure) to extract:

| Property Name | Content | Output |
|---|---|---|
| `Primary:Kerberos` | Legacy Kerberos keys (DES_CBC_MD5, RC4_HMAC) | Key type + hex key + salt |
| `Primary:Kerberos-Newer-Keys` | Modern Kerberos keys (AES256, AES128, DES, RC4) | Key type + hex key + salt + iteration count |
| `Primary:WDigest` | 29 MD5 digest hashes for HTTP digest auth | Array of hex hashes |
| `Primary:CLEARTEXT` | Plaintext password (UTF-16LE) | Decoded string |
| `Primary:NTLM-Strong-NTOWF` | Random NT hash not derived from password (WS2016+) | Hex hash |

NTDSWolf shall also support Windows Server 2025 Kerberos key types: `AES256-CTS-HMAC-SHA384-192` and `AES128-CTS-HMAC-SHA256-128`.

**Spec reference:** [MS-SAMR] §2.2.10 (USER_PROPERTIES), [MS-KILE] §3.1.1.1 (Kerberos Key Types).

#### FR-11: Trust Password Extraction
NTDSWolf shall decrypt trust authentication data from `trustAuthIncoming` and `trustAuthOutgoing` attributes. For each trust, it shall extract:
- Cleartext trust password (TRUST_AUTH_TYPE_CLEAR).
- NT4OWF hash (TRUST_AUTH_TYPE_NT4OWF).
- Derived Kerberos keys from the trust password using string_to_key with the appropriate domain/trust salt:
  - RC4-HMAC (MD4 of UTF-16LE password)
  - AES128-CTS-HMAC-SHA1-96
  - AES256-CTS-HMAC-SHA1-96

Both current and previous authentication info shall be extracted.

**Spec reference:** [MS-LSAD] §2.2.7.21 (LSAPR_AUTH_INFORMATION), [RFC 3962] (AES String to Key).

#### FR-12: DPAPI Backup Key Extraction
NTDSWolf shall extract DPAPI domain backup keys from `secret` objects in the database. It shall output:
- The RSA private key in PVK format.
- The associated X.509 certificate in PEM format.

**Spec reference:** [MS-BKRP] §3.1.4.1 (BackupKey Remote Protocol).

#### FR-13: LAPS Password Extraction
NTDSWolf shall extract Local Administrator Password Solution credentials:
- **LAPS v1:** `ms-Mcs-AdmPwd` (plaintext string), `ms-Mcs-AdmPwdExpirationTime`.
- **LAPS v2 (Windows LAPS):** `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`, `msLAPS-EncryptedDSRMPassword`, `msLAPS-EncryptedDSRMPasswordHistory`. Decryption requires KDS root keys (`msKds-ProvRootKey` objects) from the database and MS-GKDI group key derivation.
- `msLAPS-PasswordExpirationTime`, `msLAPS-CurrentPasswordVersion`.

**Spec reference:** [MS-GKDI] (Group Key Distribution Protocol), [MS-LAPS] (Local Administrator Password Solution).

#### FR-14: Group Managed Service Account (gMSA) Passwords
NTDSWolf shall extract gMSA managed password metadata from `msDS-ManagedPasswordId` and `msDS-ManagedPasswordPreviousId`. If KDS root keys are available in the database, NTDSWolf shall derive the current managed password using MS-GKDI key derivation.

**Spec reference:** [MS-ADTS] §3.1.1.4.5.28 (msDS-ManagedPassword), [MS-GKDI] §3.1.4.1.

#### FR-15: BitLocker Recovery Key Extraction
NTDSWolf shall extract BitLocker recovery information from `msFVE-RecoveryInformation` objects, including:
- `msFVE-RecoveryPassword` (48-digit numerical recovery password).
- `msFVE-VolumeGuid` (volume identifier).
- `msFVE-KeyPackage` (binary key package blob).

**Spec reference:** [MS-FVE] §2.2 (BitLocker Data Structures).

#### FR-16: Key Credential Extraction (Windows Hello / FIDO2)
NTDSWolf shall parse `msDS-KeyCredentialLink` attributes to extract Windows Hello for Business and FIDO2 key credentials. For each key credential, it shall output:
- Key ID, key type (NGC, FIDO2, STK), key usage.
- RSA or EC public key material.
- Device ID and approximate creation time.
- FIDO2 attestation data (CBOR/COSE format) where present.

**Spec reference:** [MS-ADTS] §2.2.20 (msDS-KeyCredentialLink Attribute), [WebAuthn] §6.5.4 (COSE Key).

#### FR-17: Replication Metadata
NTDSWolf shall parse the `replPropertyMetaData` attribute to extract per-attribute replication metadata including:
- Originating DSA (domain controller that last wrote the attribute).
- Originating USN and local USN.
- Version number (change count).
- Timestamp of last change.

This data is critical for forensic timeline reconstruction.

**Spec reference:** [MS-DRSR] §4.1.10.2.22 (PROPERTY_META_DATA_EXT_VECTOR).

### 2.4 Output

#### FR-18: Output Formats
NTDSWolf shall support the following output formats, selectable via CLI flags:

| Format | Flag | Description |
|---|---|---|
| NDJSON | `--format ndjson` (default) | One JSON object per line, one file per object class. Compatible with `jq`, SIEM ingestion, and streaming parsers. |
| JSON | `--format json` | Pretty-printed JSON array per object class. |
| CSV | `--format csv` | Flat CSV with one row per object. Multi-valued attributes comma-separated within cells. |
| hashcat | `--format hashcat` | NT/LM hashes in hashcat-compatible format (mode 1000 for NT, mode 3000 for LM). |
| John the Ripper | `--format john` | Hashes in John the Ripper format. |
| pwdump | `--format pwdump` | `username:rid:lm-hash:nt-hash:::` format. |

All text output shall be UTF-8 encoded. Binary values shall be lowercase hex-encoded.

#### FR-19: Output Organization
Output shall be organized into a configurable output directory (`--output`, default: `./ntdswolf_output/`). Files shall be named by object class and format:
- `users.ndjson`, `computers.ndjson`, `groups.ndjson`, `trusts.ndjson`, `domains.ndjson`, `gpos.ndjson`, etc.
- `hashes.hashcat`, `hashes.john`, `hashes.pwdump` for credential-specific formats.
- `dpapi_backup_keys/` subdirectory for PVK and PEM files.
- `bitlocker_keys.ndjson` for BitLocker recovery information.
- `kds_root_keys.ndjson` for KDS root key data.

#### FR-20: Selective Extraction
NTDSWolf shall support extracting specific object classes or credential types:
- `--extract users,groups,trusts` -- Only extract specified object classes.
- `--extract hashes` -- Only extract password hashes (hashcat/john/pwdump output).
- `--extract all` -- Extract everything (default).
- `--no-history` -- Exclude password history hashes.
- `--include-deleted` / `--exclude-deleted` -- Control inclusion of deleted objects and deactivated links.

### 2.5 Data Type Handling

#### FR-21: AD Data Type Decoding
NTDSWolf shall correctly decode all Active Directory data types per [MS-ADTS] §3.1.1.2.2:

| AD Syntax | ESE Type | Output Format |
|---|---|---|
| Boolean | Bit | `true` / `false` |
| Integer / Enumeration | Long | Decimal integer |
| LargeInteger | Currency/LongLong | Decimal integer or ISO 8601 timestamp (context-dependent) |
| OctetString | Binary/LongBinary | Lowercase hex or parsed structure (SID, GUID, etc.) |
| Unicode String | Text/LongText | UTF-8 string (decoded from UTF-16LE or CP1252) |
| DN | Text | Full distinguished name string |
| SID | Binary | `S-1-5-21-...` string format |
| GUID/UUID | GUID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` format |
| FILETIME | Currency | ISO 8601 UTC timestamp (`2024-01-15T10:30:45.123456+00:00`) |
| NT Security Descriptor | Binary | SDDL string + raw hex |
| GeneralizedTime | Text | ISO 8601 timestamp |

Encoding detection for strings shall be determined by the `NTLMSSP_NEGOTIATE_UNICODE` flag equivalent in the ESE column metadata (codepage). Every `.decode()` call shall be commented with the flag or spec section driving the encoding choice.

#### FR-22: Enumeration and Flag Decoding
NTDSWolf shall decode well-known enumeration and flag fields into human-readable form:
- `userAccountControl` -- List of flag names (e.g., `["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWD"]`).
- `sAMAccountType` -- Enum name (e.g., `"SAM_USER_OBJECT"`).
- `groupType` -- List of flag names (e.g., `["GLOBAL_GROUP", "SECURITY_ENABLED"]`).
- `trustType` -- Enum name.
- `trustDirection` -- Enum name.
- `trustAttributes` -- List of flag names.
- `instanceType` -- List of flag names.
- `systemFlags` -- List of flag names.
- `msDS-SupportedEncryptionTypes` -- List of encryption type names.

Raw numeric values shall always be included alongside decoded names (e.g., `"userAccountControl": {"value": 66048, "flags": ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWD"]}`).

## 3. Non-Functional Requirements

### 3.1 Performance

#### NFR-1: Streaming Processing
NTDSWolf shall process the datatable, link_table, and sd_table as streams. Peak memory usage shall remain bounded regardless of database size. The bound shall be configurable but default to a reasonable limit (e.g., 512MB for caches and buffers).

#### NFR-2: Parallel Processing
NTDSWolf shall support parallel object processing via configurable worker count (`--workers N`, default: CPU count). Schema building and PEK decryption are sequential prerequisites; object extraction and output shall be parallelized.

#### NFR-3: Progress Reporting
NTDSWolf shall display progress during long-running operations:
- Object count and throughput (objects/sec) during extraction.
- Current phase (schema loading, PEK decryption, object extraction, link resolution).
- Estimated time remaining where feasible.
- Progress output shall go to stderr to keep stdout clean for piping.

### 3.2 Reliability

#### NFR-4: Error Handling
NTDSWolf shall not crash on corrupted, truncated, or malformed records. Individual record failures shall be logged with the DNT and error details, and processing shall continue. A summary of errors shall be printed at completion.

No bare `except:` clauses. All exception handlers shall catch specific exception types and log the error with context.

#### NFR-5: Validation
NTDSWolf shall validate:
- ESE database magic number and version before processing.
- PEK authenticator GUID after decryption to confirm the boot key is correct.
- Decrypted hash lengths (16 bytes for NT/LM) before output.
- Output format integrity (valid JSON, valid CSV).

If PEK validation fails (wrong boot key), NTDSWolf shall emit a clear error message and exit with a non-zero status code rather than producing garbage output.

### 3.3 Code Quality

#### NFR-6: Python Standards
- Target: Python 3.14.
- `from __future__ import annotations` in every module.
- Full type annotations on all functions, parameters, return types, and class attributes.
- Google-style docstrings with spec references for protocol code.
- `StrEnum` for string constants, `IntEnum`/`IntFlag` for numeric flags/enumerations.
- `@dataclass(frozen=True)` for immutable data records.

#### NFR-7: Linting and Type Checking
- Ruff with `select = ["ALL"]`, `line-length = 320`, `target-version = "py314"`.
- ty with `all = "error"`, `error-on-warning = true`, `python-version = "3.14"`.
- Zero warnings, zero errors on every commit.

#### NFR-8: Testing
- Unit tests for all decryption routines, data type decoders, and schema resolution.
- Integration tests using known-good NTDS.dit samples with verified output.
- Tests run via `uv run pytest`.
- Test coverage target: 90%+ for core parsing and decryption modules.

#### NFR-9: Documentation
- Module-level docstrings explaining role and key design decisions.
- Every function gets a docstring explaining WHY it exists.
- Protocol code references spec sections (e.g., "Per [MS-SAMR] §2.2.11.1").
- Non-obvious constants commented with spec source and meaning.

### 3.4 Packaging and Distribution

#### NFR-10: Packaging
- Managed with `uv`. No version pins on dependencies.
- Single `pyproject.toml` with `[project.scripts]` entry point.
- Installable via `uv tool install ntdswolf` or `pipx install ntdswolf`.
- CLI entry point: `ntdswolf`.

## 4. Dependencies

### 4.1 Required Dependencies

| Package | Purpose |
|---|---|
| `dissect.database` | ESE database parsing, NTDS object model, schema resolution, PEK decryption |
| `pycryptodome` | AES, DES, RC4, MD4, MD5, HMAC, PBKDF2 for credential decryption |
| `cryptography` | ECDH, KBKDF, ConcatKDF for GKDI/LAPS v2 key derivation; X.509 certificate handling |
| `pyasn1-modules` | ASN.1 parsing for LAPS v2 CMS encrypted blobs |

### 4.2 Optional Dependencies

| Package | Purpose |
|---|---|
| `rich` | Terminal progress bars, colored output, tables (graceful degradation if absent) |

### 4.3 Explicitly Excluded Dependencies

| Package | Reason |
|---|---|
| `impacket` | Heavy, poorly typed, many transitive dependencies. NTDSWolf shall implement needed structures directly with spec references. |
| `ldap3` | Only needed for LDAP client operations. SID/UUID formatting done in-house. |
| `six` | Python 2 compatibility shim. Not needed for Python 3.14. |

## 5. CLI Interface

### 5.1 Command Structure

```
ntdswolf <ntds.dit> [--system <SYSTEM>] [--bootkey <hex>] [OPTIONS]
```

### 5.2 Arguments and Flags

| Argument | Type | Default | Description |
|---|---|---|---|
| `ntds.dit` | positional | required | Path to the NTDS.dit database file. |
| `--system` | path | auto-detect | Path to SYSTEM registry hive for boot key extraction. |
| `--bootkey` | hex string | none | Raw 32-character hex boot key. Overrides `--system`. |
| `--output` / `-o` | path | `./ntdswolf_output/` | Output directory. Created if it doesn't exist. |
| `--format` / `-f` | choice | `ndjson` | Output format: `ndjson`, `json`, `csv`, `hashcat`, `john`, `pwdump`. |
| `--extract` / `-e` | comma-list | `all` | Object classes or categories to extract: `users`, `computers`, `groups`, `trusts`, `domains`, `gpos`, `gmsas`, `bitlocker`, `dpapi`, `kds`, `hashes`, `all`. |
| `--workers` / `-w` | int | CPU count | Number of parallel workers for object extraction. |
| `--no-history` | flag | false | Exclude password history hashes from output. |
| `--include-deleted` | flag | true | Include deleted objects and deactivated links. |
| `--exclude-deleted` | flag | false | Exclude deleted objects and deactivated links. |
| `--naming` | choice | `ldap` | Attribute naming mode: `ldap` (lowercase) or `cn` (Common-Name). |
| `--raw` | flag | false | Include raw encrypted values alongside decrypted values (prefixed with `RAW_`). |
| `--verbose` / `-v` | flag | false | Verbose logging to stderr. |
| `--quiet` / `-q` | flag | false | Suppress all non-error output. |
| `--version` | flag | -- | Print version and exit. |

### 5.3 Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error (I/O, invalid arguments) |
| 2 | Invalid or unreadable NTDS.dit file |
| 3 | Boot key validation failed (wrong SYSTEM hive or boot key) |
| 4 | Partial extraction (some objects failed, results are incomplete) |

## 6. Compatibility and Extensibility

### 6.1 Windows Server Version Support
NTDSWolf shall support NTDS.dit files from:
- Windows Server 2008 / 2008 R2
- Windows Server 2012 / 2012 R2
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows Server 2025

Each version may use different PEK encryption, Kerberos key types, or attribute schemas. NTDSWolf shall handle all known variations.

### 6.2 Future Extensibility
The architecture shall accommodate future additions without major refactoring:
- ADAM/AD LDS database support.
- Additional output formats (e.g., Bloodhound JSON ingest).
- Custom attribute decoders via plugin or configuration.
- Additional credential types as Microsoft introduces them.

## 7. Microsoft Specification References

The following Microsoft specifications are authoritative for NTDSWolf's implementation:

| Spec | Title | Relevance |
|---|---|---|
| [MS-ESENT] | Extensible Storage Engine File Format | ESE database format, page/record structure |
| [MS-ADTS] | Active Directory Technical Specification | Schema, object model, replication, naming |
| [MS-SAMR] | Security Account Manager Remote Protocol | Password hash structures, USER_PROPERTIES, supplementalCredentials |
| [MS-DRSR] | Directory Replication Service Remote Protocol | OID prefix mapping, replication metadata |
| [MS-DTYP] | Windows Data Types | SID, GUID, SECURITY_DESCRIPTOR, FILETIME |
| [MS-LSAD] | Local Security Authority Domain Policy | Trust authentication structures |
| [MS-KILE] | Kerberos Protocol Extensions | Kerberos key types, encryption types |
| [MS-GKDI] | Group Key Distribution Protocol | KDS root keys, gMSA/LAPS v2 key derivation |
| [MS-BKRP] | BackupKey Remote Protocol | DPAPI backup key structure |
| [MS-FVE] | BitLocker Drive Encryption | Recovery key structures |
| [MS-LAPS] | Local Administrator Password Solution | LAPS v1/v2 attribute formats |
| [RFC 3962] | AES Encryption for Kerberos 5 | AES string-to-key for trust password derivation |
