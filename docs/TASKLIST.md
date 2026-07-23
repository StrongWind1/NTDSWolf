# NTDSWolf -- Implementation Tasklist

> **Superseded (2026-06-01).** This is the original from-scratch build plan. The implementation diverged from it and is now feature-complete: all `crypto/` and `decoders/` code is wired into the pipeline, output is byte-identical to secretsdump, and the `_unmapped` passthrough ensures nothing is dropped. See the [CHANGELOG](../CHANGELOG.md) for the current state.

**Version:** 0.1.0
**Date:** 2025-05-22
**Status:** Draft
**Upstream:** [REQUIREMENTS.md](REQUIREMENTS.md) → [DESIGN.md](DESIGN.md) → [ARCHITECTURE.md](ARCHITECTURE.md)

This document enumerates every implementation task required to build NTDSWolf from the design and architecture documents. Tasks are ordered by dependency: earlier tasks produce artifacts that later tasks consume. Within each phase, tasks are listed in implementation order.

**Notation:**
- `[REQ FR-N]` = traces to a functional requirement in REQUIREMENTS.md
- `[DES §N]` = traces to a design section in DESIGN.md
- `[ARCH §N]` = traces to an architecture section in ARCHITECTURE.md
- `[SPEC MS-XXX]` = requires reading a Microsoft specification

---

## Phase 0: Project Scaffolding

Everything needed before any application code is written. Sets up the directory structure, build tooling, linting configuration, and CI pipeline.

### T-0.1: Create the src/ layout directory structure

Create every directory and `__init__.py` file defined in [ARCH §8]. This establishes the physical package layout that all subsequent tasks write into.

**Files to create:**
- `src/ntdswolf/__init__.py` -- Package root. Define `__version__ = "0.1.0"`.
- `src/ntdswolf/__main__.py` -- Entry point stub: `from ntdswolf.cli.app import app; app()`.
- `src/ntdswolf/constants.py` -- Empty module with module docstring placeholder.
- `src/ntdswolf/cli/__init__.py`
- `src/ntdswolf/cli/app.py` -- Empty module with module docstring placeholder.
- `src/ntdswolf/cli/callbacks.py` -- Empty module.
- `src/ntdswolf/core/__init__.py`
- `src/ntdswolf/core/database.py`
- `src/ntdswolf/core/schema.py`
- `src/ntdswolf/core/pipeline.py`
- `src/ntdswolf/core/links.py`
- `src/ntdswolf/core/dn_cache.py`
- `src/ntdswolf/core/workers.py`
- `src/ntdswolf/crypto/__init__.py`
- `src/ntdswolf/crypto/bootkey.py`
- `src/ntdswolf/crypto/pek.py`
- `src/ntdswolf/crypto/hashes.py`
- `src/ntdswolf/crypto/supplemental.py`
- `src/ntdswolf/crypto/trusts.py`
- `src/ntdswolf/crypto/dpapi.py`
- `src/ntdswolf/crypto/laps.py`
- `src/ntdswolf/crypto/gkdi.py`
- `src/ntdswolf/crypto/keycredential.py`
- `src/ntdswolf/crypto/structures.py`
- `src/ntdswolf/decoders/__init__.py`
- `src/ntdswolf/decoders/registry.py`
- `src/ntdswolf/decoders/base.py`
- `src/ntdswolf/decoders/users.py`
- `src/ntdswolf/decoders/groups.py`
- `src/ntdswolf/decoders/trusts.py`
- `src/ntdswolf/decoders/domains.py`
- `src/ntdswolf/decoders/gpo.py`
- `src/ntdswolf/decoders/gmsa.py`
- `src/ntdswolf/decoders/bitlocker.py`
- `src/ntdswolf/decoders/kds.py`
- `src/ntdswolf/decoders/generic.py`
- `src/ntdswolf/output/__init__.py`
- `src/ntdswolf/output/base.py`
- `src/ntdswolf/output/ndjson.py`
- `src/ntdswolf/output/json_.py`
- `src/ntdswolf/output/csv_.py`
- `src/ntdswolf/output/hashcat.py`
- `src/ntdswolf/output/john.py`
- `src/ntdswolf/output/pwdump.py`
- `src/ntdswolf/models/__init__.py`
- `src/ntdswolf/models/objects.py`
- `src/ntdswolf/models/credentials.py`
- `src/ntdswolf/models/flags.py`
- `src/ntdswolf/models/links.py`
- `src/ntdswolf/models/metadata.py`
- `tests/__init__.py`
- `tests/conftest.py`
- `tests/fixtures/` (empty directory with .gitkeep)

**Acceptance:** `uv run python -c "import ntdswolf"` succeeds. All `__init__.py` files exist. Directory tree matches [ARCH §8].

### T-0.2: Configure pyproject.toml

Replace the placeholder `pyproject.toml` with the full project configuration from [ARCH §9.1]. This includes:

- `[project]` section: name, version, description, requires-python >= 3.14, all dependencies (dissect.database, pycryptodome, cryptography, pyasn1-modules, typer, rich).
- `[project.scripts]`: `ntdswolf = "ntdswolf.cli.app:app"`.
- `[dependency-groups]`: dev (pytest, pytest-cov, ruff), docs (mkdocs, mkdocs-material).
- `[tool.ruff]`: target-version py314, line-length 320, src = ["src"], select ALL, ignore COM812/ISC001/D203/D213, per-file-ignores for tests.
- `[tool.ty]`: python-version 3.14, all = error, per-file-ignores for tests set to ignore.
- `[tool.pytest.ini_options]`: testpaths = ["tests"].
- `[build-system]`: hatchling or setuptools backend.

**Files to modify:** `pyproject.toml`.
**Files to delete:** `main.py` (replaced by `src/ntdswolf/__main__.py`), `.python-version` (update to 3.14 if not already).

**Acceptance:** `uv sync` installs all dependencies. `uv run ruff check .` runs (may have errors on empty files -- that's fine). `uv run ntdswolf --help` shows a placeholder help message. `uv run pytest` discovers the tests directory.

### T-0.3: Configure CI pipeline

Create the GitHub Actions CI workflow defined in [ARCH §9.2].

**Files to create:**
- `.github/workflows/ci.yml` -- Jobs: lint (ruff check + ruff format --check), typecheck (ty), test (pytest --cov), build (uv build --wheel). Build depends on all three. Pin actions by SHA. Set timeout-minutes on each job. Use astral-sh/setup-uv with cache. Set concurrency with cancel-in-progress for PRs. Use persist-credentials: false on checkout. set -euo pipefail in all run steps.

**Acceptance:** CI workflow YAML is valid. `act` or manual push triggers all four jobs.

### T-0.4: Configure pre-commit hooks

Set up pre-commit configuration per the project's tooling standards.

**Files to create:**
- `.pre-commit-config.yaml` -- Hooks: ruff (check --fix + format), trailing-whitespace, end-of-file-fixer, check-yaml, check-toml.

**Acceptance:** `uv run pre-commit run --all-files` executes all hooks.

### T-0.5: Create Dependabot configuration

**Files to create:**
- `.github/dependabot.yml` -- Enable for github-actions ecosystem, weekly schedule.

### T-0.6: Create GitHub templates

**Files to create:**
- `.github/pull_request_template.md` -- Summary, Changes, Testing checklist (ruff, ty, pytest), Notes.
- `.github/ISSUE_TEMPLATE/bug_report.yml` -- Command, output, expected behavior, environment.
- `.github/ISSUE_TEMPLATE/feature_request.yml` -- Problem, proposed solution, alternatives.

---

## Phase 1: Models Layer

The models layer is the shared vocabulary used by every other layer. It has zero internal dependencies beyond `constants.py`. Every subsequent phase imports from here.

### T-1.1: Implement constants.py

Define all well-known constants, GUIDs, and spec-derived values used throughout the codebase. This module imports only from stdlib.

**Contents:**
- `PEK_AUTHENTICATOR_GUID`: `"4881d956-91ec-11d1-905a-00c04fc2d4cf"` -- Used to validate PEK decryption. [SPEC MS-ADTS §3.1.1.3.1.6]
- `EMPTY_NT_HASH`: `"31d6cfe0d16ae931b73c59d7e0c089c0"` -- MD4 of empty UTF-16LE string. [SPEC MS-SAMR]
- `EMPTY_LM_HASH`: `"aad3b435b51404eeaad3b435b51404ee"` -- DES of empty password. [SPEC MS-SAMR]
- `NEVER_EXPIRES_FILETIME`: `0x7FFFFFFFFFFFFFFF` -- accountExpires "never" sentinel. [SPEC MS-ADTS]
- `NEVER_EXPIRES_FILETIME_ALT`: `9223372032559808511` -- alternate "never" sentinel.
- `ENC_ALGORITHM_RC4`: `0x6609` -- RC4 encryption algorithm ID. [SPEC MS-SAMR §2.2.11.1]
- `ENC_ALGORITHM_AES`: `0x6610` -- AES encryption algorithm ID. [SPEC MS-SAMR §2.2.11.1]
- `PEK_VERSION_RC4`: `0x02` -- Pre-2012R2 PEK version. [SPEC MS-ADTS]
- `PEK_VERSION_AES`: `0x03` -- 2016+ PEK version. [SPEC MS-ADTS]
- `USER_PROPERTIES_SIGNATURE`: `0x50` -- 'P' byte validating USER_PROPERTIES. [SPEC MS-SAMR §2.2.10]
- `BOOTKEY_PERMUTATION_TABLE`: The fixed 16-byte permutation for unscrambling the boot key from SYSTEM hive class names.
- `BOOTKEY_LSA_KEYS`: `("JD", "Skew1", "GBG", "Data")` -- Registry key names under `Control\Lsa`.
- `TRUST_AUTH_TYPE_CLEAR`: `1` -- [SPEC MS-LSAD §2.2.7.21]
- `TRUST_AUTH_TYPE_NT4OWF`: `2` -- [SPEC MS-LSAD §2.2.7.21]
- `TRUST_AUTH_TYPE_VERSION`: `3` -- [SPEC MS-LSAD §2.2.7.21]
- `KERBEROS_KEY_TYPE_*` constants for all supported Kerberos encryption types. [SPEC MS-KILE]
- `WELL_KNOWN_SIDS`: Dict of well-known SID strings to names (S-1-5-21-*-500 = Administrator, etc.).

**Acceptance:** `uv run ruff check src/ntdswolf/constants.py` clean. `uv run ty check` clean. Module importable.

### T-1.2: Implement models/flags.py

Define all IntFlag, IntEnum, and StrEnum types for AD enumeration and flag fields. Every definition must include a docstring with the Microsoft spec section reference.

**Contents (per [DES §3.3] and [REQ FR-22]):**
- `UserAccountControl(IntFlag)` -- All 21 flags from [MS-ADTS] §2.2.16, including PARTIAL_SECRETS_ACCOUNT.
- `GroupType(IntFlag)` -- GLOBAL_GROUP, DOMAIN_LOCAL_GROUP, UNIVERSAL_GROUP, SECURITY_ENABLED. [MS-ADTS] §2.2.12.
- `SAMAccountType(IntEnum)` -- Domain, SecurityGroup, DistributionGroup, Alias, NonSecurityAlias, User, Computer, Trust, AppBasicGroup, AppQueryGroup. [MS-SAMR] §2.2.6.
- `TrustType(IntEnum)` -- DOWNLEVEL, UPLEVEL, MIT, DCE, AAD. [MS-ADTS] §6.1.6.9.1.
- `TrustDirection(IntFlag)` -- DISABLED, INBOUND, OUTBOUND, BIDIRECTIONAL. [MS-ADTS] §6.1.6.9.1.
- `TrustAttributes(IntFlag)` -- All flags including FOREST_TRANSITIVE, CROSS_ORGANIZATION, USES_RC4, USES_AES_KEYS, etc. [MS-ADTS] §6.1.6.7.9.
- `InstanceType(IntFlag)` -- HEAD, REPLICA, ABOVE, SUBREF, WRITE, REMOVE. [MS-ADTS].
- `SystemFlags(IntFlag)` -- All system flag bits. [MS-ADTS].
- `SupportedEncryptionTypes(IntFlag)` -- DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC, AES128, AES256, AES256_SK, FAST, COMPOUND_IDENTITY, CLAIMS, RESOURCE_SID_COMPRESSION_DISABLED. [MS-KILE].
- `PwdProperties(IntFlag)` -- DOMAIN_PASSWORD_COMPLEX, DOMAIN_PASSWORD_NO_ANON_CHANGE, etc. [MS-ADTS].
- `KerberosKeyType(IntEnum)` -- DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC, AES128_CTS, AES256_CTS, AES256_SHA384, AES128_SHA256. [MS-KILE] §3.1.1.1.
- `KeyCredentialType(StrEnum)` -- NGC, FIDO2, STK. [MS-ADTS] §2.2.20.
- Helper function `decode_flags(value: int, flag_class: type[IntFlag]) -> dict` that returns `{"value": int, "flags": list[str]}` per the JSON output contract [ARCH §5.3].

**Acceptance:** All enums importable. `decode_flags(66048, UserAccountControl)` returns `{"value": 66048, "flags": ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWD"]}`. Unit tests in `tests/test_flags.py` covering every enum with at least one known value.

### T-1.3: Implement models/credentials.py

Define frozen dataclass types for all credential material. These are the output of the crypto layer and consumed by decoders and output formatters.

**Contents (per [DES §3.3]):**
- `NTHash` -- frozen dataclass with `hash: bytes` (16 bytes) and `hex() -> str` method.
- `KerberosKey` -- frozen dataclass: `key_type: KerberosKeyType`, `key_value: bytes`, `salt: str`, `iteration_count: int`.
- `UserCredentials` -- frozen dataclass aggregating: `nt_hash`, `lm_hash`, `nt_history`, `lm_history`, `kerberos_keys`, `wdigest_hashes`, `cleartext_password`, `ntlm_strong_ntowf`.
- `TrustCredentials` -- frozen dataclass: `cleartext_password`, `nt4owf_hash`, `rc4_hmac_key`, `aes128_key`, `aes256_key`, `previous: TrustCredentials | None`.
- `LAPSPassword` -- frozen dataclass: `version: int`, `password: str`, `expiration: datetime | None`, `account_name: str | None`.
- `DPAPIBackupKey` -- frozen dataclass: `key_id: str`, `pvk_data: bytes`, `certificate_pem: str | None`, `creation_time: datetime | None`.
- `BitLockerRecoveryKey` -- frozen dataclass: `recovery_password: str`, `volume_guid: str`, `key_package: bytes | None`.
- `KeyCredential` -- frozen dataclass: `key_id: str`, `key_type: KeyCredentialType`, `key_usage: str`, `public_key: bytes`, `device_id: str | None`, `creation_time: datetime | None`.
- `GMSAPassword` -- frozen dataclass: `managed_password_id: bytes`, `managed_password: bytes | None`, `previous_password_id: bytes | None`.
- `to_dict()` method on each dataclass that produces the JSON-schema-compliant dict defined in [ARCH §6].

**Acceptance:** All types importable. Frozen (immutable). `to_dict()` output matches [ARCH §6.2] credentials schema. Unit tests for each type's construction and serialization.

### T-1.4: Implement models/links.py

Define dataclass types for link table records and resolved links.

**Contents (per [ARCH §4.2]):**
- `LinkRecord` -- frozen dataclass: `link_dnt: int`, `backlink_dnt: int`, `link_base: int`, `link_deltime: datetime | None`, `link_deactivetime: datetime | None`, `link_data: bytes | None`.
- `ResolvedLink` -- frozen dataclass: `attribute_name: str`, `target_dnt: int`, `target_dn: str`, `is_deleted: bool`, `deleted_time: datetime | None`, `is_deactivated: bool`, `deactivated_time: datetime | None`, `link_data: bytes | None`.

**Acceptance:** Importable, frozen, type-annotated.

### T-1.5: Implement models/metadata.py

Define dataclass types for replication metadata and security descriptors.

**Contents (per [REQ FR-17] and [REQ FR-7]):**
- `ReplicationMetadataEntry` -- frozen dataclass: `attribute_name: str`, `version: int`, `last_originating_change: datetime`, `originating_dsa: str`, `originating_usn: int`, `local_usn: int`.
- `SecurityDescriptorInfo` -- frozen dataclass: `sd_id: int`, `sddl: str`, `raw_hex: str`.

**Acceptance:** Importable, frozen, type-annotated.

### T-1.6: Implement models/objects.py

Define frozen dataclass types for all AD object models. These are the primary output types used by decoders and consumed by output writers.

**Contents (per [DES §3.3] and [ARCH §6]):**
- `ADObject` -- Base: `dn`, `dnt`, `object_class`, `object_guid`, `object_sid`, `when_created`, `when_changed`, `is_deleted`, `instance_type`, `security_descriptor`, `raw_attributes`.
- `ADUser` -- Extends ADObject: `sam_account_name`, `user_principal_name`, `display_name`, `user_account_control`, `sam_account_type`, `admin_count`, `pwd_last_set`, `last_logon_timestamp`, `last_logon`, `account_expires`, `bad_password_time`, `bad_pwd_count`, `lockout_time`, `description`, `mail`, `title`, `department`, `manager`, `member_of`, `sid_history`, `credentials`, `supported_encryption_types`, `replication_metadata`, `key_credentials`.
- `ADComputer` -- Extends ADObject: `sam_account_name`, `dns_host_name`, `operating_system`, `operating_system_version`, `user_account_control`, `credentials`, `laps_password`, `allowed_to_delegate_to`, `allowed_to_act_on_behalf`, `member_of`, `supported_encryption_types`.
- `ADGroup` -- Extends ADObject: `sam_account_name`, `group_type`, `members`, `member_of`, `admin_count`, `description`.
- `ADTrust` -- Extends ADObject: `trust_partner`, `trust_type`, `trust_direction`, `trust_attributes`, `flat_name`, `security_identifier`, `trust_credentials`, `supported_encryption_types`.
- `ADDomain` -- Extends ADObject: `domain_sid`, `functional_level`, `min_pwd_length`, `max_pwd_age`, `min_pwd_age`, `lockout_threshold`, `lockout_duration`, `lockout_observation_window`, `pwd_properties`, `pwd_history_length`.
- `ADGPO` -- Extends ADObject: `display_name`, `gpc_file_sys_path`, `version_number`, `gpc_machine_extensions`, `gpc_user_extensions`.
- `ADGMSA` -- Extends ADObject: `sam_account_name`, `gmsa_password`, `managed_password_interval`, `group_msa_membership`.
- `ADKDSRootKey` -- Extends ADObject: `root_key_data`, `create_time`, `use_start_time`, `kdf_param`, `secret_agreement_param`.
- `ADBitLockerRecovery` -- Extends ADObject: `recovery_key`.
- `ADGenericObject` -- Extends ADObject: no extra fields; all data in `raw_attributes`.
- `to_dict()` method on each that produces the JSON output defined in [ARCH §6]. Each `to_dict()` must add the `_object_class` and `_dnt` synthetic fields, serialize flag fields via `decode_flags()`, and serialize credential fields via their own `to_dict()`.

**Acceptance:** All types importable. `to_dict()` output for ADUser matches [ARCH §6.2] exactly. `to_dict()` output for ADGroup matches [ARCH §6.4]. Unit tests validating serialization of each type.

---

## Phase 2: Crypto Layer

The crypto layer implements all decryption and binary structure parsing. It depends only on `models/` and `constants.py`. No imports from `core/`, `decoders/`, `cli/`, or `output/`.

### T-2.1: Implement crypto/structures.py

Define all binary wire format structures using `dissect.cstruct`. Each structure must reference the spec section it implements.

**Contents (per [DES §3.3]):**
- `ENC_SECRET` -- [MS-SAMR] §2.2.11.1: AlgorithmId (WORD), Flags (WORD), PekIndex (DWORD), Salt (16 bytes).
- `USER_PROPERTIES` -- [MS-SAMR] §2.2.10: Reserved1 (DWORD), Length (DWORD), Reserved2 (WORD), Reserved3 (WORD), Reserved4 (96 bytes), PropertySignature (WORD), PropertyCount (WORD).
- `USER_PROPERTY` -- [MS-SAMR] §2.2.10: NameLength (WORD), ValueLength (WORD), Reserved (WORD).
- `KERB_STORED_CREDENTIAL` -- [MS-KILE]: Revision (WORD), Flags (WORD), CredentialCount (WORD), OldCredentialCount (WORD), DefaultSaltLength (WORD), DefaultSaltMaximumLength (WORD), DefaultSaltOffset (DWORD).
- `KERB_STORED_CREDENTIAL_NEW` -- [MS-KILE]: Same as above plus ServiceCredentialCount, OldServiceCredentialCount, DefaultIterationCount.
- `KERB_KEY_DATA` -- [MS-KILE]: Reserved1 (WORD), Reserved2 (WORD), Reserved3 (DWORD), KeyType (DWORD), KeyLength (DWORD), KeyOffset (DWORD).
- `KERB_KEY_DATA_NEW` -- [MS-KILE]: Same as above plus IterationCount (DWORD).
- `PEK_LIST_HEADER` -- [MS-ADTS]: Version (DWORD), Flags (DWORD), Salt (16 bytes).
- `PEK_KEY` -- [MS-ADTS]: PekId (DWORD), PekKey (16 bytes).
- `LSAPR_AUTH_INFORMATION` -- [MS-LSAD] §2.2.7.21: LastUpdateTime (8 bytes), AuthType (DWORD), AuthInfoLength (DWORD).
- `REPL_PROPERTY_META_DATA` -- [MS-DRSR] §4.1.10.2.22: dwVersion (DWORD), timeChanged (8 bytes), uuidDsaOriginating (16 bytes), usnOriginating (8 bytes), usnProperty (8 bytes), attrType (DWORD).
- `REPL_PROPERTY_META_DATA_BLOB` -- [MS-DRSR]: dwVersion (DWORD), dwReserved (DWORD), cEntries (DWORD), dwReserved2 (DWORD).
- `DPAPI_DOMAIN_RSA_KEY` -- [MS-BKRP] §3.1.4.1: Version (DWORD), Magic (DWORD), BitLength (DWORD), etc.
- `KEY_CREDENTIAL_ENTRY` -- [MS-ADTS] §2.2.20: Version, KeyID, etc.
- `LAPS_ENCRYPTED_PASSWORD` -- [MS-LAPS]: header structure for LAPS v2 encrypted blobs.
- `KDS_ROOT_KEY` -- [MS-GKDI]: structure for msKds-ProvRootKey data.

**Acceptance:** All structures parse correctly from known hex blobs. Unit tests in `tests/test_structures.py` validating parsing of each structure against reference data from ntdissector/DSInternals test vectors.

### T-2.2: Implement crypto/bootkey.py

Extract the boot key (SYSKEY) from a SYSTEM registry hive file, or accept a raw hex string. Implement the auto-detect search logic.

**Contents (per [DES §2.3] and [REQ FR-2]):**
- `extract_bootkey_from_hive(system_hive_path: Path) -> bytes` -- Opens the SYSTEM hive with `dissect.regf`, reads class names from `ControlSet00X\Control\Lsa\{JD, Skew1, GBG, Data}`, concatenates hex digits, applies the permutation table, returns 16-byte boot key. Must handle multiple ControlSet entries and find the current one. Per [SPEC MS-GKDI].
- `parse_bootkey_hex(hex_string: str) -> bytes` -- Validates 32-char hex string, returns 16 bytes. Raises `ValueError` on invalid input.
- `auto_detect_system_hive(ntds_dir: Path) -> Path | None` -- Searches for a file named `SYSTEM` (case-insensitive) in: (a) same directory as ntds.dit, (b) parent directory, (c) `../registry/` relative path. Returns first match or None.
- `resolve_bootkey(bootkey_hex: str | None, system_path: Path | None, ntds_dir: Path) -> bytes | None` -- Priority chain: hex > system > auto-detect > None. Logs the source used.

**Dependencies:** `dissect.regf` (part of dissect ecosystem, should come as transitive dependency of dissect.database or added as a direct dependency).

**Acceptance:** Unit tests with a known SYSTEM hive extract the correct boot key. `parse_bootkey_hex` validates correctly. Auto-detect finds SYSTEM files in expected locations. Tests in `tests/test_bootkey.py`.

### T-2.3: Implement crypto/pek.py

Decrypt the Password Encryption Key (PEK) list from the domain object's `pekList` attribute. Wrap `dissect.database.ese.ntds.pek` if it provides sufficient functionality, or reimplement if needed.

**Contents (per [DES §2.3] and [REQ FR-8]):**
- `PEKList` -- Frozen dataclass holding decrypted PEK keys: `keys: dict[int, bytes]` mapping PEK ID to 16-byte key. Must be picklable for transfer to worker processes.
- `decrypt_pek_list(pek_list_encrypted: bytes, bootkey: bytes) -> PEKList` -- Decrypts the PEK list blob. Handles both version 0x02 (RC4 with MD5/HMAC, 1000 iterations) and version 0x03 (AES-128-CBC). Validates the authenticator GUID `4881d956-91ec-11d1-905a-00c04fc2d4cf`. Raises `BootKeyError` on validation failure.
- `pek_decrypt_secret(encrypted_blob: bytes, pek_list: PEKList) -> bytes` -- Generic PEK decryption: parses ENC_SECRET header, selects PEK by index, derives key via HMAC-SHA1(PEK, salt) with 1000 rounds, decrypts with RC4 (0x6609) or AES-128-CBC (0x6610). Returns decrypted plaintext.
- `BootKeyError(Exception)` -- Raised when PEK authenticator GUID doesn't match.

**Acceptance:** Decrypts known PEK list blobs from test fixtures. Validates authenticator. Raises `BootKeyError` on wrong boot key. Tests in `tests/test_pek.py`.

### T-2.4: Implement crypto/hashes.py

Decrypt NT and LM password hashes and hash history arrays.

**Contents (per [REQ FR-9]):**
- `decrypt_nt_hash(encrypted: bytes, pek_list: PEKList) -> NTHash | None` -- PEK-decrypts the unicodePwd attribute, validates 16-byte length, returns NTHash. Returns None if attribute is empty/missing.
- `decrypt_lm_hash(encrypted: bytes, pek_list: PEKList) -> NTHash | None` -- Same for dBCSPwd.
- `decrypt_hash_history(encrypted: bytes, pek_list: PEKList) -> list[NTHash]` -- PEK-decrypts ntPwdHistory or lmPwdHistory. Parses the array of 16-byte hashes from the decrypted blob (first 4 bytes = count, then count × 16 bytes of hashes).
- All functions log errors and return None/empty list on failure, never raise.

**Acceptance:** Decrypts known hash blobs from test fixtures. History parsing returns correct count and hashes. Tests in `tests/test_hashes.py`.

### T-2.5: Implement crypto/supplemental.py

Parse the decrypted supplementalCredentials (USER_PROPERTIES) blob to extract all credential types.

**Contents (per [REQ FR-10] and [DES §4.3]):**
- `parse_supplemental_credentials(encrypted: bytes, pek_list: PEKList) -> SupplementalCredentials` -- PEK-decrypts, then parses USER_PROPERTIES. Validates PropertySignature == 0x50. Iterates properties by name.
- `_parse_kerberos_newer_keys(value: bytes) -> list[KerberosKey]` -- Parses KERB_STORED_CREDENTIAL_NEW. Extracts AES256, AES128, DES, RC4 keys with salt and iteration count. Must support Windows Server 2025 key types (AES256-SHA384, AES128-SHA256).
- `_parse_kerberos_legacy(value: bytes) -> list[KerberosKey]` -- Parses KERB_STORED_CREDENTIAL (revision 3). Extracts DES + RC4 keys.
- `_parse_wdigest(value: bytes) -> list[bytes]` -- Reads 29 × 16-byte MD5 hashes. First 4 bytes reserved, then 4 bytes = version (must be 1), then 4 bytes = count (must be 29).
- `_parse_cleartext(value: bytes) -> str` -- Decodes UTF-16LE password string.
- `_parse_ntlm_strong_ntowf(value: bytes) -> NTHash` -- Reads 16-byte random hash.
- Internal `SupplementalCredentials` dataclass aggregating all parsed properties.

**Acceptance:** Parses known supplementalCredentials blobs. All five property types extracted correctly. WS2025 key types handled. Tests in `tests/test_supplemental.py`.

### T-2.6: Implement crypto/trusts.py

Decrypt trust authentication data and derive Kerberos keys from trust passwords.

**Contents (per [REQ FR-11] and [DES §4.4]):**
- `decrypt_trust_auth(encrypted: bytes, pek_list: PEKList, domain_name: str, trust_partner: str) -> TrustCredentials` -- PEK-decrypts, parses LSAPR_AUTH_INFORMATION array, extracts current and previous auth info.
- `_parse_auth_info_array(data: bytes) -> list[AuthInfoEntry]` -- Parses the array of LSAPR_AUTH_INFORMATION entries with AuthType, AuthInfoLength, and data.
- `_derive_trust_keys(password_bytes: bytes, domain: str, partner: str) -> tuple[bytes, bytes, bytes]` -- Derives RC4 key (MD4 of UTF-16LE password), AES128 key (string_to_key per [RFC 3962]), AES256 key (string_to_key per [RFC 3962]). Salt = `DOMAIN.COMkrbtgtTRUSTED.COM` (uppercase realm names).
- `string_to_key(password: str, salt: str, enctype: int) -> bytes` -- Implements Kerberos string-to-key for AES128 and AES256 per [RFC 3962]. Uses PBKDF2-HMAC-SHA1 with iteration count from the DK function.

**Dependencies:** `pycryptodome` for MD4, `cryptography` for PBKDF2.

**Acceptance:** Trust passwords decrypted and keys derived correctly against known test vectors. Both CLEAR and NT4OWF auth types handled. Previous auth info parsed. Tests in `tests/test_trusts.py`.

### T-2.7: Implement crypto/dpapi.py

Extract DPAPI domain backup keys from `secret` objects.

**Contents (per [REQ FR-12]):**
- `extract_dpapi_backup_key(encrypted: bytes, pek_list: PEKList) -> DPAPIBackupKey | None` -- PEK-decrypts the `currentValue` attribute, parses the RSA private key blob, extracts PVK data and X.509 certificate if present.
- `_parse_pvk(data: bytes) -> bytes` -- Parses the PVK (Private Key) format blob.
- `_extract_certificate(data: bytes) -> str | None` -- Extracts and PEM-encodes the X.509 certificate if present.

**Dependencies:** `cryptography` for X.509 handling.

**Acceptance:** Extracts PVK and PEM from known DPAPI backup key blobs. Tests in `tests/test_dpapi.py`.

### T-2.8: Implement crypto/gkdi.py

Implement the MS-GKDI group key derivation protocol used by both LAPS v2 and gMSA.

**Contents (per [REQ FR-13], [REQ FR-14], [SPEC MS-GKDI]):**
- `GKDIKeyDeriver` -- Class that holds KDS root keys and derives group keys.
- `derive_key(root_key_data: bytes, key_id: bytes, kdf_param: bytes, secret_agreement_param: bytes) -> bytes` -- Implements the full MS-GKDI key derivation chain: L0 → L1 → L2 key generation using the root key and KDF parameters.
- `_kdf(key: bytes, label: bytes, context: bytes, hash_algorithm: str) -> bytes` -- Key derivation function (KBKDF-HMAC per SP800-108).
- `_compute_l0_key(...)`, `_compute_l1_key(...)`, `_compute_l2_key(...)` -- Individual level computations.
- DH group parameter handling for the secret agreement step.

**Dependencies:** `cryptography` for KBKDF, ConcatKDF, ECDH.

**Acceptance:** Derives correct keys from known KDS root key test data. Tests in `tests/test_gkdi.py`. This is one of the most complex crypto modules.

### T-2.9: Implement crypto/laps.py

Extract LAPS v1 plaintext passwords and decrypt LAPS v2 encrypted passwords.

**Contents (per [REQ FR-13]):**
- `extract_laps_v1(ms_mcs_admpwd: str | bytes, expiration: int | None) -> LAPSPassword` -- Decodes the plaintext ms-Mcs-AdmPwd attribute. Parses expiration FILETIME.
- `decrypt_laps_v2(encrypted_blob: bytes, kds_root_keys: list[KDSRootKey], domain_sid: str) -> LAPSPassword | None` -- Decrypts msLAPS-EncryptedPassword using MS-GKDI key derivation. Parses the CMS encrypted blob (ASN.1/DER), extracts the content encryption key, decrypts the password JSON, extracts password string and account name.
- `_parse_laps_v2_blob(data: bytes) -> tuple[bytes, bytes]` -- Parses the LAPS v2 wire format to separate the CMS blob and metadata.

**Dependencies:** `pyasn1-modules` for CMS parsing, `crypto/gkdi.py` for key derivation.

**Acceptance:** LAPS v1 plaintext extracted. LAPS v2 decrypted with known KDS root keys. Tests in `tests/test_laps.py`.

### T-2.10: Implement crypto/keycredential.py

Parse msDS-KeyCredentialLink binary blobs for Windows Hello for Business and FIDO2 key credentials.

**Contents (per [REQ FR-16] and [SPEC MS-ADTS §2.2.20]):**
- `parse_key_credential(blob: bytes) -> KeyCredential` -- Parses the binary key credential structure. Extracts key ID, key type (NGC, FIDO2, STK), key usage, public key material (RSA or EC), device ID, creation time.
- `_parse_key_material(key_type: int, data: bytes) -> bytes` -- Parses RSA or EC public key material based on key type.
- `_parse_fido2_attestation(data: bytes) -> dict` -- Parses CBOR/COSE attestation data for FIDO2 keys.

**Dependencies:** Possibly `cbor2` for CBOR parsing (evaluate if stdlib can handle it or if this needs a new dependency).

**Acceptance:** Parses known key credential blobs. Correct key type identification. Tests in `tests/test_keycredential.py`.

---

## Phase 3: Decoders Layer

Decoders transform raw ESE records into typed ADObject dicts. They import from `crypto/`, `models/`, and `constants`, but never from `core/`, `cli/`, or `output/`.

### T-3.1: Implement decoders/registry.py

The decoder registry maps objectClass names to decoder instances.

**Contents (per [DES §3.4]):**
- `DecoderRegistry` -- Class with `register(object_class: str, decoder: BaseDecoder)` and `get(object_class: str) -> BaseDecoder` methods. `get()` returns `GenericDecoder` for unregistered classes. Never raises.
- `build_default_registry() -> DecoderRegistry` -- Factory function that creates a registry with all built-in decoders registered: user → UserDecoder, computer → UserDecoder, group → GroupDecoder, trustedDomain → TrustDecoder, domainDNS → DomainDecoder, groupPolicyContainer → GPODecoder, msDS-GroupManagedServiceAccount → GMSADecoder, msKds-ProvRootKey → KDSDecoder, msFVE-RecoveryInformation → BitLockerDecoder. All others → GenericDecoder.

**Acceptance:** Registry returns correct decoder for each registered class. Returns GenericDecoder for unknown classes.

### T-3.2: Implement decoders/base.py

The base decoder provides common attribute decoding logic shared by all specialized decoders.

**Contents (per [DES §3.4] and [DES §4.1]):**
- `DecoderContext` -- Frozen dataclass bundling all dependencies: schema, pek_list, link_resolver, dn_cache, sd_cache, include_deleted, include_raw, naming_mode, errors list.
- `BaseDecoder` -- Base class with:
  - `decode(record, context: DecoderContext) -> dict` -- Template method: calls `_decode_common_attrs()`, then subclass-specific `_decode_specific()`, merges results.
  - `_decode_common_attrs(record, context) -> dict` -- Extracts fields common to all objects: `_object_class`, `_dnt`, `distinguishedName` (from dn_cache), `objectGUID`, `objectSid`, `name`, `whenCreated`, `whenChanged`, `isDeleted`, `instanceType`, `nTSecurityDescriptor`.
  - `_decode_timestamps(record, attr_names: list[str]) -> dict` -- Decodes FILETIME attributes to ISO 8601 strings. Handles special sentinel values (0 → null, 0x7FFF... → "never").
  - `_decode_sid(raw: bytes) -> str` -- Converts binary SID to `S-1-5-21-...` string format.
  - `_decode_guid(raw: bytes) -> str` -- Converts binary GUID to `xxxxxxxx-xxxx-...` string using UUID(bytes_le=...).
  - `_decode_security_descriptor(sd_id: int, sd_cache: dict) -> str | None` -- Looks up SD by ID, converts to SDDL string.
  - `_decode_flags(value: int, flag_class: type[IntFlag]) -> dict` -- Delegates to `decode_flags()` from models/flags.py.
  - `_get_record_attr(record, attr_name: str) -> Any` -- Safe attribute access that returns None on missing attributes.
  - `_resolve_links(dnt: int, link_resolver, attr_name: str) -> list[str]` -- Gets forward or back links for a given attribute, returns list of target DN strings.

**Acceptance:** BaseDecoder extracts common fields correctly. All timestamp formats handled. SID and GUID formatting correct. Tests in `tests/test_decoders.py`.

### T-3.3: Implement decoders/users.py

Decoder for `user` and `computer` object classes. This is the most complex decoder because it handles all credential extraction.

**Contents (per [ARCH §6.2], [ARCH §6.3]):**
- `UserDecoder(BaseDecoder)` -- Handles objectClass "user" and "computer".
  - `_decode_specific(record, context) -> dict` -- Extracts: sAMAccountName, userPrincipalName, displayName, userAccountControl (via decode_flags), sAMAccountType, adminCount, pwdLastSet, lastLogonTimestamp, lastLogon, accountExpires, badPasswordTime, badPwdCount, lockoutTime, description, mail, title, department.
  - `_decode_credentials(record, pek_list) -> dict | None` -- Orchestrates: decrypt_nt_hash, decrypt_lm_hash, decrypt_hash_history (×2), parse_supplemental_credentials. Assembles the `credentials` dict per [ARCH §6.2].
  - `_decode_computer_specific(record, context) -> dict` -- Additional fields for computers: dNSHostName, operatingSystem, operatingSystemVersion, msDS-AllowedToDelegateTo, LAPS attributes.
  - `_decode_delegation(record) -> dict` -- Parses msDS-AllowedToActOnBehalfOfOtherIdentity (binary SD → list of SIDs).
  - `_decode_replication_metadata(record) -> list[dict] | None` -- Parses replPropertyMetaData blob via REPL_PROPERTY_META_DATA structures. [REQ FR-17]
  - `_decode_key_credentials(record) -> list[dict] | None` -- Parses msDS-KeyCredentialLink via crypto/keycredential.py. [REQ FR-16]
  - `_decode_supported_encryption_types(record) -> dict | None` -- Decodes msDS-SupportedEncryptionTypes flags.
  - Link resolution for `memberOf` (back links) and `manager` (if linked attribute).
  - Handles `--raw` mode by including RAW_ prefixed fields.
  - Detects computer vs user by objectClass and adds computer-specific fields.

**Acceptance:** Full user dict matches [ARCH §6.2] schema. Full computer dict matches [ARCH §6.3]. Credentials properly decrypted when PEK available. Credentials output as `_encrypted` hex when PEK absent. Tests covering: user with all fields, user without credentials, computer with LAPS, deleted user.

### T-3.4: Implement decoders/groups.py

**Contents (per [ARCH §6.4]):**
- `GroupDecoder(BaseDecoder)` -- Handles objectClass "group".
  - `_decode_specific(record, context) -> dict` -- Extracts: sAMAccountName, groupType (via decode_flags), adminCount, description.
  - `_resolve_members(dnt, link_resolver) -> list[str]` -- Gets forward links for "member" attribute, returns list of member DN strings. Handles deleted/deactivated members per include_deleted setting.
  - `_resolve_member_of(dnt, link_resolver) -> list[str]` -- Gets back links for "memberOf".

**Acceptance:** Group dict matches [ARCH §6.4]. Member list correctly populated from link_table. Deleted members included/excluded based on flag.

### T-3.5: Implement decoders/trusts.py

**Contents (per [ARCH §6.5]):**
- `TrustDecoder(BaseDecoder)` -- Handles objectClass "trustedDomain".
  - `_decode_specific(record, context) -> dict` -- Extracts: trustPartner, flatName, securityIdentifier, trustType (enum), trustDirection (flags), trustAttributes (flags), msDS-SupportedEncryptionTypes.
  - `_decode_trust_credentials(record, pek_list, domain_name, trust_partner) -> dict | None` -- Calls crypto/trusts.py for both trustAuthIncoming and trustAuthOutgoing. Produces the nested trustCredentials structure with outgoing/incoming and previous rotation data.

**Acceptance:** Trust dict matches [ARCH §6.5]. Trust credentials decrypted with key derivation. Both incoming and outgoing handled.

### T-3.6: Implement decoders/domains.py

**Contents (per [ARCH §6.6]):**
- `DomainDecoder(BaseDecoder)` -- Handles objectClass "domainDNS".
  - `_decode_specific(record, context) -> dict` -- Extracts: msDS-Behavior-Version (functional level), minPwdLength, maxPwdAge, minPwdAge, lockoutThreshold, lockoutDuration, lockoutObservationWindow, pwdProperties (flags), pwdHistoryLength.

**Acceptance:** Domain dict matches [ARCH §6.6].

### T-3.7: Implement decoders/gpo.py

**Contents:**
- `GPODecoder(BaseDecoder)` -- Handles objectClass "groupPolicyContainer".
  - `_decode_specific(record, context) -> dict` -- Extracts: displayName, gPCFileSysPath, versionNumber, gPCMachineExtensionNames, gPCUserExtensionNames.

### T-3.8: Implement decoders/gmsa.py

**Contents (per [REQ FR-14]):**
- `GMSADecoder(BaseDecoder)` -- Handles objectClass "msDS-GroupManagedServiceAccount".
  - `_decode_specific(record, context) -> dict` -- Extracts: sAMAccountName, objectSid, credentials (same as user), msDS-ManagedPasswordId, msDS-ManagedPasswordInterval, msDS-GroupMSAMembership. If KDS root keys are available, derives the managed password via crypto/gkdi.py.

### T-3.9: Implement decoders/bitlocker.py

**Contents (per [REQ FR-15] and [ARCH §6.7]):**
- `BitLockerDecoder(BaseDecoder)` -- Handles objectClass "msFVE-RecoveryInformation".
  - `_decode_specific(record, context) -> dict` -- Extracts: msFVE-RecoveryPassword, msFVE-VolumeGuid (as GUID string), msFVE-KeyPackage (as hex).

### T-3.10: Implement decoders/kds.py

**Contents:**
- `KDSDecoder(BaseDecoder)` -- Handles objectClass "msKds-ProvRootKey".
  - `_decode_specific(record, context) -> dict` -- Extracts: msKds-RootKeyData (hex), msKds-CreateTime, msKds-UseStartTime, msKds-KDFParam (hex), msKds-SecretAgreementParam (hex).

### T-3.11: Implement decoders/generic.py

**Contents:**
- `GenericDecoder(BaseDecoder)` -- Fallback for any unregistered objectClass.
  - `_decode_specific(record, context) -> dict` -- Iterates all non-null attributes in the record, decodes each by its schema-defined syntax type (string, integer, binary → hex, GUID, SID, timestamp). Attributes that cannot be resolved keep their `ATTx######` column names.

**Acceptance:** Generic objects output all attributes. Resolved names used where possible. Unknown attributes keep column names. Tests with a mock record containing mixed attribute types.

---

## Phase 4: Output Layer

Output writers serialize typed dicts to files. They import only from `models/` and `constants`. No imports from `core/`, `cli/`, `crypto/`, or `decoders/`.

### T-4.1: Implement output/base.py

**Contents (per [DES §3.5] and [ARCH §4.4]):**
- `OutputWriter(Protocol)` -- Protocol with `open(path: Path, object_class: str) -> None`, `write(obj_dict: dict) -> None`, `close() -> None`.
- `OutputManager` -- Coordinates per-class output writers. `__init__(format: str, output_dir: Path, extract_classes: set[str])`. Methods: `write_batch(dicts: list[dict])` dispatches each dict to the appropriate writer by `_object_class`. `finalize() -> OutputStats` closes all writers and returns counts.
- `OutputStats` -- frozen dataclass: `counts_by_class: dict[str, int]`, `total_bytes: int`, `total_objects: int`.

### T-4.2: Implement output/ndjson.py

**Contents (per [REQ FR-18] NDJSON format):**
- `NDJSONWriter(OutputWriter)` -- Writes one JSON object per line. Opens per-class files (`users.ndjson`, `groups.ndjson`, etc.). Uses `json.dumps()` with `ensure_ascii=False` for UTF-8 output. 64KB write buffer.

**Acceptance:** Output is valid NDJSON (one JSON object per line). Each line parseable by `json.loads()`. Tests in `tests/test_output_ndjson.py`.

### T-4.3: Implement output/json_.py

**Contents (per [REQ FR-18] JSON format):**
- `JSONWriter(OutputWriter)` -- Writes a pretty-printed JSON array per object class. Opens file, writes `[`, writes each object with comma separation and 2-space indentation, writes `]` on close.

### T-4.4: Implement output/csv_.py

**Contents (per [ARCH §7.4]):**
- `CSVWriter(OutputWriter)` -- Writes flat CSV. Discovers column headers from the first object of each class, writes header row, then data rows. Multi-valued fields pipe-delimited. Flag fields get companion `_flags` columns. Nested credential fields flattened (e.g., `credentials.ntHash`).

### T-4.5: Implement output/hashcat.py

**Contents (per [ARCH §7.1]):**
- `HashcatWriter(OutputWriter)` -- Writes NT and LM hashes in hashcat format. Creates `hashes_nt.hashcat` (one hash per line), `hashes_lm.hashcat`, optionally `hashes_nt_history.hashcat`. Creates companion `.users` mapping file with `hash:domain\username`.

**Acceptance:** Output compatible with `hashcat -m 1000`. Tests in `tests/test_output_hashcat.py`.

### T-4.6: Implement output/john.py

**Contents (per [ARCH §7.2]):**
- `JohnWriter(OutputWriter)` -- Writes hashes in John the Ripper `username:$NT$hash` format.

### T-4.7: Implement output/pwdump.py

**Contents (per [ARCH §7.3]):**
- `PwdumpWriter(OutputWriter)` -- Writes `username:rid:lm_hash:nt_hash:::` format. History entries use `username__historyN` naming.

**Acceptance:** Output compatible with standard pwdump consumers. Tests in `tests/test_output_pwdump.py`.

---

## Phase 5: Core Layer

The core layer orchestrates the pipeline. It imports from all other internal layers and from external dependencies (dissect.database, multiprocessing).

### T-5.1: Implement core/database.py

Wrapper around `dissect.database.ese.ntds.NTDS`.

**Contents (per [DES §3.3] and [ARCH §4.1]):**
- `NTDSDatabase` -- Class wrapping NTDS. Methods: `open(path: Path) -> NTDSDatabase` (validates ESE magic/version, raises `InvalidDatabaseError`), `unlock(bootkey: bytes | None) -> PEKList | None` (decrypts PEK, validates authenticator, raises `BootKeyError`), `iter_datatable() -> Iterator[Record]`, `iter_link_table() -> Iterator[Record]`, `iter_sd_table() -> Iterator[Record]`, `domain() -> Record | None`, property `schema` exposes dissect schema, property `db_path` for workers.
- `InvalidDatabaseError(Exception)` -- Raised on invalid ESE file.
- `SchemaStats` -- Frozen dataclass with attribute_count, class_count, unresolved_count.

**Acceptance:** Opens valid NTDS.dit files. Rejects non-ESE files. Schema statistics reported correctly. PEK decryption works end-to-end. Tests using test fixture NTDS.dit.

### T-5.2: Implement core/schema.py

Schema extensions beyond what `dissect.database` provides.

**Contents (per [DES §3.1] and [REQ FR-3]):**
- `SchemaExtensions` -- Adds any attribute mappings not covered by dissect.database's bootstrap schema. Provides the `_decode_attribute_by_syntax()` function that maps AD syntax IDs to Python decoders (string, integer, SID, GUID, FILETIME, binary, etc.) per [ARCH §5.1].
- `SYNTAX_DECODER_MAP` -- Dict mapping AD syntax OIDs to decoder functions.
- `ATTRIBUTE_DECODER_MAP` -- Dict mapping specific attribute LDAP names to semantic decoders (e.g., "userAccountControl" → UserAccountControl IntFlag parser).

### T-5.3: Implement core/links.py

LinkResolver protocol and both concrete implementations.

**Contents (per [DES §2.4], [ARCH §4.2]):**
- `LinkResolver(Protocol)` -- `forward_links(dnt) -> dict[str, list[ResolvedLink]]`, `back_links(dnt) -> dict[str, list[ResolvedLink]]`, `close() -> None`.
- `MemoryLinkResolver` -- In-memory dict implementation. Two dicts: `_forward[link_dnt] -> list[LinkRecord]` and `_backward[backlink_dnt] -> list[LinkRecord]`.
- `SqliteLinkResolver` -- SQLite temp DB implementation. Creates temp file, creates table with columns (link_dnt, backlink_dnt, link_base, link_deltime, link_deactivetime, link_data), batch-inserts with executemany every 10K records, creates indices after all inserts. Per-connection access (each worker opens own read-only connection).
- `build_link_resolver(link_records: Iterator[Record], schema, dn_cache: dict[int, str], output_dir: Path, threshold: int = 5_000_000) -> LinkResolver` -- Streams link_table records, counts them, selects Memory or SQLite. Resolves link_base to attribute name via schema. Resolves target DNTs to DN strings via dn_cache.

**Acceptance:** MemoryLinkResolver returns correct forward/backward links. SqliteLinkResolver produces identical results. Threshold-based selection works. Deleted/deactivated links tracked with timestamps. Tests in `tests/test_links.py` with both implementations.

### T-5.4: Implement core/dn_cache.py

Distinguished name reconstruction from the datatable.

**Contents (per [DES §2.5] and [REQ FR-5]):**
- `build_dn_cache(datatable_iter: Iterator[Record], schema) -> dict[int, str]` -- Single-pass scan of datatable reading only DNT_col, PDNT_col, RDNtyp_col, and name (RDN). Builds intermediate dict[int, (int, str, int)] mapping DNT → (parent_DNT, RDN_value, RDN_type). Then resolves parent chains to produce full DN strings. RDN type determines prefix: CN=, OU=, DC=, O=, etc. based on the attribute schema.
- Two-pass resolution: first pass builds objects with known parents, second pass resolves any remaining with previously-unresolved parents.
- Reports count of unresolvable DNTs (orphaned objects).

**Acceptance:** Correctly builds DN strings for a test datatable. Handles all RDN types (CN, OU, DC). Reports orphaned objects. Tests in `tests/test_dn_cache.py`.

### T-5.5: Implement core/workers.py

Multiprocessing worker pool management.

**Contents (per [DES §2.5] and [ARCH §4.5]):**
- `WorkerPool` -- Manages `multiprocessing.Pool`. Methods: `start(worker_count, db_path, pek_list, dn_cache, schema, sd_cache, config)` creates pool with initializer. `submit_batch(record_identifiers: list[int]) -> list[dict]` distributes work and collects results. `shutdown()` terminates pool cleanly.
- `_worker_init(db_path, pek_pickle, dn_cache_pickle, schema_pickle, sd_cache_pickle, config_pickle)` -- Worker initializer: unpickles data, opens own NTDSDatabase, constructs DecoderRegistry and DecoderContext. Stored in global worker state.
- `_worker_process_batch(dnt_batch: list[int]) -> list[dict]` -- Processes a batch of DNTs: for each DNT, reads record from ESE, classifies by objectClass, selects decoder, calls decode(), returns list of dicts.
- Error handling: individual record failures logged and counted, never crash the worker. If a worker process crashes, the main process logs and continues with remaining workers.
- Batch size: 1000 DNTs per batch (configurable).
- Pickle compatibility: PEKList, schema maps, DN cache, SD cache all must be picklable. Test this explicitly.

**Acceptance:** Worker pool processes records in parallel. Results match single-threaded processing. Worker crashes handled gracefully. Tests in `tests/test_pipeline_integration.py` (integration tests).

### T-5.6: Implement core/pipeline.py

The PipelineOrchestrator coordinates all four phases.

**Contents (per [DES §2.1] and [ARCH §3.1]):**
- `ExtractionConfig` -- Frozen dataclass capturing all CLI options: ntds_path, system_path, bootkey_hex, output_dir, format, extract_classes, worker_count, no_history, include_deleted, naming_mode, include_raw, verbose, quiet.
- `ExtractionResult` -- Frozen dataclass: output_stats, error_count, errors list, duration.
- `PipelineOrchestrator` -- Main class. `__init__(config: ExtractionConfig)`. `run() -> ExtractionResult` executes all phases:
  - Phase 1: `_phase_schema()` -- Opens NTDSDatabase, reports schema stats. Progress via rich.
  - Phase 2: `_phase_pek()` -- Resolves boot key, decrypts PEK. Reports success/failure.
  - Phase 3: `_phase_links()` -- Builds DN cache (single datatable scan), builds LinkResolver (link_table scan), loads SD cache (sd_table scan). Progress bars for each.
  - Phase 4: `_phase_extract()` -- Creates OutputManager, creates WorkerPool, iterates datatable DNTs, submits batches, collects results, writes to output. Progress bar with objects/sec throughput.
  - Summary: prints extraction statistics, error count, output path.
- Exit code determination: 0 = success, 2 = invalid DB, 3 = bad boot key, 4 = partial (errors > 0).

**Acceptance:** Full pipeline runs end-to-end on a test NTDS.dit file. Output files created in correct format. Progress displayed. Errors reported. Tests in `tests/test_pipeline_integration.py`.

---

## Phase 6: CLI Layer

The CLI layer is a thin wrapper around the pipeline. It imports from `core/` and `models/` only.

### T-6.1: Implement cli/callbacks.py

Argument validation callbacks for typer.

**Contents:**
- `validate_bootkey(value: str) -> str` -- Validates 32-character hex string. Raises typer.BadParameter on invalid input.
- `validate_ntds_path(value: Path) -> Path` -- Validates file exists and is readable. Raises typer.BadParameter if not.
- `validate_system_path(value: Path | None) -> Path | None` -- If provided, validates file exists. Otherwise returns None.
- `validate_output_dir(value: Path) -> Path` -- Creates directory if it doesn't exist. Validates writability.
- `validate_extract_classes(value: str) -> set[str]` -- Parses comma-separated list. Validates against known class names + "all" + "hashes". Raises typer.BadParameter on unknown names.

### T-6.2: Implement cli/app.py

The typer application definition with the main command.

**Contents (per [REQ §5]):**
- `app = typer.Typer()` -- Main typer app.
- `@app.command()` main function with all arguments per [REQ §5.2]:
  - `ntds_dit: Path` (positional, required)
  - `--system: Path | None` (optional)
  - `--bootkey: str | None` (optional)
  - `--output / -o: Path` (default: `./ntdswolf_output/`)
  - `--format / -f: str` (choice: ndjson, json, csv, hashcat, john, pwdump)
  - `--extract / -e: str` (default: "all")
  - `--workers / -w: int` (default: CPU count)
  - `--no-history: bool` (flag)
  - `--include-deleted / --exclude-deleted: bool` (default: True)
  - `--naming: str` (choice: ldap, cn)
  - `--raw: bool` (flag)
  - `--verbose / -v: bool` (flag)
  - `--quiet / -q: bool` (flag)
- Main function: constructs `ExtractionConfig` from args, creates `PipelineOrchestrator`, calls `run()`, handles `ExtractionResult`, returns exit code.
- Version callback: `--version` prints version and exits.
- Error handling: catches `InvalidDatabaseError`, `BootKeyError`, `KeyboardInterrupt` and maps to exit codes.

**Acceptance:** `uv run ntdswolf --help` shows all arguments with descriptions. `uv run ntdswolf --version` prints version. Basic invocation with valid NTDS.dit runs the full pipeline. Tests in `tests/test_cli.py` via subprocess invocation.

---

## Phase 7: Testing

### T-7.1: Create test fixtures

Prepare test data for unit and integration tests.

**Contents:**
- `tests/fixtures/` directory with:
  - Small synthetic NTDS.dit file with known objects and known password hashes.
  - Matching SYSTEM hive with known boot key.
  - Known PEK list blob (encrypted and decrypted reference).
  - Known ENC_SECRET blobs with expected decrypted hashes.
  - Known USER_PROPERTIES blob with all property types.
  - Known trust auth info blob.
  - Known DPAPI backup key blob.
  - Known key credential blob.
  - Known replication metadata blob.
  - Hex blobs for each crypto/structures.py structure.

**Note:** If real test NTDS.dit files are not available, create mock ESE database records using dissect.database's API or use pickled record fixtures.

### T-7.2: Write unit tests for crypto layer

One test file per crypto module:
- `tests/test_bootkey.py` -- Boot key extraction from SYSTEM hive, hex parsing, auto-detect.
- `tests/test_pek.py` -- PEK list decryption (both RC4 and AES versions), authenticator validation, wrong-key detection.
- `tests/test_hashes.py` -- NT/LM hash decryption, history array parsing, empty hash detection.
- `tests/test_supplemental.py` -- Full supplementalCredentials parsing: Kerberos-Newer-Keys, WDigest, CLEARTEXT, NTLM-Strong-NTOWF, legacy Kerberos.
- `tests/test_trusts.py` -- Trust auth decryption, key derivation (RC4, AES128, AES256), salt construction.
- `tests/test_dpapi.py` -- DPAPI backup key extraction, PVK parsing, PEM extraction.
- `tests/test_laps.py` -- LAPS v1 extraction, LAPS v2 decryption (requires GKDI test vectors).
- `tests/test_gkdi.py` -- MS-GKDI key derivation chain, L0/L1/L2 key computation.
- `tests/test_keycredential.py` -- Key credential blob parsing, NGC/FIDO2/STK type detection.
- `tests/test_structures.py` -- All dissect.cstruct definitions parse correctly from known hex blobs.

### T-7.3: Write unit tests for decoders

- `tests/test_decoders.py` -- Tests for each decoder class. Mock ESE records with known attributes, verify output dicts match expected JSON schema. Test: user with full credentials, user without credentials, computer with LAPS, group with members, trust with credentials, domain with policy, GPO, gMSA, BitLocker, KDS root key, generic unknown object.

### T-7.4: Write unit tests for output formatters

- `tests/test_output_ndjson.py` -- Valid NDJSON output, each line JSON-parseable.
- `tests/test_output_hashcat.py` -- Hashcat-compatible output, user mapping file.
- `tests/test_output_pwdump.py` -- pwdump format compliance.
- Additional tests for JSON, CSV, John writers.

### T-7.5: Write unit tests for core modules

- `tests/test_links.py` -- MemoryLinkResolver and SqliteLinkResolver produce identical results. Forward/backward links. Deleted link handling.
- `tests/test_dn_cache.py` -- DN reconstruction from mock datatable. All RDN types. Orphaned objects.
- `tests/test_flags.py` -- Every IntFlag/IntEnum definition with known values. `decode_flags()` function.

### T-7.6: Write integration tests

- `tests/test_pipeline_integration.py` -- Full pipeline execution against test NTDS.dit fixture. Verify: output files exist, output is valid JSON/NDJSON, hash values match known hashes, object counts match expected, error handling works (wrong boot key, corrupted record).
- `tests/test_cli.py` -- CLI invocation via subprocess. Test: `--help`, `--version`, valid run, invalid file, wrong boot key exit code.

### T-7.7: Achieve coverage targets

Run `uv run pytest --cov=ntdswolf --cov-report=term-missing` and verify:
- `crypto/`: >= 90% coverage
- `decoders/`: >= 90% coverage
- `models/`: >= 90% coverage
- `output/`: >= 90% coverage
- `core/workers.py`: exempted (tested via integration)
- `cli/`: exempted (tested via subprocess)

---

## Phase 8: Documentation and Polish

### T-8.1: Write module-level docstrings

Every `__init__.py` and every source module gets a module-level docstring explaining:
- The module's role in the project.
- Key design decisions.
- For protocol code: the relevant Microsoft specification sections.

### T-8.2: Write function docstrings

Every function and method gets a Google-style docstring explaining WHY it exists, not just what it does. Protocol code references spec sections.

### T-8.3: Write README.md

Replace the empty README with:
- Project description (one paragraph).
- Installation instructions (`uv tool install ntdswolf` or `pipx`).
- Quick start example (minimal invocation).
- CLI reference (all flags with descriptions).
- Output format descriptions.
- Supported credential types list.
- Supported Windows Server versions.
- Dependencies.
- License.

### T-8.4: Final linting pass

Run the full lint + typecheck + test suite and fix any remaining issues:
- `uv run ruff check .` -- zero errors
- `uv run ruff format --check .` -- zero diffs
- `uv run ty check` -- zero errors
- `uv run pytest` -- all passing

### T-8.5: Verify CLI end-to-end

Manual verification of all CLI features against a real or synthetic NTDS.dit:
- Default run (NDJSON output, all objects).
- Each output format: `--format json`, `--format csv`, `--format hashcat`, `--format john`, `--format pwdump`.
- Selective extraction: `--extract users,groups`, `--extract hashes`.
- Boot key modes: `--bootkey`, `--system`, auto-detect.
- `--no-history`, `--exclude-deleted`, `--raw`, `--naming cn`.
- `--workers 1` (single-threaded) and `--workers 8` (parallel).
- Error cases: missing file, wrong boot key, corrupted database.

---

## Summary: Task Count by Phase

| Phase | Tasks | Description |
|---|---|---|
| Phase 0 | 6 | Project scaffolding, build config, CI, templates |
| Phase 1 | 6 | Models layer (constants, flags, credentials, links, metadata, objects) |
| Phase 2 | 10 | Crypto layer (structures, bootkey, PEK, hashes, supplemental, trusts, DPAPI, GKDI, LAPS, key credentials) |
| Phase 3 | 11 | Decoders layer (registry, base, users, groups, trusts, domains, GPO, gMSA, BitLocker, KDS, generic) |
| Phase 4 | 7 | Output layer (base, NDJSON, JSON, CSV, hashcat, John, pwdump) |
| Phase 5 | 6 | Core layer (database, schema, links, DN cache, workers, pipeline) |
| Phase 6 | 2 | CLI layer (callbacks, app) |
| Phase 7 | 7 | Testing (fixtures, crypto tests, decoder tests, output tests, core tests, integration tests, coverage) |
| Phase 8 | 5 | Documentation and polish (docstrings, README, linting, verification) |
| **Total** | **60** | |

---

## Dependency Graph (Task Execution Order)

```
Phase 0 (scaffolding)
  └── all tasks can run in parallel, must complete before Phase 1

Phase 1 (models)
  ├── T-1.1 (constants) ── must complete first
  ├── T-1.2 (flags) ── depends on T-1.1
  ├── T-1.3 (credentials) ── depends on T-1.1, T-1.2
  ├── T-1.4 (links) ── depends on T-1.1
  ├── T-1.5 (metadata) ── depends on T-1.1
  └── T-1.6 (objects) ── depends on T-1.2, T-1.3, T-1.4, T-1.5

Phase 2 (crypto) ── depends on all of Phase 1
  ├── T-2.1 (structures) ── no internal deps
  ├── T-2.2 (bootkey) ── no internal deps
  ├── T-2.3 (pek) ── depends on T-2.1
  ├── T-2.4 (hashes) ── depends on T-2.3
  ├── T-2.5 (supplemental) ── depends on T-2.1, T-2.3
  ├── T-2.6 (trusts) ── depends on T-2.3
  ├── T-2.7 (dpapi) ── depends on T-2.3
  ├── T-2.8 (gkdi) ── no internal deps
  ├── T-2.9 (laps) ── depends on T-2.8
  └── T-2.10 (keycredential) ── no internal deps

Phase 3 (decoders) ── depends on all of Phase 2
  ├── T-3.1 (registry) ── no internal deps
  ├── T-3.2 (base) ── no internal deps
  ├── T-3.3 (users) ── depends on T-3.1, T-3.2
  ├── T-3.4 (groups) ── depends on T-3.1, T-3.2
  ├── T-3.5 (trusts) ── depends on T-3.1, T-3.2
  ├── T-3.6 (domains) ── depends on T-3.1, T-3.2
  ├── T-3.7 (gpo) ── depends on T-3.1, T-3.2
  ├── T-3.8 (gmsa) ── depends on T-3.1, T-3.2
  ├── T-3.9 (bitlocker) ── depends on T-3.1, T-3.2
  ├── T-3.10 (kds) ── depends on T-3.1, T-3.2
  └── T-3.11 (generic) ── depends on T-3.1, T-3.2

Phase 4 (output) ── depends on Phase 1 only (models)
  ├── T-4.1 (base) ── no internal deps
  ├── T-4.2 (ndjson) ── depends on T-4.1
  ├── T-4.3 (json) ── depends on T-4.1
  ├── T-4.4 (csv) ── depends on T-4.1
  ├── T-4.5 (hashcat) ── depends on T-4.1
  ├── T-4.6 (john) ── depends on T-4.1
  └── T-4.7 (pwdump) ── depends on T-4.1

Phase 5 (core) ── depends on Phase 2, 3, 4
  ├── T-5.1 (database) ── no internal deps
  ├── T-5.2 (schema) ── no internal deps
  ├── T-5.3 (links) ── no internal deps
  ├── T-5.4 (dn_cache) ── no internal deps
  ├── T-5.5 (workers) ── depends on T-5.1, T-5.3, T-5.4
  └── T-5.6 (pipeline) ── depends on T-5.1 through T-5.5

Phase 6 (cli) ── depends on Phase 5
  ├── T-6.1 (callbacks) ── no internal deps
  └── T-6.2 (app) ── depends on T-6.1, T-5.6

Phase 7 (testing) ── depends on Phases 1-6
  └── all test tasks can run after their target code is written

Phase 8 (polish) ── depends on Phase 7
  └── all tasks can run in parallel, final gate before release
```

**Note:** Phase 4 (output) can be developed in parallel with Phase 2 (crypto) and Phase 3 (decoders) since output writers depend only on Phase 1 (models). This is the primary parallelization opportunity in the implementation schedule.
