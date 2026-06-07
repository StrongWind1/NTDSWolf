<h1 align="center">NTDSWolf</h1>

<p align="center">
  Offline NTDS.dit parser and credential extractor for Active Directory forensics, penetration testing, and security auditing.
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/NTDSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NTDSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg" alt="Python 3.11–3.14"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://strongwind1.github.io/NTDSWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind1.github.io/NTDSWolf/guide/">Guide</a> &bull;
  <a href="https://strongwind1.github.io/NTDSWolf/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind1.github.io/NTDSWolf/reference/cli/">CLI Reference</a>
</p>

NTDSWolf parses Windows Active Directory NTDS.dit database files and extracts password hashes (NT/LM and history), Kerberos keys, WDigest hashes, and cleartext passwords, along with core object metadata for users, computers, groups, trusts, and domains. It produces structured output in multiple formats suitable for downstream analysis and credential cracking tools.

> **Project status: beta (v0.2.0).** NT/LM hashes and history, Kerberos keys (AES256/AES128/RC4/DES), WDigest, cleartext passwords, inter-realm trust keys (RC4 + AES), LAPS v1/v2 passwords, gMSA/dMSA managed passwords (offline MS-GKDI derivation), and key credentials are extracted and verified against real NTDS databases (Windows Server 2012–2025) — *MSA secrets round-trip-authenticate against a live DC. DPAPI backup keys and BitLocker recovery keys are wired but not yet verified against real data.

## Why NTDSWolf?

- **Pure Python** -- runs on Linux, macOS, and Windows with no .NET dependency.
- **Parses modern NTDS.dit** -- handles Windows Server 2008 through 2025, including the AES PEK era.
- **Structured output** -- emits NDJSON, JSON, and CSV alongside hashcat and secretsdump-compatible pwdump cracking formats.
- **Typed and tested** -- full type hints, strict linting, and a test suite covering the decryption and output paths.

## Installation

```bash
# Install with uv
uv tool install git+https://github.com/StrongWind1/NTDSWolf

# Or install from source
git clone https://github.com/StrongWind1/NTDSWolf.git
cd NTDSWolf
uv sync
```

## Quick Start

```bash
# Basic extraction with auto-detected SYSTEM hive
ntdswolf ntds.dit

# Specify SYSTEM hive explicitly
ntdswolf ntds.dit --system SYSTEM

# Provide boot key directly
ntdswolf ntds.dit --bootkey aabbccdd11223344aabbccdd11223344

# Extract only password hashes in hashcat format
ntdswolf ntds.dit --system SYSTEM --format hashcat

# Extract only users and groups as JSON
ntdswolf ntds.dit --system SYSTEM --format json --extract users,groups

# Full extraction with pwdump output
ntdswolf ntds.dit --system SYSTEM --format pwdump -o ./output/
```

## CLI Reference

```
ntdswolf <ntds.dit> [OPTIONS]

Arguments:
  ntds.dit                     Path to the NTDS.dit database file (required)

Options:
  --system PATH                Path to SYSTEM registry hive for boot key extraction
  --bootkey HEX                Raw 32-character hex boot key (overrides --system)
  -o, --output PATH            Output directory (default: ./ntdswolf-output/)
  -f, --format FORMAT          Output format: ndjson, json, csv, hashcat, pwdump
                               (default: ndjson)
  -e, --extract CLASSES        Comma-separated object classes to extract:
                               users, computers, groups, trusts, domains, all
                               (default: all)
  -w, --workers N              Number of parallel workers (default: 1)
  --no-history                 Exclude password history hashes
  --include-deleted            Include deleted (tombstoned) objects (excluded by default)
  --naming MODE                Object naming: dn, sam, cn (default: dn)
  --hashcat-username FIELD     hashcat line username: sam, upn, rid, sid (default: sam)
  --raw                        Include raw/unmapped attributes in output
  -v, --verbose                Verbose logging to stderr
  -q, --quiet                  Suppress all non-error output
  --version                    Print version and exit
```

## Output Formats

### NDJSON (default)

One JSON object per line, one file per object class. Compatible with `jq`, SIEM ingestion, and streaming parsers.

```bash
ntdswolf ntds.dit --system SYSTEM --format ndjson
# Output: users.ndjson, computers.ndjson, groups.ndjson, ...
```

```json
{"_object_class": "user", "_dnt": 3802, "sAMAccountName": "Administrator", "objectSid": "S-1-5-21-...-500", "credentials": {"ntHash": "7facdc498ed1680c4fd1448319a8c04f", ...}}
```

### JSON

Pretty-printed JSON arrays, one file per object class.

```bash
ntdswolf ntds.dit --system SYSTEM --format json
# Output: users.json, computers.json, ...
```

### CSV

Flat CSV with one row per object. Nested fields flattened with dot notation.

```bash
ntdswolf ntds.dit --system SYSTEM --format csv
# Output: users.csv, computers.csv, ...
```

### hashcat

NT and LM hashes as `username:hash` lines for `hashcat --username`, split per object class, hash type (NT/LM), and age (current/history). By default the username is the sAMAccountName; `--hashcat-username` switches it to `upn`, `rid`, or `sid`. Kerberos keys are not emitted (use `pwdump` for those).

```bash
ntdswolf ntds.dit --system SYSTEM --format hashcat
# Output: ntlm_<type>_current.txt, ntlm_<type>_history.txt,
#         lm_<type>_current.txt, lm_<type>_history.txt
```

```
# ntlm_user_current.txt
Administrator:7facdc498ed1680c4fd1448319a8c04f

# lm_user_current.txt  (the two 8-byte LM halves)
Administrator:1122334455667788
Administrator:aabbccddeeff0011
```

### pwdump

secretsdump-compatible "newer pwdump" output -- byte-for-byte the files `impacket-secretsdump -outputfile` writes: the classic `username:rid:lm:nt:::` lines plus Kerberos-key and cleartext sidecar files.

```bash
ntdswolf ntds.dit --system SYSTEM --format pwdump
# Output: hashes.ntds, hashes.ntds.kerberos, hashes.ntds.cleartext
```

```
# hashes.ntds
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::

# hashes.ntds.kerberos
Administrator:aes256-cts-hmac-sha1-96:6c2d8...e1
```

## Extracted Data

### Credential Types

**Supported** types are extracted and verified against real NTDS databases. **Wired (unverified)** decoders run in the pipeline but have not yet been confirmed against real data.

| Type | Source Attribute | Status |
|---|---|---|
| NT (NTLM) hashes | `unicodePwd` | Supported |
| LM hashes | `dBCSPwd` | Supported |
| NT hash history | `ntPwdHistory` | Supported |
| LM hash history | `lmPwdHistory` | Supported |
| Kerberos keys (AES256, AES128, RC4, DES) | `supplementalCredentials` | Supported |
| Kerberos WS2025 keys (AES256-SHA384, AES128-SHA256) | `supplementalCredentials` | Supported |
| WDigest hashes | `supplementalCredentials` | Supported |
| Cleartext passwords | `supplementalCredentials` | Supported |
| NTLM-Strong-NTOWF | `supplementalCredentials` | Supported |
| Trust keys (RC4 + AES, both directions) | `trustAuthIncoming/Outgoing` | Supported |
| LAPS v1 passwords | `ms-Mcs-AdmPwd` | Supported |
| LAPS v2 cleartext / encrypted passwords | `msLAPS-Password` / `msLAPS-EncryptedPassword` | Supported |
| gMSA / dMSA managed passwords | `msDS-ManagedPasswordId` | Supported |
| Key credentials (WHfB/FIDO2) | `msDS-KeyCredentialLink` | Supported |
| DPAPI backup keys (PVK + PEM) | `secret` objects | Wired (unverified) |
| BitLocker recovery keys | `msFVE-RecoveryInformation` | Wired (unverified) |

### Object Types

The pipeline decodes each object's common attributes and adds class-specific fields for the classes below. Other classes are emitted with their common attributes only.

| Object Class | Class-specific fields extracted |
|---|---|
| `user` | NT/LM hashes + history, sAMAccountName, UPN, userAccountControl (decoded flags), sAMAccountType, account timestamps, adminCount, group membership |
| `computer` | Same as user, plus dNSHostName and operating-system info |
| `group` | sAMAccountName, groupType, adminCount, members (via link resolution) |
| `trustedDomain` | trustPartner, flatName, securityIdentifier, trustType / trustDirection / trustAttributes, decrypted trust keys (RC4 + AES, both directions) |
| `msDS-*ManagedServiceAccount` | NT hash + Kerberos keys; gMSA/dMSA also get the offline-derived `managedPassword` (self-verified against the NT hash) |
| `domainDNS` | Functional level, password and lockout policy fields |
| All others | Common attributes only (DN, objectGUID, objectSid, name, timestamps, isDeleted) |

## Windows Server Compatibility

| Server Version | NTDS.dit Parsing | PEK Decryption | Hash Extraction |
|---|---|---|---|
| Server 2008 / 2008 R2 | Supported | RC4 | Supported |
| Server 2012 / 2012 R2 | Supported | RC4 | Supported |
| Server 2016 | Supported | AES | Supported |
| Server 2019 | Supported | AES | Supported |
| Server 2022 | Supported | AES | Supported |
| Server 2025 | Supported | AES | Supported |

## Architecture

NTDSWolf uses a three-phase processing pipeline:

1. **Open** -- Opens the ESE database via `dissect.database` and loads the AD schema
2. **Decrypt** -- Resolves the boot key from the SYSTEM hive (or raw hex) and unlocks the Password Encryption Keys
3. **Extract** -- Iterates all objects, dispatches each to its decoder, resolves links natively via dissect, decrypts credentials, and writes to output

Object decoding is dispatched through a per-class decoder registry (`decoders/`). Phase 3 runs across multiple worker processes when `--workers` is greater than 1, producing output identical to the single-threaded path.

```
ntdswolf/
  cli/          Command-line interface (typer)
  core/         Pipeline orchestration, database wrapper, caches, worker pool
  crypto/       Boot key, PEK, and NT/LM hash decryption; trust/DPAPI/LAPS/key-credential parsers
  decoders/     Per-class object decoders and the decoder registry
  output/       Format writers (NDJSON, JSON, CSV, hashcat, pwdump)
  models/       Enums and flag definitions
  constants.py  Spec-derived constants and well-known values
```

## Dependencies

| Package | Purpose |
|---|---|
| `dissect.database` | ESE database parsing, NTDS object model, schema |
| `dissect.regf` | SYSTEM registry hive parsing for boot key |
| `dpapi-ng` | Offline MS-GKDI / DPAPI-NG decryption for LAPS v2 |
| `pycryptodome` | AES, DES, RC4, MD4, HMAC, PBKDF2 |
| `typing-extensions` | `@override` backport for Python 3.11 |
| `typer` | CLI framework |
| `rich` | Progress bars and colored output |

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error (I/O, invalid arguments) |
| 2 | Invalid or unreadable NTDS.dit file |
| 3 | Boot key validation failed (wrong SYSTEM hive) |
| 4 | Partial extraction (some objects had errors) |

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
