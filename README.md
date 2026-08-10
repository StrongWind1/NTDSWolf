<h1 align="center">NTDSWolf</h1>

<p align="center">
  Offline NTDS.dit parser and credential extractor for Active Directory forensics, penetration testing, and security auditing.
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/NTDSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NTDSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ntdswolf/"><img src="https://img.shields.io/pypi/v/ntdswolf.svg" alt="PyPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/NTDSWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/NTDSWolf/guide/">Guide</a> &bull;
  <a href="https://strongwind.dev/NTDSWolf/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind.dev/NTDSWolf/reference/cli/">CLI reference</a>
</p>

NTDSWolf parses Windows Active Directory NTDS.dit database files with two goals: dump **everything** the directory holds - every object's full attribute set - and present all credential material correctly. It extracts and decrypts NT/LM hashes (and history), Kerberos keys, WDigest, cleartext passwords, trust keys, LAPS, and gMSA/dMSA managed passwords, and emits structured output (NDJSON/JSON/CSV) plus hashcat and pwdump cracking formats that are byte-identical to secretsdump.

## Why NTDSWolf?

- **Dumps everything** - every object carries an `_unmapped` field with all remaining stored and linked LDAP attributes, so nothing in the database is silently dropped.
- **Correct credentials** - NT/LM hashes and history, Kerberos keys (current, previous, and service), WDigest, cleartext, trust keys, LAPS, and gMSA/dMSA managed passwords; the hashcat and pwdump outputs are byte-identical to secretsdump.
- **Pure Python** - runs on Linux, macOS, and Windows with no .NET dependency and no impacket.
- **Parses modern NTDS.dit** - handles Windows Server 2008 through 2025, including the AES PEK era.
- **Typed and tested** - full type hints, strict linting, and a test suite covering the decryption and output paths.

## Example

Extract every credential from an offline `ntds.dit` + `SYSTEM` hive into secretsdump-identical files:

```console
$ ntdswolf ntds.dit --system SYSTEM --format pwdump
[*] wrote hashes.ntds, hashes.ntds.kerberos, hashes.ntds.cleartext

$ head -1 hashes.ntds
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
```

## Installation

Install from [PyPI](https://pypi.org/project/ntdswolf/):

```sh
uv tool install ntdswolf        # recommended
pip install ntdswolf             # or with pip
```

Or install from source:

```sh
uv tool install git+https://github.com/StrongWind1/NTDSWolf
```

## Quick start

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

## CLI reference

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
  -v, --verbose                Verbose logging to stderr
  -q, --quiet                  Suppress all non-error output
  --version                    Print version and exit
```

## Output formats

The structured formats (NDJSON, JSON, CSV) write one file per object class with the curated, decoded fields **plus** an `_unmapped` field carrying every remaining stored and linked LDAP attribute - printable-ASCII values verbatim, anything else hex-encoded - so nothing is dropped. The `hashcat` and `pwdump` formats emit only credential material for cracking.

### NDJSON (default)

One JSON object per line, one file per object class. Compatible with `jq`, SIEM ingestion, and streaming parsers.

```bash
ntdswolf ntds.dit --system SYSTEM --format ndjson
# Output: users.ndjson, computers.ndjson, groups.ndjson, ...
```

```json
{"_object_class": "user", "_dnt": 3802, "sAMAccountName": "Administrator", "objectSid": "S-1-5-21-...-500", "credentials": {"ntHash": "7facdc498ed1680c4fd1448319a8c04f", ...}, "_unmapped": {"primaryGroupID": 513, "codePage": 0, "logonCount": 42, ...}}
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

secretsdump-compatible "newer pwdump" output - byte-for-byte the files `impacket-secretsdump -outputfile` writes: the classic `username:rid:lm:nt:::` lines plus Kerberos-key and cleartext sidecar files.

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

## Extracted data

### Credential types

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
| Kerberos previous-password / service keys | `supplementalCredentials` | Supported |
| Trust keys (RC4 + AES, both directions) | `trustAuthIncoming/Outgoing` | Supported |
| LAPS v1 passwords | `ms-Mcs-AdmPwd` | Supported |
| LAPS v2 cleartext / encrypted passwords | `msLAPS-Password` / `msLAPS-EncryptedPassword` | Supported |
| gMSA / dMSA managed passwords | `msDS-ManagedPasswordId` | Supported |
| Key credentials (WHfB/FIDO2) | `msDS-KeyCredentialLink` | Supported |
| DPAPI backup keys (PVK + PEM) | `secret` objects | Wired (unverified) |
| BitLocker recovery keys | `msFVE-RecoveryInformation` | Wired (unverified) |

In the structured formats, Kerberos keys appear as the current set (`kerberos`) plus the previous-password and service sets (`kerberosOld` / `kerberosOlder` / `kerberosService`), and the complete decoded `supplementalCredentials` blob is preserved verbatim under `supplementalCredentialsRaw`.

### Object types

The pipeline decodes each object's common attributes and adds class-specific fields for the classes below. **Every** object - whatever its class - also carries an `_unmapped` field with all remaining stored and linked LDAP attributes, so no data is dropped.

| Object Class | Class-specific fields extracted |
|---|---|
| `user` | NT/LM hashes + history, sAMAccountName, UPN, userAccountControl (decoded flags), sAMAccountType, account timestamps, adminCount, group membership |
| `computer` | Same as user, plus dNSHostName and operating-system info |
| `group` | sAMAccountName, groupType, adminCount, members (via link resolution) |
| `trustedDomain` | trustPartner, flatName, securityIdentifier, trustType / trustDirection / trustAttributes, decrypted trust keys (RC4 + AES, both directions) |
| `msDS-*ManagedServiceAccount` | NT hash + Kerberos keys; gMSA/dMSA also get the offline-derived `managedPassword` (self-verified against the NT hash) |
| `domainDNS` | Functional level, password and lockout policy fields |
| All others | Common attributes (DN, objectGUID, objectSid, name, timestamps, isDeleted), plus every remaining attribute under `_unmapped` |

## Windows Server compatibility

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

1. **Open** - Opens the ESE database via `dissect.database` and loads the AD schema
2. **Decrypt** - Resolves the boot key from the SYSTEM hive (or raw hex) and unlocks the Password Encryption Keys
3. **Extract** - Iterates all objects, dispatches each to its decoder, resolves links natively via dissect, decrypts credentials, and writes to output

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

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error (I/O, invalid arguments) |
| 2 | Invalid or unreadable NTDS.dit file |
| 3 | Boot key validation failed (wrong SYSTEM hive) |
| 4 | Partial extraction (some objects had errors) |

## Credits

Built on the [dissect](https://github.com/fox-it/dissect) framework by Fox-IT. The hashcat and pwdump outputs are byte-compatible with [impacket](https://github.com/fortra/impacket)'s secretsdump.

## Related tools

Other projects in this collection:

- [AD-SecretGen](https://github.com/StrongWind1/AD-SecretGen) - derive AD password hashes and Kerberos keys from a password
- [CredWolf](https://github.com/StrongWind1/CredWolf) - Active Directory credential validation
- [KerbWolf](https://github.com/StrongWind1/KerbWolf) - Kerberos roasting and hash extraction toolkit
- [Kerberos](https://github.com/StrongWind1/Kerberos) - Kerberos in Active Directory: protocol, security, and attacks

## Disclaimer

NTDSWolf is intended for authorized digital forensics, penetration testing, and security auditing only. You must have explicit written authorization to access and analyze any NTDS.dit database you process with it. Unauthorized access to computer systems and data is illegal. The authors are not responsible for any misuse or damage caused by this tool.

## License

[Apache License 2.0](LICENSE)
