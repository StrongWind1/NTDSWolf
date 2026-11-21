<h1 align="center">NTDSWolf</h1>

<p align="center"><strong>Read NTDS.dit offline. Every hash, Kerberos key, LAPS and gMSA password, plus secretsdump-identical pwdump output.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/NTDSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NTDSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ntdswolf/"><img src="https://img.shields.io/pypi/v/ntdswolf.svg" alt="PyPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/NTDSWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/NTDSWolf/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind.dev/NTDSWolf/#quick-start">Quick start</a> &bull;
  <a href="https://strongwind.dev/NTDSWolf/reference/cli/">CLI reference</a> &bull;
  <a href="https://strongwind.dev/NTDSWolf/guide/output-formats/">Output formats</a> &bull;
  <a href="https://strongwind.dev/NTDSWolf/">Documentation</a>
</p>

---

NTDSWolf parses an offline Active Directory NTDS.dit and decrypts the credential material it holds: NT/LM hashes and history, Kerberos keys, WDigest, cleartext passwords, trust keys, LAPS, and gMSA/dMSA managed passwords. It dumps every object with its full attribute set as NDJSON, JSON, or CSV, and writes cracking files: hashcat `username:hash` lists and pwdump files byte-identical to secretsdump's. It is pure Python, with no impacket and no .NET dependency, and runs on Linux, macOS, and Windows.

## Example

Decrypt an offline `ntds.dit` with its `SYSTEM` hive and write secretsdump's file set:

```console
$ ntdswolf ntds.dit --system SYSTEM --format pwdump -q -o ./output/
$ grep '^Administrator:' output/hashes.ntds
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
```

## Features

- **Dumps everything**: every object carries an `_unmapped` field with all remaining stored and linked LDAP attributes, so nothing in the database is silently dropped.
- **secretsdump parity**: the `pwdump` format writes byte-for-byte what `impacket-secretsdump -outputfile` writes: `hashes.ntds` (with password history), `hashes.ntds.kerberos`, and `hashes.ntds.cleartext`.
- **Full Kerberos key sets**: current, previous-password, and service keys, including the Server 2025 AES-SHA2 key types; the decoded `supplementalCredentials` blob is kept verbatim.
- **LAPS and managed passwords**: LAPS v1 and v2 (cleartext and encrypted), and gMSA/dMSA passwords derived offline and self-verified against the account's NT hash.
- **Five output formats**: NDJSON (default), JSON, and CSV with one file per object class; `hashcat` `username:hash` files split by class, hash type, and age; and `pwdump`.
- **Parses modern NTDS.dit**: Windows Server 2008 through 2025, in both the RC4 and AES PEK eras ([compatibility](https://strongwind.dev/NTDSWolf/guide/compatibility/)).
- **Parallel extraction**: `--workers` spreads extraction across processes and produces output identical to the single-threaded path.
- **Typed and tested**: full type hints, strict linting, and a test suite covering the decryption and output paths.

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

The runtime dependencies and what each one does are listed in the [installation guide](https://strongwind.dev/NTDSWolf/getting-started/installation/#dependencies).

## Quick start

```sh
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

Every flag is in the [CLI reference](https://strongwind.dev/NTDSWolf/reference/cli/), file names and sample lines for each format in [Output formats](https://strongwind.dev/NTDSWolf/guide/output-formats/), and exit codes in [Windows Server compatibility](https://strongwind.dev/NTDSWolf/guide/compatibility/#exit-codes).

## Credential types

**Supported** types are extracted and verified against real NTDS databases. **Wired (unverified)** decoders run in the pipeline but have not yet been confirmed against real data.

| Type | Source attribute | Status |
| --- | --- | --- |
| NT (NTLM) hashes | `unicodePwd` | Supported |
| LM hashes | `dBCSPwd` | Supported |
| NT hash history | `ntPwdHistory` | Supported |
| LM hash history | `lmPwdHistory` | Supported |
| Kerberos keys (AES256, AES128, RC4, DES) | `supplementalCredentials` | Supported |
| Kerberos Server 2025 keys (AES256-SHA384, AES128-SHA256) | `supplementalCredentials` | Supported |
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

The class-specific fields decoded for users, computers, groups, trusts, managed service accounts, and domains, and how the Kerberos key sets map to output fields, are in [Credential types](https://strongwind.dev/NTDSWolf/guide/credential-types/).

## Development

```sh
git clone https://github.com/StrongWind1/NTDSWolf.git && cd NTDSWolf
uv sync                        # install dev dependencies
make check                     # lint, typecheck, tests, strict docs build
```

Source layout under `src/ntdswolf/`: `cli/` (typer CLI), `core/` (pipeline orchestration, database wrapper, caches, worker pool), `crypto/` (boot key, PEK, and NT/LM hash decryption; trust, DPAPI, LAPS, and key-credential parsers), `decoders/` (per-class object decoders and the decoder registry), `output/` (format writers), `models/` (enums and flag definitions), `constants.py` (spec-derived constants). The three-phase pipeline is described in the [Guide](https://strongwind.dev/NTDSWolf/guide/#processing-pipeline).

## Credits

Built on the [dissect](https://github.com/fox-it/dissect) framework by Fox-IT, with [dpapi-ng](https://github.com/jborean93/dpapi-ng) for offline MS-GKDI / DPAPI-NG decryption. The pwdump output is byte-compatible with [impacket](https://github.com/fortra/impacket)'s secretsdump.

## Related tools

- [**CredWolf**](https://github.com/StrongWind1/CredWolf): Validate AD passwords, hashes, keys, and tickets over NTLM and Kerberos
- [**KerbWolf**](https://github.com/StrongWind1/KerbWolf): Kerberos roasting and TGT attack toolkit for Active Directory
- [**PassWolf**](https://github.com/StrongWind1/PassWolf): Spec-compliant AD password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, LDAP
- [**AD-SecretGen**](https://github.com/StrongWind1/AD-SecretGen): Derive every password-derived AD secret (NT/LM, Kerberos keys, WDigest) from a password
- [**ntcompress**](https://github.com/StrongWind1/ntcompress): Pure-Python ESE record compression and ntdll RtlCompressBuffer/RtlDecompressBuffer formats
- [**Kerberos**](https://github.com/StrongWind1/Kerberos): Protocol internals, security configuration, and attack techniques for Kerberos in Active Directory

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

NTDSWolf is for authorized security testing, research, and education. Use it only against systems and data you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)
