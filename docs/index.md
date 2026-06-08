# NTDSWolf

Offline NTDS.dit parser and credential extractor for Active Directory forensics, penetration testing, and security auditing.

NTDSWolf parses Windows Active Directory NTDS.dit database files with two goals: dump **everything** the directory holds — every object's full attribute set — and present all credential material correctly. It extracts and decrypts NT/LM hashes (and history), Kerberos keys, WDigest, cleartext passwords, trust keys, LAPS, and gMSA/dMSA managed passwords, and emits structured output (NDJSON/JSON/CSV) plus hashcat and pwdump cracking formats that are byte-identical to secretsdump.

**[Read the Guide](guide/index.md)** · **[Install](getting-started/installation.md)** · **[CLI Reference](reference/cli.md)**

## Why NTDSWolf

- **Dumps everything** — every object carries an `_unmapped` field with all remaining stored and linked LDAP attributes, so nothing in the database is silently dropped.
- **Correct credentials** — NT/LM hashes and history, Kerberos keys (current, previous, and service), WDigest, cleartext, trust keys, LAPS, and gMSA/dMSA managed passwords; the hashcat and pwdump outputs are byte-identical to secretsdump.
- **Pure Python** — runs on Linux, macOS, and Windows with no .NET dependency and no impacket.
- **Parses modern NTDS.dit** — handles Windows Server 2008 through 2025, including the AES PEK era.
- **Typed and tested** — full type hints, strict linting, and a test suite covering the decryption and output paths.

## Quick start

```bash
# Install with uv
uv tool install git+https://github.com/StrongWind1/NTDSWolf

# Basic extraction with an auto-detected SYSTEM hive
ntdswolf ntds.dit

# Provide the SYSTEM hive explicitly and write hashcat-ready hashes
ntdswolf ntds.dit --system SYSTEM --format hashcat -o ./loot/

# Crack the NT hashes
hashcat -m 1000 --username ./loot/ntlm_user_current.txt wordlist.txt
```

See the [installation guide](getting-started/installation.md) for setup details, or jump straight to the [guide](guide/index.md).

## How it works

NTDSWolf runs a three-phase pipeline: it opens the ESE database and loads the AD schema, extracts the boot key and decrypts the Password Encryption Keys, then iterates every object, decodes its attributes (resolving links natively via dissect), decrypts its credentials, and writes the result. The [guide](guide/index.md) walks through each phase.

## License

[Apache License 2.0](https://github.com/StrongWind1/NTDSWolf/blob/main/LICENSE)
