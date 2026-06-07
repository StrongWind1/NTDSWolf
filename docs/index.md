# NTDSWolf

Offline NTDS.dit parser and credential extractor for Active Directory forensics, penetration testing, and security auditing.

NTDSWolf parses Windows Active Directory NTDS.dit database files and extracts password hashes (NT/LM and history), Kerberos keys, WDigest hashes, and cleartext passwords, along with core object metadata for users, computers, groups, trusts, and domains. It produces structured output in multiple formats suitable for downstream analysis and credential cracking.

**[Read the Guide](guide/index.md)** · **[Install](getting-started/installation.md)** · **[CLI Reference](reference/cli.md)**

## Why NTDSWolf

- **Pure Python** — runs on Linux, macOS, and Windows with no .NET dependency.
- **Parses modern NTDS.dit** — handles Windows Server 2008 through 2025, including the AES PEK era.
- **Structured output** — emits NDJSON, JSON, and CSV alongside hashcat and secretsdump-compatible pwdump cracking formats.
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
