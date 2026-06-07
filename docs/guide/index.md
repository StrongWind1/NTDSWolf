# Guide

NTDSWolf turns an offline Active Directory database into structured, analysis-ready output. This guide explains how it processes a database and what it can extract.

## Processing pipeline

NTDSWolf runs three phases in order:

1. **Open** — opens the ESE database with `dissect.database` and loads the Active Directory schema so that column identifiers can be resolved to attribute names.
2. **Decrypt** — extracts the boot key (SYSKEY) from the SYSTEM hive, raw hex, or auto-detection, then decrypts the Password Encryption Keys from the domain object and validates the authenticator GUID.
3. **Extract** — iterates every object, dispatches it to the decoder registered for its `objectClass`, resolves links (member / memberOf) natively via dissect, decrypts credentials when the PEK is available, and streams the result to the chosen output writer. With `--workers`, this phase runs across multiple processes and produces identical output.

## Boot key resolution

The boot key is required to decrypt credentials. NTDSWolf resolves it in priority order: an explicit `--bootkey` hex value, then a `--system` hive path, then auto-detection of a `SYSTEM` file alongside the database. Without a boot key, objects are still decoded but credential fields are omitted.

## What comes next

- [Credential Types](credential-types.md) — every credential and object class NTDSWolf decodes.
- [Output Formats](output-formats.md) — NDJSON, JSON, CSV, hashcat, and secretsdump-style pwdump.
- [Windows Server Compatibility](compatibility.md) — supported NTDS.dit versions.
- [CLI Reference](../reference/cli.md) — every flag and argument.
