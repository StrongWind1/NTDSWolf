# CLI Reference

```
ntdswolf <ntds.dit> [OPTIONS]
```

## Arguments

| Argument | Description |
|---|---|
| `ntds.dit` | Path to the NTDS.dit database file (required) |

## Options

| Option | Description |
|---|---|
| `--system PATH` | Path to the SYSTEM registry hive for boot key extraction |
| `--bootkey HEX` | Raw 32-character hex boot key (overrides `--system`) |
| `-o`, `--output PATH` | Output directory (default: `ntdswolf-output/`) |
| `-f`, `--format FORMAT` | Output format: `ndjson`, `json`, `csv`, `hashcat`, `pwdump` (default: `ndjson`) |
| `-e`, `--extract CLASSES` | Comma-separated object classes to extract: `users`, `computers`, `groups`, `trusts`, `domains`, `all` (default: `all`) |
| `-w`, `--workers N` | Number of parallel workers (default: 1) |
| `--no-history` | Exclude password history hashes |
| `--include-deleted` | Include deleted (tombstoned) objects (excluded by default) |
| `--naming MODE` | Object naming: `dn`, `sam`, `cn` (default: `dn`) |
| `--hashcat-username FIELD` | Username field in hashcat output lines: `sam` (sAMAccountName), `upn`, `rid`, or `sid` (default: `sam`) |
| `--raw` | Include raw/unmapped attributes in output |
| `-v`, `--verbose` | Verbose logging to stderr |
| `-q`, `--quiet` | Suppress all non-error output |
| `--version` | Print version and exit |

## Examples

```bash
# Auto-detect the SYSTEM hive next to the database
ntdswolf ntds.dit

# Provide the boot key directly
ntdswolf ntds.dit --bootkey aabbccdd11223344aabbccdd11223344

# Extract only password hashes in hashcat format
ntdswolf ntds.dit --system SYSTEM --format hashcat

# Full extraction to pwdump in a chosen directory
ntdswolf ntds.dit --system SYSTEM --format pwdump -o ./output/
```
