# Output Formats

Select an output format with `--format` / `-f`. Output is written to the directory given by `--output` / `-o` (default `ntdswolf-output/`).

For the structured formats (NDJSON, JSON, CSV), each object class is written to its own file. Common classes get friendly names (`user` → `users.ndjson`, `computer` → `computers.csv`, `trustedDomain` → `trusts.json`, `groupPolicyContainer` → `gpos.ndjson`, `domainDNS` → `domains.ndjson`); any other class name is lowercased and sanitized to a filesystem-safe form (so `dHCPClass` → `dhcpclass.ndjson`, never the awkward `dHCPClasss`).

## NDJSON (default)

One JSON object per line, one file per object class. Compatible with `jq`, SIEM ingestion, and streaming parsers.

```bash
ntdswolf ntds.dit --system SYSTEM --format ndjson
# Output: users.ndjson, computers.ndjson, groups.ndjson, ...
```

```json
{"_object_class": "user", "_dnt": 3802, "sAMAccountName": "Administrator", "objectSid": "S-1-5-21-...-500", "credentials": {"ntHash": "..."}}
```

## JSON

Pretty-printed JSON arrays, one file per object class.

```bash
ntdswolf ntds.dit --system SYSTEM --format json
```

## CSV

Flat CSV with one row per object. Nested fields are flattened with dot notation; multi-valued fields are pipe-delimited.

```bash
ntdswolf ntds.dit --system SYSTEM --format csv
```

## hashcat

NT hashes in hashcat mode 1000 format, with a companion user-mapping file. Additional files are written only when the corresponding data is present:

| File | Contents |
| --- | --- |
| `hashes_nt.hashcat` | Bare NT hashes, one per line (mode 1000). |
| `hashes_nt.hashcat.users` | `hash:DOMAIN\username` mapping for correlating cracked results. |
| `hashes_lm.hashcat` | LM hash halves, one per line (mode 3000). |
| `hashes_nt_history.hashcat` | Historical NT hashes (only if any account has password history). |
| `hashes_lm_history.hashcat` | Historical LM hash halves. |
| `kerberos_keys.txt` | `principal:etype:key` Kerberos keys for pass-the-key (only if any account has decoded keys). |

```bash
ntdswolf ntds.dit --system SYSTEM --format hashcat
```

```
# hashes_nt.hashcat
7facdc498ed1680c4fd1448319a8c04f

# hashes_nt.hashcat.users
7facdc498ed1680c4fd1448319a8c04f:DOMAIN\Administrator

# kerberos_keys.txt
DOMAIN\Administrator:AES256-CTS-HMAC-SHA1-96:6c2d8...e1
DOMAIN\Administrator:AES128-CTS-HMAC-SHA1-96:9af3b...02
```

## John the Ripper

```bash
ntdswolf ntds.dit --system SYSTEM --format john
```

```
Administrator:$NT$7facdc498ed1680c4fd1448319a8c04f
```

## pwdump

Classic `username:rid:lm:nt:::` format. History goes to `hashes_history.pwdump`, and decoded Kerberos keys are written to `kerberos_keys.txt` (same `principal:etype:key` format as the hashcat output).

```bash
ntdswolf ntds.dit --system SYSTEM --format pwdump
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
```

## Selecting object classes

`--extract` / `-e` limits output to specific object classes. It accepts singular or plural names (`user` or `users`) and `all` for everything (the default). The filter applies to every format, including the hash formats — `--extract users` keeps machine accounts out of `hashes_nt.hashcat`, and `--extract computers` keeps user accounts out.

```bash
# Only user accounts, as hashcat-ready NT hashes
ntdswolf ntds.dit --system SYSTEM --format hashcat --extract users

# Users and groups only, as NDJSON
ntdswolf ntds.dit --system SYSTEM --extract users --extract groups
```
