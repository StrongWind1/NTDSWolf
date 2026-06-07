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

NT and LM hashes as `username:hash` lines for `hashcat --username`. Files are split by object class, hash type (NT/LM), and age (current/history), and are written only when the corresponding hashes are present:

| File | Contents |
| --- | --- |
| `ntlm_<type>_current.txt` | Current NT hashes, `username:nt_hash` (mode 1000). |
| `ntlm_<type>_history.txt` | Historical NT hashes (only if any account has password history). |
| `lm_<type>_current.txt` | Current LM hashes, split into their two 8-byte halves, `username:lm_half` (mode 3000). |
| `lm_<type>_history.txt` | Historical LM hash halves. |

`<type>` is the object class: `user`, `computer`, `gmsa`, `smsa`, `dmsa` (any other class is lowercased and sanitized to a filesystem-safe name). Files are ASCII with `\n` line endings. Kerberos keys are intentionally **not** emitted — they are pass-the-key material, not hashcat-crackable hashes; use the `pwdump` format for those.

By default `username` is the sAMAccountName. Use `--hashcat-username` to switch it to the UPN (`upn`), the RID (`rid`), or the full objectSid (`sid`):

```bash
ntdswolf ntds.dit --system SYSTEM --format hashcat
ntdswolf ntds.dit --system SYSTEM --format hashcat --hashcat-username rid
```

```
# ntlm_user_current.txt
Administrator:7facdc498ed1680c4fd1448319a8c04f

# lm_user_current.txt  (the two 8-byte LM halves, one per line)
Administrator:1122334455667788
Administrator:aabbccddeeff0011
```

Crack with `hashcat --username`, which ignores the `username:` prefix:

```bash
hashcat -m 1000 --username ntlm_user_current.txt wordlist.txt
hashcat -m 3000 --username lm_user_current.txt wordlist.txt
```

## pwdump

secretsdump-compatible "newer pwdump" output — byte-for-byte the files `impacket-secretsdump -outputfile` writes:

| File | Contents |
| --- | --- |
| `hashes.ntds` | `username:rid:lm:nt:::`, with inline `username_historyN:...` lines for password history. |
| `hashes.ntds.kerberos` | `username:<etype>:<key>` Kerberos keys (lowercase etypes; no RC4, which is already the NT hash). |
| `hashes.ntds.cleartext` | `username:CLEARTEXT:<password>` for reversibly-encrypted passwords. |

This is the modern pwdump secretsdump emits: the classic `username:rid:lm:nt:::` line plus the Kerberos-key and cleartext sidecar files. Accounts that carry a userPrincipalName are prefixed with their UPN domain (`TEST.corp\test2`), exactly as secretsdump does.

!!! note "Password-history padding entries"
    For exact secretsdump parity, history lines (`username_historyN`) include the trailing PKCS7 **padding block** that secretsdump decrypts and emits as a history hash. That entry is **not a real previous password** — it is derived from encryption padding, not a stored credential. NTDSWolf keeps it so `hashes.ntds` matches `secretsdump -history` byte-for-byte, and prints a `WARNING` to stderr naming each account whose history decrypts to more hashes than its `SecretLength` declares, so the fabricated entries are easy to spot.

```bash
ntdswolf ntds.dit --system SYSTEM --format pwdump
```

```
# hashes.ntds
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::

# hashes.ntds.kerberos
Administrator:aes256-cts-hmac-sha1-96:6c2d8...e1
Administrator:aes128-cts-hmac-sha1-96:9af3b...02
```

## Selecting object classes

`--extract` / `-e` limits output to specific object classes. It accepts singular or plural names (`user` or `users`) and `all` for everything (the default). The filter applies to every format, including the hash formats — `--extract users` keeps machine accounts out of `ntlm_user_current.txt`, and `--extract computers` keeps user accounts out.

```bash
# Only user accounts, as hashcat-ready NT hashes
ntdswolf ntds.dit --system SYSTEM --format hashcat --extract users

# Users and groups only, as NDJSON
ntdswolf ntds.dit --system SYSTEM --extract users --extract groups
```
