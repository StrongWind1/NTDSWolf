# Windows Server Compatibility

NTDSWolf parses NTDS.dit files from every supported Windows Server release. The PEK encryption scheme changed from RC4 to AES with Server 2016; NTDSWolf detects and handles both from the PEK list version.

| Server version | NTDS.dit parsing | PEK encryption | Hash extraction |
|---|---|---|---|
| Server 2008 / 2008 R2 | Supported | RC4 | Supported |
| Server 2012 / 2012 R2 | Supported | RC4 | Supported |
| Server 2016 | Supported | AES | Supported |
| Server 2019 | Supported | AES | Supported |
| Server 2022 | Supported | AES | Supported |
| Server 2025 | Supported | AES | Supported |

## Server 2025 notes

Server 2025 introduces additional Kerberos key types (AES256-SHA384 and AES128-SHA256) in `supplementalCredentials`. NTDSWolf decodes these alongside the legacy AES and RC4 key types.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error (I/O, invalid arguments) |
| 2 | Invalid or unreadable NTDS.dit file |
| 3 | Boot key validation failed (wrong SYSTEM hive) |
| 4 | Partial extraction (some objects had errors) |
