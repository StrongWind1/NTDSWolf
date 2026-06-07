# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `--hashcat-username` selects the username field in hashcat output lines: `sam` (sAMAccountName, the default), `upn`, `rid`, or `sid`.
- Structured output (NDJSON/JSON/CSV) now captures the previous-password and service Kerberos key sets from `supplementalCredentials` -- the `KERB_STORED_CREDENTIAL_NEW` `OldCredentials` / `OlderCredentials` / `ServiceCredentials` arrays -- under `kerberosOld` / `kerberosOlder` / `kerberosService`, alongside the current `kerberos` keys. These were previously dropped, yet every computer account (and any password-changed user) carries them. The hashcat and pwdump outputs are unchanged: they still emit only the current key set, matching secretsdump.
- Every credentialed object now includes `supplementalCredentialsRaw`: the complete decoded `supplementalCredentials` structure verbatim -- every package (including the legacy `Primary:Kerberos` and the `Packages` list), the default salt and iteration count, and all four key arrays, with byte values hex-encoded and nothing curated away.

### Changed

- Reworked the hashcat output into per-class `username:hash` files for `hashcat --username` (`ntlm_<type>_current.txt`, `ntlm_<type>_history.txt`, `lm_<type>_current.txt`, `lm_<type>_history.txt`), split by object class, hash type, and age. LM hashes are emitted as their two 8-byte halves (mode 3000). Kerberos keys are no longer written to the hashcat output -- they are pass-the-key material, not hashcat-crackable hashes.
- The pwdump format now emits secretsdump's "newer pwdump" file set, byte-for-byte compatible with `impacket-secretsdump -outputfile`: `hashes.ntds` (`username:rid:lm:nt:::` with inline `username_historyN` lines), `hashes.ntds.kerberos` (`username:<etype>:<key>`, lowercase etypes, no RC4), and `hashes.ntds.cleartext` (`username:CLEARTEXT:<password>`).

### Removed

- The John the Ripper output format (`--format john`); use `hashcat` or `pwdump`.
- The `--raw` flag, which never had any effect. The completeness it implied is now always on via `supplementalCredentialsRaw` (see Added).

### Fixed

- The pwdump `hashes.ntds.kerberos` file omitted the `dec-cbc-crc` (DES-CBC-CRC) and `rc4_hmac` Kerberos keys on Windows Server 2008 databases, which store five KeyTypes in `supplementalCredentials` (2016+ store three). The writer now keys on the numeric Kerberos KeyType, mirroring `impacket`'s `KERBEROS_TYPE` table exactly (including the `0xFFFFFF74` RC4 marker and the `dec-cbc-crc` spelling), so `hashes.ntds.kerberos` is byte-identical to secretsdump across Server 2008-2022.
- Password history (`ntPwdHistory` / `lmPwdHistory`) was silently dropped for every account, so `hashes.ntds` was missing all `_history` lines. dissect returns the blob wrapped in a one-element list (which failed an `isinstance(bytes)` check), and the AES PEK layer was PKCS7-unpadded, stripping the trailing block secretsdump keeps. History is now decrypted faithfully and `hashes.ntds` is byte-identical to `secretsdump -history` across the RC4 and AES eras (Windows Server 2008-2022). The AES padding block is kept for exact parity (secretsdump emits it as a history entry); because it is not a real password, NTDSWolf logs a stderr `WARNING` naming each account whose history decrypts to more hashes than its `SecretLength` declares.
- Removed the redundant `--exclude-deleted` flag; `--include-deleted` is now a single switch (deleted objects are excluded by default).

## [0.2.0] - 2026-06-07

### Added

- Kerberos keys (AES256/AES128/RC4/DES), WDigest, cleartext, and NTLM-Strong-NTOWF extraction, surfaced from dissect's decoded `supplementalCredentials`. Verified against real databases (Windows Server 2012/2016/2019).
- Kerberos keys are written to `kerberos_keys.txt` (`principal:etype:key`) in the hashcat and pwdump outputs for pass-the-key use.
- Per-class decoder registry is now the live decode path (replacing the simplified inline decoder).
- Working `--workers N` multiprocessing extraction (fork-based), verified to produce byte-identical output to single-threaded.
- Inter-realm trust keys: decrypt `trustAuthIncoming`/`trustAuthOutgoing` and derive each trust account's RC4-HMAC (= NT hash) and AES-256/AES-128 keys (Kerberos string-to-key with the `<REALM>krbtgt<FLATNAME>` salt). Both-direction keys are written to `kerberos_keys.txt`. Verified against a real inter-forest trust.
- LAPS extraction: v1 plaintext (`ms-Mcs-AdmPwd`), v2 cleartext (`msLAPS-Password`), and v2 encrypted (`msLAPS-EncryptedPassword`) decrypted offline through the MS-GKDI / DPAPI-NG chain (adds the `dpapi-ng` dependency, which provides the offline root-key derivation and CMS parsing the online-only RPC path lacks). Verified to reproduce the live LAPS password.
- gMSA / dMSA managed passwords derived entirely offline from the KDS root key + `msDS-ManagedPasswordId` + account SID (MS-GKDI). The 256-byte `managedPassword` self-verifies (its MD4 is the account's NT hash). Standalone (sMSA), group (gMSA), and delegated (dMSA, Server 2025) accounts route to credential-aware decoders; their NT hash + Kerberos keys round-trip-authenticate against a live DC.
- `msDS-KeyCredentialLink` parsing for Windows Hello for Business / FIDO2 / shadow-credential keys.

### Changed

- Lowered the minimum supported Python from 3.14 to 3.11, widening the install base; CI now tests the full 3.11-3.14 range. Two 3.14-only constructs were made portable: `override` now imports from `typing-extensions` (a new, lightweight dependency), and the unparenthesized multi-exception `except` clauses (PEP 758) are parenthesized.
- Removed the impacket runtime dependency. The three primitives it provided -- Kerberos AES string-to-key (RFC 3961/3962), per-RID DES key derivation ([MS-SAMR] 2.2.11.1.2-2.2.11.1.3), and the LAPS v2 timestamp header -- are now implemented directly from their specifications and validated against the RFC 3962 Appendix B test vectors. This also drops flask, ldap3, pyasn1, pyopenssl, and six from the install footprint.
- Output is now cross-validated as byte-identical to impacket-secretsdump on Windows Server 2008R2/2016/2022 (RC4 and AES eras).
- No-password accounts (e.g. Guest) are emitted with the empty NT hash, matching impacket.
- Structured output filenames now use a documented friendly-name map (`user` -> `users.ndjson`, `trustedDomain` -> `trusts.ndjson`) with a sanitized fallback for uncommon classes, replacing the naive `objectClass + "s"` pluralization (which produced names like `dHCPClasss`).
- `--extract` now filters the hash formats (hashcat/john/pwdump) as well as the structured ones, so a users-only run no longer leaks machine-account hashes.

### Fixed

- `--extract` plural names (`users`, `groups`) and `all` now select correctly instead of silently matching nothing.
- SID RID endianness: the last sub-authority is read big-endian, fixing both garbage RIDs and the NT hashes that depend on the RID for DES un-obfuscation.
- A malformed `--system` hive no longer crashes boot-key resolution.

## 0.1.0 - 2026-06-01

Initial implementation (pre-release development baseline).

### Added

**Offline NTDS.dit parsing:**

- Pure-Python ESE database parsing via `dissect.database` -- no .NET, runs on Linux, macOS, and Windows
- Boot key (SYSKEY) resolution from a SYSTEM registry hive, a raw hex boot key, or auto-detection next to the database
- Decryption of PEK-protected attributes for both the RC4 (pre-2016) and AES (2016+) eras
- Windows Server 2008 through 2025 NTDS.dit support

**Credential extraction:**

- NT and LM hashes (`unicodePwd`, `dBCSPwd`) with per-RID DES un-obfuscation
- NT and LM password history (`ntPwdHistory`, `lmPwdHistory`)

**Object decoding:**

- Common attributes for every object (distinguished name, objectGUID, objectSid, name, timestamps, isDeleted)
- Class-specific fields for user, computer, group, trustedDomain, and domainDNS objects
- userAccountControl decoded to named flags
- Group membership and other linked attributes via link-table resolution

**Output formats:**

- NDJSON (one object per line, one file per class), JSON, CSV, hashcat (mode 1000 with a user-mapping file), John the Ripper, and pwdump

### Not yet wired in (roadmap)

The codebase includes cryptographic modules for the items below, but they are not yet connected to the extraction pipeline and are not produced in output:

- Kerberos keys, WDigest, cleartext passwords, and NTLM-Strong-NTOWF from `supplementalCredentials`
- Trust passwords and derived Kerberos keys
- DPAPI domain backup keys, LAPS v1/v2, BitLocker recovery keys, and Windows Hello / FIDO2 key credentials
- gMSA managed passwords and KDS root keys (require MS-GKDI key derivation)

[Unreleased]: https://github.com/StrongWind1/NTDSWolf/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/StrongWind1/NTDSWolf/releases/tag/v0.2.0
