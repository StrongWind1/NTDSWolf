# NTDSWolf Roadmap

**Goal:** the most complete offline NTDS.dit parser built on the `dissect` libraries — surface everything `dissect.database` decodes, parse correctly anything it leaves as raw bytes, and emit it all in every output format.

**Status (v0.2.0, 2026-06-07):** NTDSWolf is feature-complete for credential extraction and verified end-to-end against real databases. What remains is an independent cross-check of two low-level decoders and the public release itself.

## Done and verified

Verified against public synthetic fixtures (skelsec/aesedb, Server 2008–2022, cross-checked byte-for-byte against impacket-secretsdump) and against real lab databases (Server 2022/2025 forests, where *MSA and trust secrets round-trip-authenticate against a live domain controller).

**Parsing and decryption**

- Pure-Python ESE parsing, schema loading, and PEK unlock via `dissect.database` (RC4 and AES eras, Server 2008–2025).
- Boot key from `--bootkey`, `--system`, or auto-detection next to the database.
- Three-phase pipeline (open → decrypt → extract) dispatched through a per-class decoder registry; the `--workers` fork pool produces byte-identical output.

**Credentials**

- NT/LM hashes and history (per-RID DES un-obfuscation).
- Kerberos keys (AES256/AES128/RC4/DES, plus the Server 2025 AES-SHA2 etypes), WDigest, cleartext, and NTLM-Strong-NTOWF from `supplementalCredentials`.
- Inter-realm trust keys (RC4 + AES, both directions) via clean-room RFC 3961/3962 Kerberos string-to-key.
- LAPS v1, and LAPS v2 decrypted offline through the MS-GKDI / DPAPI-NG chain.
- gMSA / dMSA / sMSA managed passwords derived offline from the KDS root key — the 256-byte `managedPassword` self-verifies against the stored NT hash.
- Key credentials (`msDS-KeyCredentialLink`).

**Objects and output**

- Generic attribute decoding, security-descriptor → SDDL, replication metadata, sidHistory / delegation / SPN / RBCD, tombstones, and `--naming dn|sam|cn`.
- Six output writers (NDJSON, JSON, CSV, hashcat, John, pwdump) plus `kerberos_keys.txt`; hash output cross-validated as byte-identical to impacket-secretsdump.

**Dependencies and portability**

- No `impacket` dependency: its three primitives (Kerberos string-to-key, per-RID DES key derivation, the LAPS v2 header) are reimplemented clean-room from their specs.
- `dpapi-ng` pinned to a fixed upstream commit; runs on Python 3.11–3.14.

## Remaining

- **Verify the two unconfirmed decoders.** DPAPI domain backup keys (`secret` objects) and BitLocker recovery keys (`msFVE-RecoveryInformation`) are wired and emit decoded data, but have not been cross-checked against an independent oracle (e.g. DSInternals or `manage-bde`). Confirm against a lab capture, then mark them Supported.
- **Publish.** GitHub release; install via `uv tool install git+https://github.com/StrongWind1/NTDSWolf`.

## Future

- Performance validation on multi-GB databases (millions of objects) with streaming output.
- Broader fixture coverage and a ≥90% coverage target on `crypto/`, `decoders/`, and `output/`.
