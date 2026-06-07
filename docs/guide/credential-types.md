# Credential Types

NTDSWolf extracts NT/LM hashes and history, Kerberos keys, WDigest, cleartext, NTLM-Strong-NTOWF, inter-realm trust keys (RC4 + AES), LAPS v1/v2 passwords, gMSA/dMSA managed passwords (offline MS-GKDI derivation), and key credentials, all verified against real NTDS databases — the *MSA and trust keys round-trip-authenticate against a live domain controller. The DPAPI-backup-key and BitLocker decoders run in the pipeline but have not yet been confirmed against real data.

## Credentials

**Supported** types are extracted and verified against real NTDS databases. **Wired (unverified)** decoders run in the pipeline but have not yet been confirmed against real data.

| Type | Source attribute | Status |
|---|---|---|
| NT (NTLM) hashes | `unicodePwd` | Supported |
| LM hashes | `dBCSPwd` | Supported |
| NT hash history | `ntPwdHistory` | Supported |
| LM hash history | `lmPwdHistory` | Supported |
| Kerberos keys (AES256, AES128, RC4, DES) — current, previous-password, and service key sets | `supplementalCredentials` | Supported |
| Kerberos Server 2025 keys (AES256-SHA384, AES128-SHA256) | `supplementalCredentials` | Supported |
| WDigest hashes | `supplementalCredentials` | Supported |
| Cleartext passwords | `supplementalCredentials` | Supported |
| NTLM-Strong-NTOWF | `supplementalCredentials` | Supported |
| Trust keys (RC4 + AES, both directions) | `trustAuthIncoming` / `trustAuthOutgoing` | Supported |
| LAPS v1 passwords | `ms-Mcs-AdmPwd` | Supported |
| LAPS v2 cleartext / encrypted passwords | `msLAPS-Password` / `msLAPS-EncryptedPassword` | Supported |
| gMSA / dMSA managed passwords | `msDS-ManagedPasswordId` | Supported |
| Key credentials (WHfB / FIDO2) | `msDS-KeyCredentialLink` | Supported |
| DPAPI backup keys (PVK + PEM) | `secret` objects | Wired (unverified) |
| BitLocker recovery keys | `msFVE-RecoveryInformation` | Wired (unverified) |

The structured formats (NDJSON/JSON/CSV) surface the four `KERB_STORED_CREDENTIAL_NEW` key arrays separately: `kerberos` (current), `kerberosOld` / `kerberosOlder` (previous passwords), and `kerberosService` (SPN-salted service keys). The hashcat and pwdump outputs emit only the current set, matching secretsdump.

## Object classes

The pipeline decodes each object's common attributes (distinguished name, objectGUID, objectSid, name, timestamps, isDeleted) and adds class-specific fields for the classes below. Any other class is emitted with its common attributes only.

| Object class | Class-specific fields |
|---|---|
| `user` | NT/LM hashes and history, sAMAccountName, userPrincipalName, userAccountControl (decoded flags), sAMAccountType, account timestamps, adminCount, group membership |
| `computer` | Same as user, plus dNSHostName and operating-system info |
| `group` | sAMAccountName, groupType, adminCount, members (via link resolution) |
| `trustedDomain` | trustPartner, flatName, securityIdentifier, trustType / trustDirection / trustAttributes, decrypted trust keys (RC4 + AES, both directions) |
| `msDS-GroupManagedServiceAccount`, `msDS-DelegatedManagedServiceAccount` | NT hash + Kerberos keys, the offline-derived 256-byte `managedPassword` (self-verified against the NT hash), and managed-password metadata |
| `msDS-ManagedServiceAccount` | NT hash + Kerberos keys (machine-managed, decoded like a computer account) |
| `domainDNS` | Functional level, password and lockout policy fields |

When no boot key is available, the credential fields are omitted (the objects are still decoded).
