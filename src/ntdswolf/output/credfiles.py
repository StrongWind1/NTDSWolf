# SPDX-License-Identifier: Apache-2.0
r"""Shared helpers for the credential-file output writers (hashcat, pwdump).

``account_username`` resolves an object's logon name identically for both hash
writers, removing the per-writer ``_extract_username`` duplication that existed
when each format implemented its own.

The Kerberos-key and trust-key line formatters (``kerberos_key_lines``,
``trust_credential_lines`` and their ``account_domain`` / ``credential_principal``
helpers) produce ``principal:etype:key`` records. They are not wired to a writer in
the current output set -- the hashcat format no longer emits Kerberos keys, and
pwdump follows secretsdump's per-account ``.ntds.kerberos`` layout -- but are kept
here as the canonical formatting for that data.
"""

from __future__ import annotations

from typing import Any, cast


def account_username(obj_dict: dict[str, Any]) -> str:
    """Return the best available logon name: sAMAccountName, then name, then "unknown"."""
    sam = obj_dict.get("sAMAccountName")
    if isinstance(sam, str) and sam:
        return sam
    name = obj_dict.get("name")
    if isinstance(name, str) and name:
        return name
    return "unknown"


def account_domain(obj_dict: dict[str, Any]) -> str:
    r"""Return the NetBIOS-style domain from the object's DN (first DC label, uppercased).

    Parses ``...,DC=corp,DC=local`` to ``CORP``. Returns an empty string when the
    DN is missing or carries no DC components.
    """
    dn = obj_dict.get("distinguishedName")
    if not isinstance(dn, str):
        return ""
    for component in dn.split(","):
        stripped = component.strip()
        if stripped.upper().startswith("DC="):
            return stripped[3:].upper()  # first DC label is the NetBIOS-style domain
    return ""


def credential_principal(domain: str, username: str) -> str:
    r"""Return ``DOMAIN\username`` (or just ``username`` when no domain is known)."""
    return f"{domain}\\{username}" if domain else username


# etype name -> trustCredentials field for the inter-realm trust-account keys.
_TRUST_KEY_FIELDS: tuple[tuple[str, str], ...] = (
    ("AES256-CTS-HMAC-SHA1-96", "aes256"),
    ("AES128-CTS-HMAC-SHA1-96", "aes128"),
    ("RC4-HMAC", "rc4_hmac"),
)


def trust_credential_lines(obj_dict: dict[str, Any]) -> list[str]:
    r"""Return ``principal:etype:key`` lines for a ``trustedDomain``'s trust-account keys.

    A trust stores the inter-realm trust password in both directions
    (incoming/outgoing) and both ages (current / previous); each yields RC4
    (== the trust account NT hash) and AES keys usable for pass-the-key.
    Incoming keys belong to the partner's trust account in our realm
    (``OURDOMAIN\PARTNER$``); outgoing keys belong to our trust account in the
    partner realm (``PARTNER\OURDOMAIN$``).  Previous keys are tagged
    ``...__previous``.  Returns an empty list for non-trust objects.
    """
    trust_creds = obj_dict.get("trustCredentials")
    if not isinstance(trust_creds, dict):
        return []
    our_netbios = account_domain(obj_dict)
    partner_flat = str(obj_dict.get("flatName") or "").upper()
    principals = {
        "incoming": credential_principal(our_netbios, f"{partner_flat}$") if partner_flat else None,
        "outgoing": credential_principal(partner_flat, f"{our_netbios}$") if our_netbios and partner_flat else None,
    }
    lines: list[str] = []
    for direction in ("incoming", "outgoing"):
        principal = principals[direction]
        section = trust_creds.get(direction)
        if principal is None or not isinstance(section, dict):
            continue
        for suffix, field in (("", "authInfo"), ("__previous", "previousAuthInfo")):
            entries = section.get(field)
            if not isinstance(entries, list):
                continue
            tag = f"{principal}{suffix}"
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                entry_d = cast("dict[str, object]", entry)
                lines.extend(f"{tag}:{etype}:{entry_d[fld]}" for etype, fld in _TRUST_KEY_FIELDS if entry_d.get(fld))
    return lines


def kerberos_key_lines(credentials: dict[str, object], principal: str) -> list[str]:
    """Return ``principal:etype:key`` lines for an account's decoded Kerberos keys.

    Prefers the etype name (e.g. AES256-CTS-HMAC-SHA1-96) and falls back to the
    numeric etype so no key is silently dropped. Returns an empty list when the
    account carries no Kerberos keys.
    """
    keys = credentials.get("kerberos")
    if not isinstance(keys, list):
        return []
    lines: list[str] = []
    for entry in keys:
        if not isinstance(entry, dict):
            continue
        key_entry = cast("dict[str, object]", entry)
        etype = key_entry.get("etypeName") or key_entry.get("etype")
        key = key_entry.get("key")
        if etype is not None and key:
            lines.append(f"{principal}:{etype}:{key}")
    return lines
