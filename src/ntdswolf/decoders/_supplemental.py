"""Surface dissect's already-decrypted ``supplementalCredentials`` into creds.

dissect.database removes the PEK layer from ``supplementalCredentials`` and
decodes it into a structured dict (``Primary:Kerberos-Newer-Keys`` /
``Primary:Kerberos`` / ``Primary:WDigest`` / ``Primary:CLEARTEXT`` /
``Primary:NTLM-Strong-NTOWF``).  Both the user and gMSA decoders surface the
same fields, so the merge logic lives here once rather than re-parsing the raw
blob (which would duplicate what dissect already does).
"""

from __future__ import annotations

from typing import Any, cast

from ntdswolf.constants import KERBEROS_ETYPE_NAMES


def merge_supplemental(supp: dict[str, Any], creds: dict[str, Any]) -> None:
    """Merge dissect's decoded supplementalCredentials dict into ``creds``.

    ``Primary:Kerberos-Newer-Keys`` / ``Primary:Kerberos`` carry the current
    ``Credentials`` plus ``OldCredentials`` / ``OlderCredentials`` (previous
    passwords) and ``ServiceCredentials``; these surface as ``kerberos`` and, when
    present, ``kerberosOld`` / ``kerberosOlder`` / ``kerberosService``.
    ``Primary:WDigest`` is a list of 16-byte MD5 hashes; ``Primary:CLEARTEXT`` is
    the reversibly encrypted password; ``Primary:NTLM-Strong-NTOWF`` is a 16-byte
    value. The complete decoded structure is also surfaced verbatim (bytes
    hex-encoded) under ``supplementalCredentialsRaw`` so nothing is dropped.

    Args:
        supp: dissect's decoded supplementalCredentials dict.
        creds: Credential dict to populate in place.

    """
    kerb = supp.get("Primary:Kerberos-Newer-Keys")
    if not isinstance(kerb, dict):
        kerb = supp.get("Primary:Kerberos")
    if isinstance(kerb, dict):
        default_salt = kerb.get("DefaultSalt", b"")
        salt = default_salt.decode("utf-16-le", "replace") if isinstance(default_salt, bytes) else str(default_salt)
        # KERB_STORED_CREDENTIAL_NEW carries four key arrays ([MS-SAMR] Primary:Kerberos-Newer-Keys).
        # ``Credentials`` (current keys) feeds every format -- pwdump/hashcat read ``kerberos`` and
        # secretsdump emits only this set. The previous-password (Old/Older) and SPN-salted Service
        # key sets are surfaced under their own keys so the structured formats capture them too,
        # without changing the secretsdump-compatible hash output.
        creds["kerberos"] = _key_entries(kerb.get("Credentials"), salt)
        for field, out_key in (("OldCredentials", "kerberosOld"), ("OlderCredentials", "kerberosOlder"), ("ServiceCredentials", "kerberosService")):
            entries = _key_entries(kerb.get(field), salt)
            if entries:
                creds[out_key] = entries

    wdigest = supp.get("Primary:WDigest")
    if isinstance(wdigest, list):
        creds["wdigest"] = [h.hex() if isinstance(h, bytes) else str(h) for h in wdigest]

    cleartext = supp.get("Primary:CLEARTEXT")
    if cleartext is not None:
        creds["cleartextPassword"] = cleartext if isinstance(cleartext, str) else str(cleartext)

    ntowf = supp.get("Primary:NTLM-Strong-NTOWF")
    if isinstance(ntowf, bytes):
        creds["ntlmStrongNTOWF"] = ntowf.hex()

    # True raw completeness: the entire decoded structure verbatim -- every
    # package (incl. the legacy ``Primary:Kerberos`` and the ``Packages`` list),
    # the default salt / iteration count, and all four key arrays. The curated
    # fields above are derived views of this; nothing here is dropped.
    creds["supplementalCredentialsRaw"] = _serialize_raw(supp)


def _serialize_raw(value: object) -> object:
    """Recursively convert a dissect-decoded value to a JSON-safe form (bytes -> hex), losing nothing."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): _serialize_raw(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize_raw(v) for v in value]
    if isinstance(value, (str, int, float)) or value is None:
        return value
    return str(value)


def _key_entries(creds_list: object, default_salt: str) -> list[dict[str, Any]]:
    """Map a KERB_KEY_DATA(_NEW) credential array to clean key entries (``[]`` if absent)."""
    if not isinstance(creds_list, list):
        return []
    return [kerberos_key_entry(cast("dict[str, Any]", c), default_salt) for c in creds_list if isinstance(c, dict)]


def kerberos_key_entry(cred: dict[str, Any], default_salt: str) -> dict[str, Any]:
    """Build a clean Kerberos key entry from dissect's credential dict.

    Args:
        cred: A single ``{KeyType, Key, IterationCount}`` entry from dissect.
        default_salt: The decoded DefaultSalt string for the key set.

    Returns:
        ``{etype, etypeName, key (hex), salt, iterations}``.

    """
    etype = cred.get("KeyType")
    key = cred.get("Key", b"")
    return {
        "etype": etype,
        "etypeName": KERBEROS_ETYPE_NAMES.get(etype, f"etype-{etype}") if isinstance(etype, int) else None,
        "key": key.hex() if isinstance(key, bytes) else str(key),
        "salt": default_salt,
        "iterations": cred.get("IterationCount"),
    }
