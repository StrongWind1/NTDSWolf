"""Surface dissect's already-decrypted ``supplementalCredentials`` into creds.

dissect.database removes the PEK layer from ``supplementalCredentials`` and
decodes it into a structured dict (``Primary:Kerberos-Newer-Keys`` /
``Primary:Kerberos`` / ``Primary:WDigest`` / ``Primary:CLEARTEXT`` /
``Primary:NTLM-Strong-NTOWF``).  Both the user and gMSA decoders surface the
same fields, so the merge logic lives here once rather than re-parsing the raw
blob (which would duplicate what dissect already does).
"""

from __future__ import annotations

from typing import Any

from ntdswolf.constants import KERBEROS_ETYPE_NAMES


def merge_supplemental(supp: dict[str, Any], creds: dict[str, Any]) -> None:
    """Merge dissect's decoded supplementalCredentials dict into ``creds``.

    ``Primary:Kerberos-Newer-Keys`` / ``Primary:Kerberos`` carry a ``Credentials``
    list of ``{KeyType, Key, IterationCount}``; ``Primary:WDigest`` is a list of
    16-byte MD5 hashes; ``Primary:CLEARTEXT`` is the reversibly encrypted
    password; ``Primary:NTLM-Strong-NTOWF`` is a 16-byte value.

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
        creds["kerberos"] = [kerberos_key_entry(c, salt) for c in kerb.get("Credentials", []) if isinstance(c, dict)]

    wdigest = supp.get("Primary:WDigest")
    if isinstance(wdigest, list):
        creds["wdigest"] = [h.hex() if isinstance(h, bytes) else str(h) for h in wdigest]

    cleartext = supp.get("Primary:CLEARTEXT")
    if cleartext is not None:
        creds["cleartextPassword"] = cleartext if isinstance(cleartext, str) else str(cleartext)

    ntowf = supp.get("Primary:NTLM-Strong-NTOWF")
    if isinstance(ntowf, bytes):
        creds["ntlmStrongNTOWF"] = ntowf.hex()


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
