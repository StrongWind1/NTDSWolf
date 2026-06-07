"""Trust relationship credential parsing and Kerberos key derivation.

AD inter-domain/forest trust objects store authentication credentials in the
``trustAuthIncoming`` and ``trustAuthOutgoing`` attributes.  dissect.database
removes the PEK layer for us when the boot key is known, so this module works
on the *decrypted* blob: a small header followed by ``LSAPR_AUTH_INFORMATION``
entries ([MS-LSAD] section 2.2.7.21 / [MS-ADTS] section 6.1.6.9.1):

    DWORD Count
    DWORD CurrentAuthInfoOffset
    DWORD PreviousAuthInfoOffset
    <current LSAPR_AUTH_INFORMATION entries>
    <previous LSAPR_AUTH_INFORMATION entries>

Each entry: LastUpdateTime (FILETIME, 8) + AuthType (4) + AuthInfoLength (4) +
AuthInfo[AuthInfoLength], padded to a 4-byte boundary.

* **TRUST_AUTH_TYPE_CLEAR (2)** -- the trust password (a UTF-16LE string).
  The trust account's keys derive from it:
    - RC4-HMAC = ``MD4(password_bytes)``  (== the trust account's NT hash)
    - AES-128 / AES-256 = Kerberos string-to-key (RFC 3962) over the
      UTF-16LE-decoded password with the trust account's salt.
* **TRUST_AUTH_TYPE_NT4OWF (1)** -- the NT hash directly (RC4-HMAC key).

The Kerberos salt for an inter-realm trust account is
``<ACCOUNT_REALM_DNS_UPPER>krbtgt<OTHER_DOMAIN_FLATNAME>`` -- e.g. a PARTNER$
trust account in EXAMPLE.LAB uses ``EXAMPLE.LABkrbtgtPARTNER``.  The caller
supplies the salt because it knows both domains' DNS and flat (NetBIOS) names.

Verified end-to-end against a real inter-forest trust: ``MD4`` of the current
incoming auth info equalled the trust account's stored NT hash, and the Kerberos
string-to-key (see :mod:`ntdswolf.crypto.kerberos`) of the same password with
that salt reproduced the stored AES-256/AES-128 keys exactly.
"""

from __future__ import annotations

import logging
import struct

from Crypto.Hash import MD4

from ntdswolf.crypto.kerberos import AES128_KEY_SIZE, AES256_KEY_SIZE, aes_string_to_key

logger = logging.getLogger(__name__)

# --- Trust auth type constants ([MS-LSAD] section 2.2.7.21) ---
TRUST_AUTH_TYPE_NONE: int = 0
TRUST_AUTH_TYPE_NT4OWF: int = 1
TRUST_AUTH_TYPE_CLEAR: int = 2
TRUST_AUTH_TYPE_VERSION: int = 3

_AUTH_TYPE_NAMES: dict[int, str] = {
    TRUST_AUTH_TYPE_NONE: "TRUST_AUTH_TYPE_NONE",
    TRUST_AUTH_TYPE_NT4OWF: "TRUST_AUTH_TYPE_NT4OWF",
    TRUST_AUTH_TYPE_CLEAR: "TRUST_AUTH_TYPE_CLEAR",
    TRUST_AUTH_TYPE_VERSION: "TRUST_AUTH_TYPE_VERSION",
}

# Header: Count + CurrentAuthInfoOffset + PreviousAuthInfoOffset = 3 DWORDs.
_TRUST_AUTH_HEADER_SIZE: int = 12
# LSAPR_AUTH_INFORMATION fixed header: LastUpdateTime (8) + AuthType (4) + AuthInfoLength (4).
_AUTH_INFO_HEADER_SIZE: int = 16
# NT4 OWF (NT hash) length in bytes.
_NT4OWF_LENGTH: int = 16


def parse_trust_auth(decrypted: bytes, salt: str) -> dict:
    """Parse a (dissect-decrypted) trust auth blob and derive Kerberos keys.

    Args:
        decrypted: PEK-decrypted ``trustAuthIncoming``/``trustAuthOutgoing``
            bytes (dissect removes the PEK layer when the boot key is known).
        salt: Kerberos string-to-key salt for the trust account
            (``<REALM>krbtgt<FLAT>``), used for the AES keys.

    Returns:
        ``{"count", "authInfo": [...], "previousAuthInfo": [...]}``; empty dict
        if the blob is too short to parse.

    """
    if len(decrypted) < _TRUST_AUTH_HEADER_SIZE:
        logger.debug("Trust auth blob too short: %d bytes", len(decrypted))
        return {}

    count, cur_off, prev_off = struct.unpack_from("<III", decrypted, 0)
    current = decrypted[cur_off:prev_off] if cur_off < prev_off <= len(decrypted) else decrypted[cur_off:]
    previous = decrypted[prev_off:] if 0 < prev_off <= len(decrypted) else b""

    return {
        "count": count,
        "authInfo": _parse_auth_info_array(current, salt),
        "previousAuthInfo": _parse_auth_info_array(previous, salt),
    }


def _parse_auth_info_array(data: bytes, salt: str) -> list[dict]:
    """Parse a sequence of LSAPR_AUTH_INFORMATION entries."""
    entries: list[dict] = []
    pos = 0
    while pos + _AUTH_INFO_HEADER_SIZE <= len(data):
        last_update_time, auth_type, auth_info_length = struct.unpack_from("<QII", data, pos)
        pos += _AUTH_INFO_HEADER_SIZE
        if pos + auth_info_length > len(data):
            break
        auth_info = data[pos : pos + auth_info_length]
        pos += auth_info_length
        pos += (-auth_info_length) % 4  # entries are padded to a 4-byte boundary
        entries.append(_build_auth_entry(auth_type, auth_info, last_update_time, salt))
    return entries


def _build_auth_entry(auth_type: int, auth_info: bytes, last_update_time: int, salt: str) -> dict:
    """Build one LSAPR_AUTH_INFORMATION entry, deriving keys for CLEAR types."""
    entry: dict = {
        "lastUpdateTime": last_update_time,
        "authType": _AUTH_TYPE_NAMES.get(auth_type, f"UNKNOWN({auth_type})"),
    }
    if auth_type == TRUST_AUTH_TYPE_CLEAR:
        entry["cleartextPassword"] = auth_info.hex()
        entry.update(_derive_trust_keys(auth_info, salt))
    elif auth_type == TRUST_AUTH_TYPE_NT4OWF and len(auth_info) >= _NT4OWF_LENGTH:
        entry["rc4_hmac"] = auth_info[:_NT4OWF_LENGTH].hex()
    return entry


def _derive_trust_keys(password_bytes: bytes, salt: str) -> dict:
    """Derive the trust account's Kerberos keys from its cleartext password.

    RC4-HMAC is ``MD4(password_bytes)`` (== the trust account's NT hash).  AES
    keys use the Kerberos string-to-key (RFC 3962: PBKDF2-HMAC-SHA1 followed by
    the DK derivation step -- see :mod:`ntdswolf.crypto.kerberos`); the DK step,
    which a bare PBKDF2 omits, is what turns the PBKDF2 output into the usable
    Kerberos keys.  The password is a UTF-16LE string; string-to-key consumes its
    decoded code points.

    Per [MS-KILE] / [MS-ADTS] section 6.1.6.9.1.
    """
    result: dict = {}

    md4 = MD4.new()  # noqa: S303 -- MD4 is the RC4-HMAC / NTOWF construction mandated by [MS-KILE]
    md4.update(password_bytes)
    result["rc4_hmac"] = md4.hexdigest()

    password = password_bytes.decode("utf-16-le", errors="replace")
    salt_bytes = salt.encode("utf-8")
    try:
        result["aes256"] = aes_string_to_key(password, salt_bytes, AES256_KEY_SIZE).hex()
        result["aes128"] = aes_string_to_key(password, salt_bytes, AES128_KEY_SIZE).hex()
    except (ValueError, TypeError, IndexError):
        logger.debug("Failed to derive trust AES keys (salt=%r)", salt, exc_info=True)
    return result
