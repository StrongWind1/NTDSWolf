# SPDX-License-Identifier: Apache-2.0
"""LAPS (Local Administrator Password Solution) password extraction.

Two generations of LAPS exist:

* **LAPS v1 (legacy)** -- Stores the plaintext password in the
  ``ms-Mcs-AdmPwd`` attribute as a simple UTF-16LE string.  No encryption
  beyond NTDS.dit-level ACL protection.

* **LAPS v2 (Windows Server 2019+)** -- Stores encrypted passwords in
  ``msLAPS-EncryptedPassword`` using CMS EnvelopedData with a KEK derived
  from Group Key Distribution Service (MS-GKDI / KDS root keys).  Decryption
  requires the KDS root key material, which is complex to extract offline.
  See ``gkdi.py`` for the key derivation logic.

This module provides the public API for all three forms: v1 plaintext, v2
cleartext (the JSON envelope), and v2 encrypted (delegated to ``gkdi.py`` for
the offline GKDI/DPAPI-NG decryption).
"""

from __future__ import annotations

import json
import logging
import struct
from typing import TYPE_CHECKING

from ntdswolf.crypto.gkdi import decrypt_dpapi_ng

if TYPE_CHECKING:
    from dpapi_ng import KeyCache

logger = logging.getLogger(__name__)

# The msLAPS-EncryptedPassword header preceding the DPAPI-NG/CMS blob: split
# FILETIME (lower + upper DWORDs) + Length(4) + Flags(4) = 16 bytes, with Length
# -- the encrypted-buffer size -- at offset 8.  Per the Windows LAPS on-wire format.
_LAPS_V2_HEADER_SIZE: int = 16
_LAPS_V2_LENGTH_OFFSET: int = 8


def parse_laps_cleartext(value: str | bytes) -> dict[str, str | None] | None:
    """Parse a cleartext Windows LAPS ``msLAPS-Password`` JSON envelope.

    Windows LAPS with encryption disabled stores the password as a small JSON
    object: ``{"n": <managed account>, "t": <FILETIME hex>, "p": <password>}``
    (the same envelope that lives *inside* the encrypted blob once decrypted).

    Args:
        value: The ``msLAPS-Password`` attribute value (JSON string or UTF-8 bytes).

    Returns:
        ``{"username", "password", "timestamp"}``, or ``None`` if *value* is not
        the expected JSON envelope.

    """
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    try:
        data = json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return {"username": data.get("n"), "password": data.get("p"), "timestamp": data.get("t")}


def extract_laps_v1(value: bytes) -> dict[str, str]:
    """Decode a LAPS v1 plaintext password from ``ms-Mcs-AdmPwd``.

    The value is a simple UTF-16LE-encoded string with no encryption.
    It is only protected by AD ACLs on the attribute.

    Args:
        value: Raw bytes of the ``ms-Mcs-AdmPwd`` attribute.

    Returns:
        Dict with ``"password"`` key containing the plaintext string.

    """
    try:
        password = value.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        # Some implementations store it as plain ASCII/UTF-8.
        try:
            password = value.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            logger.debug("Failed to decode LAPS v1 password, returning hex")
            password = value.hex()

    return {"password": password}


def extract_laps_v2(encrypted: bytes, cache: KeyCache | None = None) -> dict[str, str | None] | None:
    """Decrypt a LAPS v2 encrypted password from ``msLAPS-EncryptedPassword``.

    The attribute is a small 16-byte header (split FILETIME, encrypted-buffer
    length, and flags) wrapping a CMS ``EnvelopedData`` blob whose
    content-encryption key is protected via the Group Key Distribution Service
    ([MS-GKDI]).  Decryption is
    delegated to :mod:`ntdswolf.crypto.gkdi` (jborean93 dpapi-ng), which performs
    the offline L0->L1->L2 derivation, FFC-DH key agreement, AES key unwrap, and
    AES-GCM decryption using KDS root keys read from NTDS.dit.

    Args:
        encrypted: Raw bytes of the ``msLAPS-EncryptedPassword`` attribute.
        cache: A dpapi-ng key cache preloaded with the domain's KDS root keys
            (see :func:`ntdswolf.crypto.gkdi.build_kds_cache`).

    Returns:
        ``{"username", "password", "timestamp"}`` on success; ``None`` if no KDS
        keys are available or decryption fails.

    """
    if cache is None:
        logger.warning("No KDS root keys available -- cannot decrypt LAPS v2 password")
        return None

    # Strip the LAPS timestamp header to obtain the inner CMS EnvelopedData blob.
    try:
        length = struct.unpack_from("<L", encrypted, _LAPS_V2_LENGTH_OFFSET)[0]
        cms = bytes(encrypted[_LAPS_V2_HEADER_SIZE : _LAPS_V2_HEADER_SIZE + length])
    except (struct.error, ValueError, KeyError, IndexError, TypeError):  # fmt: skip
        logger.debug("Failed to parse msLAPS-EncryptedPassword header", exc_info=True)
        return None

    plaintext = decrypt_dpapi_ng(cms, cache)
    if not plaintext:
        return None

    # The decrypted payload is the same UTF-16LE JSON envelope as the cleartext form.
    try:
        envelope = plaintext.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        logger.debug("LAPS v2 plaintext was not valid UTF-16LE")
        return None
    return parse_laps_cleartext(envelope)
