"""NT and LM hash decryption from NTDS.dit encrypted attribute blobs.

After the PEK layer is removed (see ``pek.py``), NT and LM hashes still
have a per-account DES obfuscation layer keyed by the account's RID.
This module handles both layers and returns the final 16-byte MD4/LM hashes.

The DES un-obfuscation splits the 16-byte hash into two 8-byte halves and
decrypts each with a DES-ECB key derived from the RID.  The RID-to-key-pair
derivation and the LanManager parity bit-spread are implemented inline from
[MS-SAMR] sections 2.2.11.1.2-2.2.11.1.3, so this module is a thin adapter over
dissect (PEK layer) plus standalone DES key derivation.

Hash history attributes (``ntPwdHistory`` / ``lmPwdHistory``) store a
4-byte count followed by that many 16-byte DES-encrypted hashes.

All public functions return ``None`` (or an empty list) on failure rather
than raising exceptions, because missing or corrupt hash blobs are routine
in real-world NTDS.dit databases.
"""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from Crypto.Cipher import DES

from ntdswolf.constants import DWORD_SIZE
from ntdswolf.crypto.pek import BootKeyError

if TYPE_CHECKING:
    from ntdswolf.crypto.pek import PekDecryptor

logger = logging.getLogger(__name__)

# Length of a single NT or LM hash (MD4 / DES-LM output).
_HASH_LEN: int = 16


# ---------------------------------------------------------------------------
# DES key derivation from RID ([MS-SAMR] sections 2.2.11.1.2-2.2.11.1.3)
# ---------------------------------------------------------------------------


def _transform_key(key7: bytes) -> bytes:
    """Expand a 7-byte key into an 8-byte parity-adjusted DES key ([MS-SAMR] section 2.2.11.1.2).

    Spreads the 56 input bits across 8 bytes (7 data bits each), then shifts every
    byte left by one so the data bits occupy the high 7 bits of each DES key byte
    (the low bit is the ignored DES parity bit).
    """
    b = key7
    spread = bytes(
        (
            b[0] >> 1,
            ((b[0] & 0x01) << 6) | (b[1] >> 2),
            ((b[1] & 0x03) << 5) | (b[2] >> 3),
            ((b[2] & 0x07) << 4) | (b[3] >> 4),
            ((b[3] & 0x0F) << 3) | (b[4] >> 5),
            ((b[4] & 0x1F) << 2) | (b[5] >> 6),
            ((b[5] & 0x3F) << 1) | (b[6] >> 7),
            b[6] & 0x7F,
        ),
    )
    return bytes((byte << 1) & 0xFE for byte in spread)


def _derive_des_keys(rid: int) -> tuple[bytes, bytes]:
    """Derive the two 8-byte DES keys for per-RID hash obfuscation ([MS-SAMR] section 2.2.11.1.3).

    The little-endian RID bytes are interleaved into two 7-byte keys, each then
    expanded by :func:`_transform_key`.  These are the keys SAM uses to wrap the
    stored NT/LM hashes; decryption applies them to the two 8-byte halves.
    """
    r = struct.pack("<L", rid)
    key1 = bytes((r[0], r[1], r[2], r[3], r[0], r[1], r[2]))
    key2 = bytes((r[3], r[0], r[1], r[2], r[3], r[0], r[1]))
    return _transform_key(key1), _transform_key(key2)


def _remove_des_layer(encrypted_hash: bytes, rid: int) -> bytes:
    """Remove the per-RID DES obfuscation from a 16-byte hash.

    The RID-derived DES key pair comes from :func:`_derive_des_keys`
    ([MS-SAMR] section 2.2.11.1.3); each 8-byte half is then DES-ECB decrypted.

    Args:
        encrypted_hash: 16 bytes of DES-encrypted hash data.
        rid: Account RID.

    Returns:
        16-byte decrypted hash.

    """
    key1, key2 = _derive_des_keys(rid)
    return DES.new(key1, DES.MODE_ECB).decrypt(encrypted_hash[:8]) + DES.new(key2, DES.MODE_ECB).decrypt(encrypted_hash[8:16])  # noqa: S304 -- DES required by NTDS per-RID hash obfuscation ([MS-SAMR] section 2.2.11.1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def decrypt_nt_hash(encrypted: bytes, pek: PekDecryptor, rid: int) -> bytes | None:
    """Decrypt the ``unicodePwd`` attribute to recover the NT (MD4) hash.

    Args:
        encrypted: Raw bytes of the ``unicodePwd`` (ATTk589914) attribute.
        pek: PEK that removes the PEK layer (dissect's PEK or a PEKList).
        rid: Account RID for the DES layer.

    Returns:
        16-byte NT hash, or ``None`` if decryption fails.

    """
    try:
        after_pek = pek.decrypt(encrypted)
    except (BootKeyError, RuntimeError, KeyError, ValueError, struct.error):
        logger.debug("Failed to remove PEK layer from NT hash", exc_info=True)
        return None

    if len(after_pek) < _HASH_LEN:
        logger.debug("NT hash plaintext too short after PEK decryption: %d bytes", len(after_pek))
        return None

    try:
        return _remove_des_layer(after_pek[:_HASH_LEN], rid)
    except (ValueError, struct.error):
        logger.debug("Failed to remove DES layer from NT hash", exc_info=True)
        return None


def decrypt_lm_hash(encrypted: bytes, pek: PekDecryptor, rid: int) -> bytes | None:
    """Decrypt the ``dBCSPwd`` attribute to recover the LM hash.

    Args:
        encrypted: Raw bytes of the ``dBCSPwd`` (ATTk589879) attribute.
        pek: PEK that removes the PEK layer (dissect's PEK or a PEKList).
        rid: Account RID for the DES layer.

    Returns:
        16-byte LM hash, or ``None`` if decryption fails.

    """
    try:
        after_pek = pek.decrypt(encrypted)
    except (BootKeyError, RuntimeError, KeyError, ValueError, struct.error):
        logger.debug("Failed to remove PEK layer from LM hash", exc_info=True)
        return None

    if len(after_pek) < _HASH_LEN:
        logger.debug("LM hash plaintext too short after PEK decryption: %d bytes", len(after_pek))
        return None

    try:
        return _remove_des_layer(after_pek[:_HASH_LEN], rid)
    except (ValueError, struct.error):
        logger.debug("Failed to remove DES layer from LM hash", exc_info=True)
        return None


def decrypt_hash_history(encrypted: bytes, pek: PekDecryptor, rid: int) -> list[bytes]:
    """Decrypt ``ntPwdHistory`` or ``lmPwdHistory`` to a list of hashes.

    The blob structure after PEK decryption is:
        - 4-byte LE count of hashes
        - *count* x 16-byte DES-encrypted hashes

    Args:
        encrypted: Raw bytes of the history attribute.
        pek: PEK that removes the PEK layer (dissect's PEK or a PEKList).
        rid: Account RID for the DES layer.

    Returns:
        List of 16-byte hashes (may be empty on failure).

    """
    try:
        after_pek = pek.decrypt(encrypted)
    except (BootKeyError, RuntimeError, KeyError, ValueError, struct.error):
        logger.debug("Failed to remove PEK layer from hash history", exc_info=True)
        return []

    if len(after_pek) < DWORD_SIZE:
        return []

    hashes: list[bytes] = []
    # The history blob is simply N concatenated 16-byte DES-encrypted hashes
    # with no explicit count prefix in some versions, but most have a count.
    # We try to parse as many 16-byte blocks as possible.
    for i in range(len(after_pek) // _HASH_LEN):
        chunk = after_pek[i * _HASH_LEN : (i + 1) * _HASH_LEN]
        try:
            hashes.append(_remove_des_layer(chunk, rid))
        except (ValueError, struct.error):
            logger.debug("Failed to remove DES layer from history entry %d", i, exc_info=True)

    return hashes
