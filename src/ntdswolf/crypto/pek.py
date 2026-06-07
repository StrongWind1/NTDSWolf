"""Per-attribute PEK secret decryption ([MS-SAMR] section 2.2.11.1).

The PEK (Password Encryption Key) list protects every encrypted attribute value
in NTDS.dit (NT/LM hashes, supplementalCredentials, trust passwords, ...).
dissect unlocks the PEK list from the SYSTEM boot key (``PEK.unlock``); this
module only removes the *per-attribute* PEK layer via ``pek_decrypt_secret()``,
which dispatches on the ``AlgorithmId`` field in the ``ENC_SECRET`` header.

``PekDecryptor`` lets a dissect ``PEK`` and the local ``PEKList`` be used
interchangeably: production passes the dissect PEK, the unit tests pass a
``PEKList``.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from typing import Protocol

from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import unpad

logger = logging.getLogger(__name__)

# --- Algorithm IDs stored in ENC_SECRET.AlgorithmId ---
# [MS-SAMR] section 2.2.11.1
ALGO_DB_RC4: int = 0x10
ALGO_DB_RC4_SALT: int = 0x11
ALGO_REP_RC4_SALT: int = 0x12
ALGO_DB_AES: int = 0x13

# Set of all recognized RC4-based algorithm IDs.
_RC4_ALGOS: frozenset[int] = frozenset({ALGO_DB_RC4, ALGO_DB_RC4_SALT, ALGO_REP_RC4_SALT})

# ENC_SECRET fixed header sizes (before the variable-length ciphertext).
_ENC_SECRET_HEADER_RC4: int = 2 + 2 + 4 + 16  # AlgorithmId + Flags + PekIndex + Salt = 24
_ENC_SECRET_HEADER_AES: int = 2 + 2 + 4 + 16 + 4  # ... + SecretLength = 28


class BootKeyError(Exception):
    """Raised when PEK decryption fails due to a wrong or missing boot key."""


class PekDecryptor(Protocol):
    """Anything that can remove the PEK layer from an encrypted attribute value.

    Both dissect's ``PEK`` and this module's :class:`PEKList` satisfy it, so the
    credential decoders accept either.  Production passes dissect's ``PEK`` --
    relying on the library for the decryption -- while the unit tests pass a
    ``PEKList``.
    """

    def decrypt(self, data: bytes) -> bytes:
        """Return the plaintext with the PEK layer removed."""
        ...


@dataclass
class PEKList:
    """Holds the decrypted Password Encryption Keys, indexed by PEK ID.

    Attributes:
        keys: Mapping from PEK ID (usually 0) to the 16-byte PEK value.

    """

    keys: dict[int, bytes] = field(default_factory=dict)

    def __len__(self) -> int:
        """Return the number of PEK entries."""
        return len(self.keys)

    def get_key(self, pek_index: int) -> bytes:
        """Look up a PEK by index, falling back to index 0 if not found."""
        if pek_index in self.keys:
            return self.keys[pek_index]
        if 0 in self.keys:
            logger.warning("PEK index %d not found, falling back to PEK 0", pek_index)
            return self.keys[0]
        msg = f"PEK index {pek_index} not found and no fallback key available"
        raise BootKeyError(msg)

    def decrypt(self, data: bytes) -> bytes:
        """Remove the PEK layer from an encrypted attribute value.

        Mirrors dissect's ``PEK.decrypt`` so a ``PEKList`` is interchangeable
        with a dissect PEK (see :class:`PekDecryptor`).
        """
        return pek_decrypt_secret(data, self)


# ---------------------------------------------------------------------------
# Per-attribute secret decryption
# ---------------------------------------------------------------------------


def pek_decrypt_secret(encrypted: bytes, pek_list: PEKList, *, keep_padding: bool = False) -> bytes:
    """Decrypt an individual encrypted attribute value (ENC_SECRET blob).

    This handles the PEK layer only.  The caller is responsible for any
    additional layers (e.g., DES un-obfuscation for NT/LM hashes using the
    account RID).

    Args:
        encrypted: Raw encrypted attribute bytes (starts with ENC_SECRET header).
        pek_list: Decrypted PEK list.
        keep_padding: If True, return the AES plaintext without stripping PKCS7
            padding.  Password-history blobs need this: secretsdump treats the
            trailing padding block as an extra (DES-un-obfuscated) history entry,
            so stripping it would diverge from secretsdump output.  RC4 blobs are
            unaffected (the stream cipher adds no padding).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        BootKeyError: If the algorithm ID is unrecognized or decryption fails.

    """
    if len(encrypted) < _ENC_SECRET_HEADER_RC4:
        msg = f"Encrypted secret too short ({len(encrypted)} bytes)"
        raise BootKeyError(msg)

    # Parse the AlgorithmId to determine RC4 vs AES path.
    algo_id = struct.unpack_from("<H", encrypted, 0)[0]

    if algo_id in _RC4_ALGOS:
        return _decrypt_secret_rc4(encrypted, pek_list)
    if algo_id == ALGO_DB_AES:
        return _decrypt_secret_aes(encrypted, pek_list, keep_padding=keep_padding)

    msg = f"Unknown ENC_SECRET algorithm ID: {algo_id:#x}"
    raise BootKeyError(msg)


def _decrypt_secret_rc4(encrypted: bytes, pek_list: PEKList) -> bytes:
    """Remove the RC4 PEK layer from an encrypted attribute value.

    Key derivation: ``MD5(pek_key || salt)`` -> RC4 stream key.
    """
    # Parse ENC_SECRET_RC4 header fields.
    pek_index = struct.unpack_from("<I", encrypted, 4)[0]  # offset 4: PekIndex
    salt = encrypted[8:24]  # offset 8: 16-byte Salt
    ciphertext = encrypted[_ENC_SECRET_HEADER_RC4:]  # remainder: EncryptedData

    pek_key = pek_list.get_key(pek_index)

    # Derive RC4 key: MD5(pek_key || salt).
    md5 = hashlib.md5(pek_key, usedforsecurity=False)
    md5.update(salt)
    rc4_key = md5.digest()

    return ARC4.new(rc4_key).encrypt(ciphertext)


def _decrypt_secret_aes(encrypted: bytes, pek_list: PEKList, *, keep_padding: bool = False) -> bytes:
    """Remove the AES PEK layer from an encrypted attribute value.

    Uses AES-128-CBC with the PEK as key and the embedded Salt as IV.
    """
    # Parse ENC_SECRET_AES header fields.
    pek_index = struct.unpack_from("<I", encrypted, 4)[0]
    salt = encrypted[8:24]  # 16-byte Salt (also IV)
    # SecretLength at offset 24 (4 bytes) -- we don't strictly need it but
    # it tells us the plaintext length before PKCS7 padding.
    ciphertext = encrypted[_ENC_SECRET_HEADER_AES:]

    pek_key = pek_list.get_key(pek_index)

    return _aes_cbc_decrypt(pek_key, ciphertext, iv=salt, keep_padding=keep_padding)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes = b"\x00" * 16, *, keep_padding: bool = False) -> bytes:
    """AES-128-CBC decrypt with PKCS7 unpadding, tolerant of unpadded data.

    Some NTDS blobs are not PKCS7-padded (the plaintext length is an exact
    multiple of the block size).  We attempt ``unpad`` first and fall back to
    returning the raw decrypted bytes.  When ``keep_padding`` is set the
    plaintext is returned verbatim (no unpadding) -- password-history blobs rely
    on the trailing padding block surviving, because secretsdump emits it as a
    history entry.
    """
    plaintext = b""
    # Some implementations reset the IV per block for RC4-era compatibility.
    # The AES-era PEK list uses a single IV across the whole ciphertext, but
    # per-attribute decryption also uses a single IV.  We always use a single
    # cipher instance when a non-zero IV is supplied.
    if iv != b"\x00" * 16:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(_pad_to_block(ciphertext))
    else:
        # Zero IV: reset cipher per 16-byte block (legacy mode).
        for offset in range(0, len(ciphertext), 16):
            block = ciphertext[offset : offset + 16]
            block = _pad_to_block(block)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext += cipher.decrypt(block)

    if keep_padding:
        return plaintext

    try:
        return unpad(plaintext, 16)
    except ValueError:
        # Data was not PKCS7-padded; return as-is.
        return plaintext


def _pad_to_block(data: bytes, block_size: int = 16) -> bytes:
    """Pad *data* with null bytes to reach *block_size* if it is shorter."""
    if len(data) < block_size:
        return data + b"\x00" * (block_size - len(data))
    return data
