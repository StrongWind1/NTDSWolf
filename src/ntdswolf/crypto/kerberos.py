# SPDX-License-Identifier: Apache-2.0
"""RFC 3961 / RFC 3962 Kerberos AES string-to-key.

Derives the AES-128 and AES-256 Kerberos long-term keys from a cleartext
password and salt exactly as a KDC does ([RFC 3962] section 4):

    tkey = PBKDF2-HMAC-SHA1(password, salt, iterations, key_size)
    key  = DK(tkey, "kerberos")

NTDSWolf needs this one Kerberos primitive to derive an inter-realm trust
account's AES keys from the cleartext trust password (see :mod:`trusts`); it is
implemented directly from the RFCs rather than pulled from a Kerberos library.
The ``n-fold`` and ``DK``/``DR`` key-derivation routines ([RFC 3961]
section 5.1) are the only non-trivial pieces; ``random-to-key`` for AES is the
identity, so ``DK`` reduces to ``DR``.
"""

from __future__ import annotations

from math import gcd

from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Protocol.KDF import PBKDF2

# AES key sizes (bytes) for the two enctypes NTDSWolf derives.
AES128_KEY_SIZE: int = 16
AES256_KEY_SIZE: int = 32

# RFC 3962: default PBKDF2 iteration count when the string-to-key parameters are
# absent -- the value Active Directory uses for trust and account keys.
_DEFAULT_ITERATIONS: int = 4096
# AES block size (bytes): the n-fold target width and the DR feedback-block width.
_AES_BLOCK_SIZE: int = 16
# The DK "constant" that string-to-key uses ([RFC 3961] section 5.1 / [RFC 3962]).
_KERBEROS_CONSTANT: bytes = b"kerberos"
# n-fold rotates each successive replica of the input right by this many bits.
_NFOLD_ROTATE_BITS: int = 13


def aes_string_to_key(password: str, salt: bytes, key_size: int, iterations: int = _DEFAULT_ITERATIONS) -> bytes:
    """Derive an AES Kerberos key from a password and salt ([RFC 3962] section 4).

    Args:
        password: The cleartext password; its UTF-8 encoding is fed to PBKDF2.
        salt: The Kerberos salt bytes (e.g. ``b"EXAMPLE.LABkrbtgtPARTNER"``).
        key_size: 16 for AES-128 or 32 for AES-256.
        iterations: PBKDF2 iteration count (AD uses the 4096 default).

    Returns:
        The derived key (``key_size`` bytes).

    """
    # tkey = PBKDF2-HMAC-SHA1(password, salt); random-to-key is the identity for AES.
    tkey = PBKDF2(password.encode("utf-8"), salt, dkLen=key_size, count=iterations, hmac_hash_module=SHA1)
    return _derive_key(tkey, _KERBEROS_CONSTANT, key_size)


def _derive_key(key: bytes, constant: bytes, key_size: int) -> bytes:
    """DK(key, constant) for AES ([RFC 3961] section 5.1).

    ``random-to-key`` is the identity for AES, so ``DK`` equals ``DR``: n-fold the
    constant to one AES block, then iterate single-block AES-CBC (zero IV, which
    for one block is ECB), feeding each output back in, until ``key_size`` bytes
    of key material have been produced.
    """
    block = _nfold(constant, _AES_BLOCK_SIZE)
    output = bytearray()
    while len(output) < key_size:
        block = AES.new(key, AES.MODE_CBC, b"\x00" * _AES_BLOCK_SIZE).encrypt(block)
        output += block
    return bytes(output[:key_size])


def _nfold(data: bytes, out_len: int) -> bytes:
    """N-fold ``data`` to ``out_len`` bytes ([RFC 3961] section 5.1).

    Replicate the input -- each successive copy rotated right 13 more bits -- out
    to ``lcm(len(data), out_len)`` bytes, then add the ``out_len``-wide chunks
    together with ones'-complement (end-around carry) arithmetic.
    """
    in_len = len(data)
    replicate_to = in_len * out_len // gcd(in_len, out_len)
    buffer = bytearray()
    chunk = data
    for _ in range(replicate_to // in_len):
        buffer += chunk
        chunk = _rotate_right(chunk, _NFOLD_ROTATE_BITS)
    # Add the out_len-wide blocks with end-around carry, big-endian (index 0 = MSB).
    result = [0] * out_len
    carry = 0
    for i in range(out_len - 1, -1, -1):
        total = carry + sum(buffer[j] for j in range(i, len(buffer), out_len))
        result[i] = total & 0xFF
        carry = total >> 8
    while carry:  # propagate the final end-around carry back through the result
        for i in range(out_len - 1, -1, -1):
            carry += result[i]
            result[i] = carry & 0xFF
            carry >>= 8
    return bytes(result)


def _rotate_right(data: bytes, bits: int) -> bytes:
    """Rotate the big-endian bit string ``data`` right by ``bits``, preserving length."""
    width = len(data) * 8
    shift = bits % width
    value = int.from_bytes(data, "big")
    rotated = ((value >> shift) | (value << (width - shift))) & ((1 << width) - 1)
    return rotated.to_bytes(len(data), "big")
