"""MS-GKDI / DPAPI-NG offline decryption for LAPS v2 encrypted passwords.

LAPS v2 stores ``msLAPS-EncryptedPassword`` as a small timestamp header followed
by a CMS ``EnvelopedData`` blob whose content-encryption key is wrapped by a key
derived through the Group Key Distribution Service ([MS-GKDI]).  Decrypting it
offline requires:

1. The KDS root key material (``msKds-RootKeyData`` + KDF / secret-agreement
   parameters), stored in NTDS.dit under ``CN=Master Root Keys,CN=Group Key
   Distribution Service,CN=Services``.  It is confidential but survives an
   ``ntdsutil`` IFM export.
2. The full [MS-GKDI] L0->L1->L2 derivation (the L1 seed mixes in the target
   security descriptor), then FFC-DH/ECDH key agreement, AES key unwrap, and
   AES-GCM content decryption.

This module uses jborean93's ``dpapi-ng`` library, which implements the complete
offline chain (root-key derivation + CMS parsing); the common alternative
implements only the *online* RPC path.  Verified end-to-end: offline decryption
of a real ``msLAPS-EncryptedPassword`` reproduced the live ``Get-LapsADPassword``
value exactly.

The gMSA/dMSA managed-password *blob* is a different GKDI consumer (no CMS) and
is not derived here; those accounts' usable secrets (NT hash + Kerberos keys)
come from the standard PEK-decrypted ``unicodePwd`` / ``supplementalCredentials``.
"""

from __future__ import annotations

import logging
import struct
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

import dpapi_ng
from Crypto.Hash import HMAC, SHA1, SHA256, SHA384, SHA512

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from types import ModuleType

logger = logging.getLogger(__name__)

# --- gMSA / dMSA managed-password derivation (MS-GKDI + the gMSA password KDF) ---

# SP800-108 KDF labels (UTF-16LE, null-terminated), per [MS-GKDI] / the gMSA logic.
_KDS_SERVICE_LABEL: bytes = "KDS service\0".encode("utf-16-le")
_GMSA_PASSWORD_LABEL: bytes = "GMSA PASSWORD\0".encode("utf-16-le")

# GKDI L1/L2 trees have 32 entries (indices 0..31); derivation descends from 31.
_L_INDEX_MAX: int = 31
# The managed password is 256 bytes of key material.
_MANAGED_PASSWORD_LENGTH: int = 256
# KeyIdentifier (msDS-ManagedPasswordId) layout: Version(4)+Magic(4)+Flags(4)+L0(4)+L1(4)+L2(4)+RootKeyId(16).
_KEY_IDENTIFIER_MIN_LENGTH: int = 40
# KDFParameters: Unknown1(4)+Unknown2(4)+HashLen(4)+Unknown3(4)+HashName; HashLen at offset 8, name at 16.
_KDF_HASH_LEN_OFFSET: int = 8
_KDF_HASH_NAME_OFFSET: int = 16

# pycryptodome hash modules (passed to HMAC.new), keyed by the KDF's hash name.
_HASH_BY_NAME: dict[str, ModuleType] = {
    "SHA1": SHA1,
    "SHA256": SHA256,
    "SHA384": SHA384,
    "SHA512": SHA512,
}

# The fixed security descriptor the DC uses when generating a gMSA/dMSA password:
# O:SY D:(A;;FRFW;;;S-1-5-9) (Enterprise Domain Controllers), serialized in the
# MS-GKDI byte order (Dacl then Owner).  It is mixed into the L1 seed's KDF
# context.  Verified: with this SD the derived password's MD4 equals the stored
# unicodePwd NT hash for every gMSA and dMSA tested.
_GMSA_SECURITY_DESCRIPTOR: bytes = bytes.fromhex("010004803000000000000000000000001400000002001c0001000000000014009f011200010100000000000509000000010100000000000512000000")


@dataclass(frozen=True)
class KdsRootKey:
    """Raw KDS root-key material needed to derive GKDI keys offline.

    Mirrors the relevant ``msKds-ProvRootKey`` attributes.  All byte fields are
    the raw attribute values (not the hex/XML-decoded forms surfaced by the KDS
    decoder), because dpapi-ng's KDF consumes them verbatim.

    Attributes:
        guid: The root key id (the object's ``cn``, a GUID string).
        root_key_data: ``msKds-RootKeyData`` (the 64-byte root secret).
        kdf_parameters: ``msKds-KDFParam`` (KDFParameters structure: hash name).
        secret_agreement_parameters: ``msKds-SecretAgreementParam`` (FFC-DH params).
        private_key_length: ``msKds-PrivateKeyLength`` (bits).
        public_key_length: ``msKds-PublicKeyLength`` (bits).

    """

    guid: str
    root_key_data: bytes
    kdf_parameters: bytes
    secret_agreement_parameters: bytes
    private_key_length: int
    public_key_length: int


def build_kds_cache(root_keys: Iterable[KdsRootKey]) -> dpapi_ng.KeyCache:
    """Build a dpapi-ng key cache from KDS root keys read out of NTDS.dit.

    Args:
        root_keys: Iterable of :class:`KdsRootKey` carrying raw root-key material.

    Returns:
        A :class:`dpapi_ng.KeyCache` preloaded with every usable root key, ready
        to decrypt DPAPI-NG blobs offline without any RPC call.

    """
    cache = dpapi_ng.KeyCache()
    for rk in root_keys:
        try:
            cache.load_key(
                key=rk.root_key_data,
                root_key_id=uuid.UUID(rk.guid),
                kdf_parameters=rk.kdf_parameters,
                secret_parameters=rk.secret_agreement_parameters,
                private_key_length=rk.private_key_length,
                public_key_length=rk.public_key_length,
            )
        except (KeyError, ValueError, TypeError):  # fmt: skip
            logger.debug("Failed to load KDS root key %s", rk.guid, exc_info=True)
    return cache


def decrypt_dpapi_ng(blob: bytes, cache: dpapi_ng.KeyCache) -> bytes | None:
    """Decrypt a DPAPI-NG CMS ``EnvelopedData`` blob offline.

    Args:
        blob: The DPAPI-NG blob (CMS portion, LAPS timestamp header stripped).
        cache: A cache preloaded by :func:`build_kds_cache`.

    Returns:
        The decrypted plaintext, or ``None`` if no cached root key can decrypt it
        (or the blob is malformed).

    """
    try:
        return dpapi_ng.ncrypt_unprotect_secret(blob, cache=cache)
    except (ValueError, KeyError, NotImplementedError, IndexError, struct.error):  # fmt: skip
        logger.debug("DPAPI-NG decryption failed", exc_info=True)
        return None


def derive_gmsa_password(root_keys: Sequence[KdsRootKey], managed_password_id: bytes, sid: str) -> bytes | None:
    """Derive a gMSA/dMSA managed password offline from the domain's KDS root key.

    Reproduces the DC's managed-password generation: the MS-GKDI L0->L1->L2
    group-key derivation (the L1 seed mixes in the fixed gMSA target security
    descriptor) followed by the "GMSA PASSWORD" KDF keyed on the account SID.
    The result is the 256-byte managed password whose MD4 is the account's
    stored ``unicodePwd`` NT hash -- which lets the caller self-verify.

    Args:
        root_keys: The domain's KDS root keys (see ``NTDSDatabase.kds_root_keys``).
        managed_password_id: The ``msDS-ManagedPasswordId`` KeyIdentifier blob
            (L0/L1/L2 indices + root key GUID).
        sid: The account's ``objectSid`` string.

    Returns:
        The 256-byte managed password, or ``None`` if the root key is unknown or
        the inputs are malformed.

    """
    if len(managed_password_id) < _KEY_IDENTIFIER_MIN_LENGTH:
        return None
    try:
        l0, l1, l2 = struct.unpack_from("<iii", managed_password_id, 12)
        root_guid = managed_password_id[24:_KEY_IDENTIFIER_MIN_LENGTH]
        guid_str = str(uuid.UUID(bytes_le=root_guid))
        root_key = next((rk for rk in root_keys if rk.guid == guid_str), None)
        if root_key is None:
            logger.debug("No KDS root key %s for managed-password derivation", guid_str)
            return None
        hash_algo = _kdf_hash_algorithm(root_key.kdf_parameters)
        sid_bytes = _sid_string_to_bytes(sid)
    except (ValueError, struct.error):  # fmt: skip
        logger.debug("Malformed managed-password derivation inputs", exc_info=True)
        return None

    # L0 seed, then the L1 seed at index 31 (which mixes in the gMSA target SD).
    l0_key = _kbkdf(hash_algo, root_key.root_key_data, _kdf_context(root_guid, l0, -1, -1), 64)
    l1_key = _kbkdf(hash_algo, l0_key, _kdf_context(root_guid, l0, _L_INDEX_MAX, -1) + _GMSA_SECURITY_DESCRIPTOR, 64)
    # Descend the L1 tree from 31 to the requested index, then seed and descend L2.
    index = _L_INDEX_MAX
    while index != l1:
        index -= 1
        l1_key = _kbkdf(hash_algo, l1_key, _kdf_context(root_guid, l0, index, -1), 64)
    l2_key = _kbkdf(hash_algo, l1_key, _kdf_context(root_guid, l0, l1, _L_INDEX_MAX), 64)
    index = _L_INDEX_MAX
    while index != l2:
        index -= 1
        l2_key = _kbkdf(hash_algo, l2_key, _kdf_context(root_guid, l0, l1, index), 64)
    # The managed password is the "GMSA PASSWORD" KDF over the L2 group key, SID as context.
    return _kbkdf(hash_algo, l2_key, sid_bytes, _MANAGED_PASSWORD_LENGTH, label=_GMSA_PASSWORD_LABEL)


def _kbkdf(hash_module: ModuleType, secret: bytes, context: bytes, length: int, label: bytes = _KDS_SERVICE_LABEL) -> bytes:
    """SP800-108 counter-mode HMAC KDF (the primitive GKDI uses at every step).

    Implemented directly rather than via a library helper: the GKDI fixed input
    ``counter || label || 0x00 || context || L`` carries null bytes in the
    context (the root-key GUID and signed level indices), which the stock
    ``SP800_108_Counter`` rejects.
    """
    length_bits = (length * 8).to_bytes(4, byteorder="big")
    output = bytearray()
    counter = 1
    while len(output) < length:
        block = HMAC.new(secret, counter.to_bytes(4, byteorder="big") + label + b"\x00" + context + length_bits, hash_module).digest()
        output += block
        counter += 1
    return bytes(output[:length])


def _kdf_context(root_guid: bytes, l0: int, l1: int, l2: int) -> bytes:
    """Build the GKDI KDF context: root key GUID + signed little-endian L0/L1/L2 (-1 = unused)."""
    return root_guid + struct.pack("<iii", l0, l1, l2)


def _kdf_hash_algorithm(kdf_parameters: bytes) -> ModuleType:
    """Extract the KDF hash module from a ``msKds-KDFParam`` (KDFParameters) blob."""
    hash_len = struct.unpack_from("<I", kdf_parameters, _KDF_HASH_LEN_OFFSET)[0]
    name = kdf_parameters[_KDF_HASH_NAME_OFFSET : _KDF_HASH_NAME_OFFSET + hash_len].decode("utf-16-le").rstrip("\x00")
    return _HASH_BY_NAME.get(name, SHA512)


def _sid_string_to_bytes(sid: str) -> bytes:
    """Serialize an ``S-1-5-...`` SID string to its binary form ([MS-DTYP] 2.4.2.2)."""
    parts = sid.split("-")
    data = bytearray(int(parts[2]).to_bytes(8, byteorder="big"))  # 48-bit authority in the trailing 6 bytes
    data[0] = int(parts[1])  # revision
    data[1] = len(parts) - 3  # sub-authority count
    for sub_authority in parts[3:]:
        data += int(sub_authority).to_bytes(4, byteorder="little")
    return bytes(data)
