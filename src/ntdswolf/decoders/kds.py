# SPDX-License-Identifier: Apache-2.0
"""Decoder for msKds-ProvRootKey objectClass.

KDS root keys are the cryptographic foundation of the Group Key
Distribution Protocol (GKDI).  They are stored under
``CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services``
in the configuration naming context.

Each root key contains raw key material, creation/activation timestamps,
and XML-encoded key derivation function (KDF) parameters.  The managed
passwords for gMSAs and LAPS v2 are derived from these keys using a
hierarchical key tree (L0 -> L1 -> L2 -> managed password).

Per [MS-GKDI] section 3.1.4.1 (Key Derivation).

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

from typing_extensions import override

from ntdswolf.decoders.base import BaseDecoder, DecoderContext, decode_filetime

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject

logger = logging.getLogger(__name__)


class KDSDecoder(BaseDecoder):
    """Decoder for ``msKds-ProvRootKey`` objectClass.

    Extracts root key data, creation/use-start timestamps, and KDF
    parameters needed for GKDI key derivation.
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract KDS root key-specific attributes.

        Per [MS-GKDI] section 2.2 and [MS-ADA2] for attribute schemas.
        """
        # --- Root key data ---
        # msKds-RootKeyData is the raw key material (typically 64 bytes)
        # used as input to the hierarchical key derivation.
        root_key_data = self._get_attr(obj, "msKds-RootKeyData", raw=True)
        if root_key_data is not None and isinstance(root_key_data, bytes):
            result["msKds-RootKeyData"] = root_key_data.hex()
        else:
            result["msKds-RootKeyData"] = None

        # --- Creation timestamp ---
        # msKds-CreateTime records when the root key was generated.
        create_time = self._get_attr(obj, "msKds-CreateTime")
        result["msKds-CreateTime"] = _format_kds_timestamp(create_time)

        # --- Use-start timestamp ---
        # msKds-UseStartTime is the earliest time the root key is allowed
        # to be used for key derivation.  This is typically 10 hours after
        # creation to allow for replication across all DCs.
        # Per [MS-GKDI] section 3.1.4.1.
        use_start_time = self._get_attr(obj, "msKds-UseStartTime")
        result["msKds-UseStartTime"] = _format_kds_timestamp(use_start_time)

        # --- KDF parameters ---
        # msKds-KDFParam is an XML blob specifying the KDF algorithm and
        # parameters (typically SP800-108 HMAC-SHA256).
        kdf_param = self._get_attr(obj, "msKds-KDFParam", raw=True)
        if kdf_param is not None and isinstance(kdf_param, bytes):
            # Try to decode as UTF-16LE or UTF-8 (AD stores XML as UTF-16LE)
            result["msKds-KDFParam"] = _try_decode_xml(kdf_param)
        else:
            result["msKds-KDFParam"] = None

        # --- Remaining attributes ---
        self._decode_kds_extra_attrs(obj, result)

    def _decode_kds_extra_attrs(self, obj: DissectObject, result: dict[str, Any]) -> None:
        """Extract secondary KDS root key attributes."""
        # --- KDF algorithm name ---
        kdf_algo = self._get_attr(obj, "msKds-KDFAlgorithmID")
        if kdf_algo is not None:
            result["msKds-KDFAlgorithmID"] = str(kdf_algo)

        # --- Secret agreement parameters ---
        # msKds-SecretAgreementParam is an XML blob specifying the secret
        # agreement algorithm (typically DH).
        sa_param = self._get_attr(obj, "msKds-SecretAgreementParam", raw=True)
        if sa_param is not None and isinstance(sa_param, bytes):
            result["msKds-SecretAgreementParam"] = _try_decode_xml(sa_param)

        # --- Secret agreement algorithm name ---
        sa_algo = self._get_attr(obj, "msKds-SecretAgreementAlgorithmID")
        if sa_algo is not None:
            result["msKds-SecretAgreementAlgorithmID"] = str(sa_algo)

        # --- Key lengths ---
        private_key_len = self._get_attr(obj, "msKds-PrivateKeyLength")
        if private_key_len is not None:
            result["msKds-PrivateKeyLength"] = int(private_key_len)

        public_key_len = self._get_attr(obj, "msKds-PublicKeyLength")
        if public_key_len is not None:
            result["msKds-PublicKeyLength"] = int(public_key_len)

        # --- Version ---
        version = self._get_attr(obj, "msKds-Version")
        if version is not None:
            result["msKds-Version"] = int(version)

        # --- Domain ID ---
        # msKds-DomainID is the DN of the domain this root key belongs to.
        domain_id = self._get_attr(obj, "msKds-DomainID")
        if domain_id is not None:
            result["msKds-DomainID"] = str(domain_id)


def _format_kds_timestamp(value: object) -> str | None:
    """Format a KDS timestamp attribute to ISO 8601.

    KDS timestamps may be returned as datetime objects by dissect,
    or as raw FILETIME integers.

    Args:
        value: datetime, int, or None.

    Returns:
        ISO 8601 string, or None.

    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    # Raw FILETIME or other type
    return decode_filetime(value)


def _try_decode_xml(data: bytes) -> str:
    """Attempt to decode an XML blob as UTF-16LE, then UTF-8, then hex.

    AD stores KDF parameter XML as UTF-16LE encoded strings.  This
    function tries the most likely encoding first, then falls back.

    Args:
        data: Raw bytes of the XML attribute.

    Returns:
        Decoded XML string, or hex representation on failure.

    """
    # Try UTF-16LE first (most common for AD XML attributes)
    try:
        decoded = data.decode("utf-16-le").rstrip("\x00")
        if decoded and ("<" in decoded or "?" in decoded):
            return decoded
    except (UnicodeDecodeError, ValueError):  # fmt: skip
        pass

    # Try UTF-8
    try:
        decoded = data.decode("utf-8").rstrip("\x00")
        if decoded and ("<" in decoded or "?" in decoded):
            return decoded
    except (UnicodeDecodeError, ValueError):  # fmt: skip
        pass

    # Fall back to hex
    return data.hex()
