"""Decoder for msFVE-RecoveryInformation objectClass.

BitLocker recovery keys are stored as child objects under the computer
account they protect.  Each msFVE-RecoveryInformation object holds the
48-digit numerical recovery password, the volume GUID identifying which
encrypted volume the key belongs to, and optionally a binary key package
for raw key recovery.

These objects are not PEK-encrypted -- the recovery password is stored
in plaintext within the AD attribute.  Access control is enforced via
the nTSecurityDescriptor on the object and its parent container.

Per [MS-FVE] section 2.2 (Recovery Information).

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from typing_extensions import override

from ntdswolf.decoders.base import BaseDecoder, DecoderContext

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject

logger = logging.getLogger(__name__)


class BitLockerDecoder(BaseDecoder):
    """Decoder for ``msFVE-RecoveryInformation`` objectClass.

    Extracts the recovery password, volume GUID, and key package.
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract BitLocker recovery-specific attributes.

        Per [MS-FVE] section 2.2 and [MS-ADA2] for individual attribute schemas.
        """
        # --- Recovery password ---
        # msFVE-RecoveryPassword is the 48-digit numerical password
        # (e.g., "123456-789012-345678-901234-567890-123456-789012-345678").
        # Stored as a plaintext string attribute.
        result["msFVE-RecoveryPassword"] = self._get_attr(obj, "msFVE-RecoveryPassword")

        # --- Volume GUID ---
        # msFVE-VolumeGuid identifies which BitLocker-encrypted volume
        # this recovery key belongs to.  Stored as a 16-byte binary GUID.
        volume_guid_raw = self._get_attr(obj, "msFVE-VolumeGuid", raw=True)
        if volume_guid_raw is not None:
            result["msFVE-VolumeGuid"] = self._decode_guid(volume_guid_raw)
        else:
            # Try the decoded version
            volume_guid = self._get_attr(obj, "msFVE-VolumeGuid")
            if volume_guid is not None:
                result["msFVE-VolumeGuid"] = str(volume_guid)

        # --- Recovery GUID ---
        # msFVE-RecoveryGuid is a secondary GUID for the recovery entry itself.
        recovery_guid_raw = self._get_attr(obj, "msFVE-RecoveryGuid", raw=True)
        if recovery_guid_raw is not None:
            result["msFVE-RecoveryGuid"] = self._decode_guid(recovery_guid_raw)
        else:
            recovery_guid = self._get_attr(obj, "msFVE-RecoveryGuid")
            if recovery_guid is not None:
                result["msFVE-RecoveryGuid"] = str(recovery_guid)

        # --- Key package ---
        # msFVE-KeyPackage is an optional binary blob for raw key recovery.
        # It contains the Full Volume Encryption Key (FVEK) wrapped in a
        # key protector.  Only present if the admin configured key package
        # backup.
        key_package = self._get_attr(obj, "msFVE-KeyPackage", raw=True)
        if key_package is not None and isinstance(key_package, bytes):
            result["msFVE-KeyPackage"] = key_package.hex()
        elif key_package is not None:
            result["msFVE-KeyPackage"] = str(key_package)
