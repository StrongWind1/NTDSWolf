# SPDX-License-Identifier: Apache-2.0
"""Decoder for groupPolicyContainer objectClass.

GPO objects represent Group Policy Objects stored in AD.  Each GPO has a
display name, a UNC path to its SYSVOL file system data, a version number
encoding both user and computer policy revision, and lists of Client-Side
Extension (CSE) GUIDs that determine which policy processors apply.

Per [MS-GPOL] section 2.3 (Group Policy Container).

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


class GPODecoder(BaseDecoder):
    """Decoder for ``groupPolicyContainer`` objectClass.

    Extracts displayName, SYSVOL path, version number, and CSE GUID lists.
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract GPO-specific attributes.

        Per [MS-GPOL] section 2.3 and [MS-ADA1] for individual attributes.
        """
        # --- Display name ---
        result["displayName"] = self._get_attr(obj, "displayName")

        # --- SYSVOL path ---
        # gPCFileSysPath is the UNC path to the GPO's SYSVOL data
        # (e.g., "\\\\domain.local\\SysVol\\domain.local\\Policies\\{GUID}").
        result["gPCFileSysPath"] = self._get_attr(obj, "gPCFileSysPath")

        # --- Version number ---
        # Encodes both user and computer version in a single DWORD:
        # - High 16 bits: user version
        # - Low 16 bits: computer version
        # Per [MS-GPOL] section 2.3.
        version = self._get_attr(obj, "versionNumber")
        if version is not None:
            version_int = int(version) if not isinstance(version, int) else version
            result["versionNumber"] = version_int
            # Also break out the user and computer versions for clarity
            result["_userVersion"] = (version_int >> 16) & 0xFFFF
            result["_computerVersion"] = version_int & 0xFFFF
        else:
            result["versionNumber"] = None

        # --- Client-Side Extension GUIDs ---
        # These are semicolon-delimited lists of GUID pairs that tell the
        # GP client which CSEs to invoke.  Format:
        # [{CSE_GUID}{Tool_GUID}][{CSE_GUID}{Tool_GUID}]...
        result["gPCMachineExtensionNames"] = self._get_attr(obj, "gPCMachineExtensionNames")
        result["gPCUserExtensionNames"] = self._get_attr(obj, "gPCUserExtensionNames")

        # --- GPO flags ---
        # 0 = enabled, 1 = user config disabled, 2 = computer config disabled,
        # 3 = all disabled.
        gpo_flags = self._get_attr(obj, "flags")
        if gpo_flags is not None:
            result["flags"] = int(gpo_flags) if not isinstance(gpo_flags, int) else gpo_flags
