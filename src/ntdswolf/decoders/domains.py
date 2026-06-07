"""Decoder for domainDNS objectClass.

The domainDNS object is the root of each AD domain naming context and
holds domain-wide policy settings: password policy (complexity, length,
age, history), lockout policy (threshold, duration, observation window),
and the domain functional level (msDS-Behavior-Version).

Duration attributes (maxPwdAge, minPwdAge, lockoutDuration, etc.) are
stored as negative 64-bit FILETIME intervals and converted to
human-readable strings by this decoder.

Per [MS-ADTS] section 3.1.1.5 (Domain Object).

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from typing_extensions import override

from ntdswolf.decoders.base import BaseDecoder, DecoderContext

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject
from ntdswolf.models.flags import PwdProperties

logger = logging.getLogger(__name__)


class DomainDecoder(BaseDecoder):
    """Decoder for ``domainDNS`` objectClass.

    Extracts domain functional level, password policy, and lockout policy
    attributes from the domain root object.
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract domain-specific attributes.

        Per [MS-ADTS] section 3.1.1.5 and section 3.1.1.5.2.5
        (Password Policy / Lockout Policy).
        """
        # --- Domain functional level ---
        # msDS-Behavior-Version determines the domain functional level:
        # 0 = WS2000, 1 = WS2003 interim, 2 = WS2003, 3 = WS2008,
        # 4 = WS2008 R2, 5 = WS2012, 6 = WS2012 R2, 7 = WS2016.
        # Per [MS-ADTS] section 6.1.4.2.
        result["msDS-Behavior-Version"] = self._get_attr(obj, "msDS-Behavior-Version")

        # --- Password policy ---
        result["minPwdLength"] = self._get_attr(obj, "minPwdLength")

        # maxPwdAge and minPwdAge are negative FILETIME intervals (100-ns units).
        # A value of 0 means "not set" (no maximum/minimum age).
        # Per [MS-ADTS] section 3.1.1.5.2.5.
        result["maxPwdAge"] = self._decode_interval(self._get_attr(obj, "maxPwdAge"))
        result["minPwdAge"] = self._decode_interval(self._get_attr(obj, "minPwdAge"))

        # --- Lockout policy ---
        result["lockoutThreshold"] = self._get_attr(obj, "lockoutThreshold")

        # lockoutDuration and lockoutObservationWindow are also negative intervals.
        result["lockoutDuration"] = self._decode_interval(self._get_attr(obj, "lockoutDuration"))
        result["lockoutObservationWindow"] = self._decode_interval(self._get_attr(obj, "lockoutObservationWindow"))

        # --- Password properties flags ---
        # pwdProperties is a bitmask controlling complexity requirements,
        # reversible encryption, etc.
        # Per [MS-ADTS] section 3.1.1.5.2.5.
        pwd_props_raw = self._get_attr(obj, "pwdProperties")
        result["pwdProperties"] = self._decode_flags_field(pwd_props_raw, PwdProperties)

        # --- Password history length ---
        result["pwdHistoryLength"] = self._get_attr(obj, "pwdHistoryLength")
