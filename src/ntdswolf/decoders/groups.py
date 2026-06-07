"""Decoder for group objectClass.

Groups are security principals that aggregate other principals via the
``member`` forward link.  Membership is stored in the ESE link_table
rather than as an inline attribute, so resolving members requires the
LinkResolver dependency.

The ``memberOf`` backlinks give the groups this group is nested into.

Per [MS-ADTS] section 3.1.1.5.3 (Group Object).

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from typing_extensions import override

from ntdswolf.decoders.base import BaseDecoder, DecoderContext

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject
from ntdswolf.models.flags import GroupType

logger = logging.getLogger(__name__)


class GroupDecoder(BaseDecoder):
    """Decoder for ``group`` objectClass.

    Extracts sAMAccountName, groupType, adminCount, description, and
    resolves both the member list (forward links) and memberOf list
    (backlinks).
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract group-specific attributes.

        Per [MS-ADA3] section 2.284 (sAMAccountName) and
        [MS-ADTS] section 2.2.12 (groupType).
        """
        # --- Identity ---
        result["sAMAccountName"] = self._get_attr(obj, "sAMAccountName")

        # --- Group type flags ---
        # groupType is a bitmask combining scope (global/domain-local/universal)
        # with the SECURITY_ENABLED bit.  Per [MS-ADTS] section 2.2.12.
        group_type_raw = self._get_attr(obj, "groupType")
        result["groupType"] = self._decode_flags_field(group_type_raw, GroupType)

        # --- Admin count ---
        # adminCount == 1 indicates the group is (or was) protected by AdminSDHolder.
        result["adminCount"] = self._get_attr(obj, "adminCount")

        # --- Description ---
        result["description"] = self._get_attr(obj, "description")

        # --- Membership: dissect resolves member (forward) and memberOf (back) ---
        if ctx.include_links:
            result["member"] = self._resolve_links(obj, "member", forward=True)
            result["memberOf"] = self._resolve_links(obj, "memberOf", forward=False)
        else:
            result["member"] = []
            result["memberOf"] = []
