# SPDX-License-Identifier: Apache-2.0
"""Generic fallback decoder for unknown or unregistered object classes.

When the DecoderRegistry encounters an objectClass it has no specialised
decoder for, it falls back to GenericDecoder. This decoder adds no
class-specific fields of its own: ``BaseDecoder`` extracts the common
attributes, and the base ``_passthrough`` captures every remaining stored and
linked attribute under ``_unmapped`` -- the same robust, per-attribute,
internals-excluding path every class uses. That guarantees no data is dropped
for unrecognised classes while keeping their output shape identical to the
specialised decoders (previously this decoder dumped a flat raw ``as_dict()``,
which leaked dissect's internal columns and aborted on a single undecodable
attribute).

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from typing_extensions import override

from ntdswolf.decoders.base import BaseDecoder

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject

    from ntdswolf.decoders.base import DecoderContext


class GenericDecoder(BaseDecoder):
    """Fallback decoder for AD objects without a specialised decoder.

    Adds no class-specific fields; the common-attribute extraction and the raw
    passthrough in ``BaseDecoder`` capture everything the record contains.
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """No class-specific fields: the base ``_passthrough`` captures all attributes under ``_unmapped``."""
