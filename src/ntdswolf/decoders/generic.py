"""Generic fallback decoder for unknown or unregistered object classes.

When the DecoderRegistry encounters an objectClass it does not have a
specialised decoder for, it falls back to GenericDecoder.  This decoder
iterates all attributes on the record, decodes each according to its
type (string, integer, bytes, datetime), and outputs them using their
LDAP display name (or ATT column name if schema lookup fails).

This ensures no data is silently dropped for unrecognised object types.
The output is less structured than specialised decoders but captures
everything the record contains.

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from typing_extensions import override

from ntdswolf.decoders.base import BaseDecoder, DecoderContext

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject

logger = logging.getLogger(__name__)


class GenericDecoder(BaseDecoder):
    """Fallback decoder for AD objects without a specialised decoder.

    Iterates every attribute on the record and includes it in the output
    dict, using type-appropriate encoding (hex for bytes, ISO 8601 for
    timestamps, etc.).  This is the safety net that guarantees all data
    is captured even for uncommon object classes.
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Iterate all record attributes and decode each by type.

        Uses ``obj.as_dict()`` to get all attributes with their LDAP names.
        Falls back to raw column iteration if ``as_dict()`` is unavailable.
        """
        try:
            # as_dict() returns {ldap_name: decoded_value} for all attributes
            attrs = obj.as_dict()
        except (AttributeError, TypeError, ValueError):  # fmt: skip
            logger.debug(
                "as_dict() unavailable for object DNT=%s, skipping generic attribute extraction",
                self._get_attr(obj, "DNT", default="?"),
            )
            return

        if not isinstance(attrs, dict):
            return

        for attr_name, attr_value in attrs.items():
            # Skip attributes already handled by _decode_common_attrs
            if attr_name in _COMMON_ATTR_NAMES:
                continue

            # Skip None values to keep output clean
            if attr_value is None:
                continue

            # Skip empty lists (multi-valued attributes with no values)
            if isinstance(attr_value, list) and not attr_value:
                continue

            # Encode the value to a JSON-compatible type
            encoded = _encode_value(attr_value)
            if encoded is not None:
                result[attr_name] = encoded


# Attribute names already extracted by BaseDecoder._decode_common_attrs.
# GenericDecoder skips these to avoid duplication in the output.
_COMMON_ATTR_NAMES: frozenset[str] = frozenset(
    {
        "objectClass",
        "DNT",
        "Pdnt",
        "Ncdnt",
        "distinguishedName",
        "objectGUID",
        "objectSid",
        "name",
        "whenCreated",
        "whenChanged",
        "isDeleted",
        "isRecycled",
        "lastKnownParent",
        "instanceType",
        "nTSecurityDescriptor",
        "replPropertyMetaData",
        # Internal ESE columns that are not useful in output
        "Ancestors",
        "cnt",
        "RDNtyp",
        "NCDNT",
        "ATTb590606",
    }
)


def _encode_value(value: object) -> object:
    """Encode a single attribute value to a JSON-compatible type.

    Handles bytes, datetimes, UUIDs, lists, enums, and nested objects
    with to_dict() methods.  Returns None for unrepresentable types.
    """
    if value is None:
        return None

    # Bytes -> hex string
    if isinstance(value, bytes | bytearray):
        return value.hex()

    # Well-known types with direct string conversions
    if isinstance(value, datetime):
        return value.isoformat()

    # Primitive types and UUIDs pass through (UUID has a useful __str__)
    if isinstance(value, str | int | float | bool | UUID):
        return str(value) if isinstance(value, UUID) else value

    # Lists -> encode each element
    if isinstance(value, list):
        return [v for v in (_encode_value(item) for item in value) if v is not None]

    return _encode_complex_value(value)


def _encode_complex_value(value: object) -> object:
    """Encode an object that is not a primitive, bytes, datetime, UUID, or list.

    Tries enum-like .name/.value, then .to_dict(), then falls back to str().
    """
    # Enum types -> use name or value
    if hasattr(value, "name") and hasattr(value, "value"):
        return str(value)

    # Objects with to_dict() -> delegate
    if hasattr(value, "to_dict"):
        try:
            return cast("Any", value).to_dict()
        except (AttributeError, ValueError, TypeError):  # fmt: skip
            return str(value)

    # String fallback
    return str(value)
