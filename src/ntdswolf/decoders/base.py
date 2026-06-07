"""Base decoder and context for transforming raw NTDS.dit records into dicts.

Every decoder subclass inherits from BaseDecoder, which implements the
template method pattern: ``decode()`` calls ``_decode_common_attrs()`` then
``_decode_specific()``.  Subclasses override ``_decode_specific()`` to handle
class-specific attributes (user fields, group membership, trust credentials,
etc.).

The DecoderContext dataclass bundles all external dependencies a decoder
might need during the decode pass -- schema info, PEK list, link resolver,
DN cache, security descriptor cache, and config flags.

Import rules: decoders import from crypto/, models/, constants ONLY.
Never from core/, cli/, output/.
"""

from __future__ import annotations

import io
import logging
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.database.ese.ntds.sd import SecurityDescriptor

from ntdswolf.constants import NEVER_EXPIRES, NEVER_EXPIRES_ALT, SID_RSPLIT_PART_COUNT, TIMESTAMP_NOT_SET, UUID_BYTE_LENGTH
from ntdswolf.crypto.structures import cs
from ntdswolf.decoders.sddl import to_sddl
from ntdswolf.models.flags import InstanceType, decode_flags

if TYPE_CHECKING:
    from enum import IntFlag

    from dissect.database.ese.ntds.objects import Object as DissectObject
    from dpapi_ng import KeyCache

    from ntdswolf.crypto.gkdi import KdsRootKey
    from ntdswolf.crypto.pek import PekDecryptor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Windows FILETIME epoch offset
# ---------------------------------------------------------------------------

# Number of 100-nanosecond intervals between the Windows FILETIME epoch
# (1601-01-01 00:00:00 UTC) and the Unix epoch (1970-01-01 00:00:00 UTC).
# Used by _decode_filetime() to convert FILETIME integers to Python datetimes.
_FILETIME_EPOCH_DELTA: int = 116_444_736_000_000_000

# replPropertyMetaData header size: dwVersion + dwReserved + cNumProps + dwReserved2
# (4 x DWORD = 16 bytes); cNumProps is at offset 8. Per [MS-DRSR] section 4.1.10.2.11.
_REPLMD_HEADER_SIZE: int = 16

# replPropertyMetaData stores the originating change time as a DSTIME (seconds
# since 1601-01-01 UTC); FILETIME counts 100-ns units, so multiply to convert.
_DSTIME_TO_FILETIME: int = 10_000_000


# ---------------------------------------------------------------------------
# DecoderContext -- everything a decoder needs during a decode pass
# ---------------------------------------------------------------------------


@dataclass
class DecoderContext:
    """Bundle of dependencies injected into decoders at decode time.

    Keeps decoder classes decoupled from the core orchestration layer.
    Each field corresponds to a subsystem that decoders may (but need not)
    use depending on the object class being decoded.
    """

    pek_list: PekDecryptor | None = None  # PEK that decrypts credential attributes (dissect PEK in production; None if boot key unavailable)
    kds_cache: KeyCache | None = None  # dpapi-ng key cache for offline LAPS v2 / GKDI decryption; None when no KDS root keys are present
    kds_root_keys: list[KdsRootKey] = field(default_factory=list)  # raw KDS root keys for offline gMSA/dMSA managed-password derivation

    # --- Config flags ---
    include_deleted: bool = False  # Whether to include tombstoned objects
    include_credentials: bool = True  # Whether to decrypt and include credential material
    include_links: bool = True  # Whether to resolve and include linked attributes
    naming: str = "dn"  # Preferred identifier for the _name field: "dn", "sam", or "cn"

    # --- Error accumulator ---
    errors: list[str] = field(default_factory=list)  # Non-fatal errors encountered during decode


# ---------------------------------------------------------------------------
# BaseDecoder -- template method for all object decoders
# ---------------------------------------------------------------------------


class BaseDecoder(ABC):
    """Abstract base class for all NTDS.dit object decoders.

    Provides the template method ``decode()`` which extracts common AD
    attributes shared by all object classes, then delegates to
    ``_decode_specific()`` for class-specific fields.

    The record object comes from dissect.database and provides:
    - ``obj.get("attrName")`` for LDAP attribute access via schema lookup
    - ``obj.dnt`` for the object's Directory Number Tag
    - ``obj.name`` for the RDN
    - ``obj.object_class`` for the objectClass list

    Note: All methods accepting ``obj`` use ``DissectObject`` which is the
    base Object class from dissect.database.ese.ntds.objects.  The
    ``_get_attr()`` helper provides safe access regardless of the concrete type.
    """

    def decode(self, obj: DissectObject, ctx: DecoderContext) -> dict[str, Any]:
        """Decode a dissect Object into a flat dict matching the JSON output schema.

        This is the main entry point called by the extraction pipeline.
        It first extracts attributes common to all AD objects, then calls
        ``_decode_specific()`` for class-specific attributes.

        Args:
            obj: A dissect.database Object instance.
            ctx: DecoderContext with dependencies and config.

        Returns:
            Dictionary ready for JSON serialisation.

        """
        result: dict[str, Any] = {}

        try:
            # Common attributes shared by every AD object class
            self._decode_common_attrs(obj, result)

            # Class-specific attributes (implemented by subclasses)
            self._decode_specific(obj, ctx, result)

            # Preferred display name per the configured naming convention
            self._apply_naming(result, ctx.naming)
        except (AttributeError, ValueError, KeyError, TypeError, struct.error, UnicodeDecodeError, LookupError, OSError):  # fmt: skip
            # Record the error but still return whatever we managed to decode
            dnt = self._get_attr(obj, "DNT", default="unknown")
            logger.exception("Error decoding object DNT=%s", dnt)
            ctx.errors.append(f"Failed to fully decode object DNT={dnt}")

        return result

    def _decode_common_attrs(self, obj: DissectObject, result: dict[str, Any]) -> None:
        """Extract attributes present on every AD object regardless of class.

        Populates _object_class, _dnt, distinguishedName, objectGUID,
        objectSid, name, whenCreated, whenChanged, isDeleted, instanceType,
        and nTSecurityDescriptor.

        Per [MS-ADTS] section 3.1.1.2 (Object Model).
        """
        # --- Synthetic fields for identification ---
        object_class = self._get_attr(obj, "objectClass")
        # objectClass is a multi-valued attribute; the first value is the most specific class
        if isinstance(object_class, list) and object_class:
            result["_object_class"] = object_class[0]
        elif isinstance(object_class, str):
            result["_object_class"] = object_class
        else:
            result["_object_class"] = "unknown"

        result["_dnt"] = self._get_attr(obj, "DNT", default=0)

        # --- Distinguished name ---
        dn = self._get_attr(obj, "distinguishedName")
        result["distinguishedName"] = str(dn) if dn is not None else None

        # --- objectGUID -- binary UUID. Per [MS-DTYP] section 2.3.4. ---
        raw_guid = self._get_attr(obj, "objectGUID", raw=True)
        if raw_guid is not None:
            result["objectGUID"] = self._decode_guid(raw_guid)
        else:
            # Try the decoded version (dissect may return a UUID object)
            guid_val = self._get_attr(obj, "objectGUID")
            if guid_val is not None:
                result["objectGUID"] = str(guid_val)

        # --- objectSid -- dissect decodes the binary SID to its S-1-... string
        # (including the big-endian RID), so we surface it directly. ---
        sid_val = self._get_attr(obj, "objectSid")
        if sid_val is not None:
            result["objectSid"] = str(sid_val)

        # --- Simple scalar attributes ---
        result["name"] = self._get_attr(obj, "name")

        # --- Timestamps ---
        self._decode_common_timestamps(obj, result)

        # --- Deletion markers (tombstones) ---
        result["isDeleted"] = bool(self._get_attr(obj, "isDeleted"))
        if self._get_attr(obj, "isRecycled"):
            result["isRecycled"] = True
        last_known_parent = self._get_attr(obj, "lastKnownParent")
        if last_known_parent is not None:
            result["lastKnownParent"] = str(last_known_parent)

        # --- instanceType bitmask. Per [MS-ADTS] section 3.1.1.2.4.8. ---
        instance_type = self._get_attr(obj, "instanceType")
        if instance_type is not None:
            raw_val = int(instance_type) if not isinstance(instance_type, int) else instance_type
            result["instanceType"] = decode_flags(raw_val, InstanceType)

        # --- Security descriptor (SDDL) ---
        self._decode_common_sd(obj, result)

        # --- Replication metadata ---
        self._decode_replication_metadata(obj, result)

    def _decode_common_timestamps(self, obj: DissectObject, result: dict[str, Any]) -> None:
        """Extract whenCreated and whenChanged timestamps."""
        when_created = self._get_attr(obj, "whenCreated")
        result["whenCreated"] = when_created.isoformat() if isinstance(when_created, datetime) else self._to_str_or_none(when_created)

        when_changed = self._get_attr(obj, "whenChanged")
        result["whenChanged"] = when_changed.isoformat() if isinstance(when_changed, datetime) else self._to_str_or_none(when_changed)

    def _decode_common_sd(self, obj: DissectObject, result: dict[str, Any]) -> None:
        """Serialize the object's security descriptor to SDDL.

        dissect parses ``nTSecurityDescriptor`` into a structured SecurityDescriptor
        (``obj.sd``); we convert it to an SDDL string per [MS-DTYP] section 2.5.1.
        """
        try:
            sd = obj.sd
        except (AttributeError, ValueError, KeyError, TypeError, struct.error, EOFError):  # fmt: skip
            return
        if sd is None:
            return
        try:
            result["nTSecurityDescriptor"] = to_sddl(sd)
        except (AttributeError, ValueError, TypeError):  # fmt: skip
            logger.debug("Failed to serialize security descriptor to SDDL", exc_info=True)

    def _decode_replication_metadata(self, obj: DissectObject, result: dict[str, Any]) -> None:
        """Parse replPropertyMetaData into per-attribute replication stamps.

        Per [MS-DRSR] section 4.1.10.2.11: a header (version, count) followed by
        one entry per replicated attribute carrying its version, originating
        change time / DSA / USN, and local USN.
        """
        raw = self._get_attr(obj, "replPropertyMetaData", raw=True)
        if not isinstance(raw, bytes) or len(raw) < _REPLMD_HEADER_SIZE:
            return
        try:
            header = cs.REPLMD_HEADER(raw)
            entries = cs.REPLMD_ENTRY[header.cNumEntries](raw[_REPLMD_HEADER_SIZE:])
        except (ValueError, EOFError, struct.error):  # fmt: skip
            logger.debug("Failed to parse replPropertyMetaData", exc_info=True)
            return
        meta = [
            {
                "attribute": self._resolve_attr_name(obj, entry.AttId),
                "version": entry.Version,
                "originatingChange": decode_filetime(entry.TimeChanged * _DSTIME_TO_FILETIME),
                "originatingDSA": str(UUID(bytes_le=bytes(entry.UuidDsaOriginating))),
                "originatingUSN": entry.UsnOriginating,
                "localUSN": entry.UsnLocal,
            }
            for entry in entries
        ]
        if meta:
            result["replPropertyMetaData"] = meta

    @staticmethod
    def _resolve_attr_name(obj: DissectObject, attid: int) -> str | int:
        """Resolve an attribute id (ATTRTYP) to its LDAP name via the schema."""
        try:
            entry = obj.db.data.schema.lookup(attrtyp=attid)
        except (AttributeError, ValueError, KeyError, TypeError):  # fmt: skip
            return attid
        return entry.name if entry is not None else attid

    @staticmethod
    def _apply_naming(result: dict[str, Any], naming: str) -> None:
        """Set the ``_name`` field to the preferred identifier for *naming*.

        ``dn`` uses the distinguished name, ``sam`` the sAMAccountName, ``cn``
        the common name; each falls back to the RDN when the chosen field is
        absent.
        """
        if naming == "sam":
            result["_name"] = result.get("sAMAccountName") or result.get("name")
        elif naming == "cn":
            result["_name"] = result.get("cn") or result.get("name")
        else:
            result["_name"] = result.get("distinguishedName") or result.get("name")

    @staticmethod
    def _sd_bytes_to_sddl(raw: object) -> str | None:
        """Parse a raw security-descriptor blob and serialize it to SDDL.

        Used for attributes that embed a security descriptor (for example
        ``msDS-AllowedToActOnBehalfOfOtherIdentity``).
        """
        if not isinstance(raw, bytes) or not raw:
            return None
        try:
            return to_sddl(SecurityDescriptor(io.BytesIO(raw)))
        except (AttributeError, ValueError, TypeError, OSError, EOFError, struct.error):  # fmt: skip
            return None

    @abstractmethod
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract class-specific attributes (implemented by subclasses).

        Args:
            obj: A dissect.database Object instance.
            ctx: DecoderContext with dependencies and config.
            result: Mutable dict to populate with decoded attributes.

        """

    # --- Helper methods ---

    @staticmethod
    def _get_attr(obj: DissectObject, name: str, default: object = None, *, raw: bool = False) -> Any:  # noqa: ANN401 -- dissect attribute values are dynamically typed
        """Safely retrieve an attribute from a dissect Object.

        Catches AttributeError (attribute not in schema) and any other
        exceptions that dissect might raise for missing or corrupt data.
        Returns *default* on failure.

        Args:
            obj: A dissect.database Object instance.
            name: LDAP attribute name (e.g., "sAMAccountName") or ESE column name.
            default: Value to return if the attribute is missing or access fails.
            raw: If True, request the raw (undecoded) value from dissect.

        Returns:
            The attribute value, or *default* if unavailable.

        """
        try:
            if raw:
                return obj.get(name, raw=True)
            return obj.get(name)
        except (AttributeError, ValueError, KeyError, TypeError, struct.error):  # fmt: skip
            return default

    @staticmethod
    def _decode_guid(raw_bytes: object) -> str:
        """Convert raw bytes or a UUID object to a standard UUID string.

        dissect may already return a UUID object from its decoder, so we
        handle both cases.

        Args:
            raw_bytes: Raw 16-byte GUID in mixed-endian format, or a UUID object.

        Returns:
            Standard UUID string (lowercase, hyphenated).

        """
        if isinstance(raw_bytes, UUID):
            return str(raw_bytes)
        if isinstance(raw_bytes, bytes) and len(raw_bytes) == UUID_BYTE_LENGTH:
            # GUIDs in AD are stored in mixed-endian (bytes_le) format.
            # Per [MS-DTYP] section 2.3.4.
            return str(UUID(bytes_le=raw_bytes))
        if isinstance(raw_bytes, str):
            return raw_bytes
        return str(raw_bytes)

    @staticmethod
    def _decode_filetime(value: object) -> str | None:
        """Convert a Windows FILETIME integer to an ISO 8601 string.

        Delegates to the module-level ``decode_filetime()`` function,
        which is the canonical implementation.

        Args:
            value: Raw FILETIME integer, datetime, or None.

        Returns:
            ISO 8601 string, "never", or None.

        """
        return decode_filetime(value)

    @staticmethod
    def _decode_flags_field(value: Any, flag_class: type[IntFlag]) -> dict[str, int | list[str]] | None:  # noqa: ANN401 -- raw dissect attribute value
        """Decode a raw integer into a structured flag dictionary.

        Wraps the ``decode_flags()`` helper from the flags module, handling
        None and non-integer values gracefully.

        Args:
            value: Raw integer from the AD attribute, or None.
            flag_class: The IntFlag subclass to decode against.

        Returns:
            ``{"value": N, "flags": [...]}`` or None if value is None.

        """
        if value is None:
            return None
        raw = int(value) if not isinstance(value, int) else value
        return decode_flags(raw, flag_class)

    @staticmethod
    def _resolve_links(obj: DissectObject, attr_name: str, *, forward: bool = True) -> list[str]:
        """Resolve a linked attribute (member / memberOf) to a list of DNs.

        dissect's ``links()`` / ``backlinks()`` yield ``(attr_name, Object)``
        pairs already labeled with the LDAP attribute name (``member`` forward,
        ``memberOf`` back), so we filter by *attr_name* and return the linked DNs.

        Args:
            obj: The dissect object whose links to resolve.
            attr_name: LDAP name of the link attribute (e.g., "member", "memberOf").
            forward: If True, resolve forward links; if False, resolve back links.

        Returns:
            List of DN strings for linked objects (empty on any error).

        """
        try:
            pairs = obj.links() if forward else obj.backlinks()
            return [str(linked.dn) for name, linked in pairs if name == attr_name]
        except (AttributeError, ValueError, KeyError, TypeError, LookupError):
            logger.debug("Failed to resolve %s %s links", "forward" if forward else "back", attr_name, exc_info=True)
            return []

    @staticmethod
    def _to_str_or_none(value: object) -> str | None:
        """Convert a value to string, or None if the value is None."""
        return str(value) if value is not None else None

    @staticmethod
    def _extract_rid_from_sid(sid_str: str) -> int | None:
        """Extract the RID (last component) from a SID string.

        Args:
            sid_str: SID in "S-1-5-21-...-RID" format.

        Returns:
            Integer RID, or None if the SID format is invalid.

        """
        if not sid_str or not sid_str.startswith("S-"):
            return None
        parts = sid_str.rsplit("-", 1)
        if len(parts) < SID_RSPLIT_PART_COUNT:
            return None
        try:
            return int(parts[1])
        except ValueError:
            return None

    @staticmethod
    def _decode_interval(value: object) -> str | None:
        """Convert a negative FILETIME interval to a human-readable duration string.

        AD stores policy durations (maxPwdAge, lockoutDuration, etc.) as
        negative 64-bit FILETIME intervals.  For example, -8640000000000
        represents 10 days.

        Per [MS-ADTS] section 3.1.1.5.2.5.

        Args:
            value: Negative FILETIME interval (100-ns units), or None.

        Returns:
            Human-readable duration string (e.g., "10 days, 0:00:00"), or None.

        """
        if value is None:
            return None

        if not isinstance(value, int):
            return str(value)

        if value == 0:
            return "none"

        # AD stores intervals as negative values in 100-nanosecond units
        # Convert to positive seconds
        abs_100ns = abs(value)
        total_seconds = abs_100ns // 10_000_000

        days = total_seconds // 86400
        remainder = total_seconds % 86400
        hours = remainder // 3600
        minutes = (remainder % 3600) // 60
        seconds = remainder % 60

        if days > 0:
            return f"{days} days, {hours}:{minutes:02d}:{seconds:02d}"
        return f"{hours}:{minutes:02d}:{seconds:02d}"


def decode_filetime(value: object) -> str | None:
    """Convert a Windows FILETIME value to an ISO 8601 string.

    FILETIME is a 64-bit value representing 100-nanosecond intervals
    since 1601-01-01 00:00:00 UTC.  Per [MS-DTYP] section 2.3.3.

    Special cases:
    - None: returns None
    - 0 (TIMESTAMP_NOT_SET): returns None (attribute was never set)
    - 0x7FFFFFFFFFFFFFFF or alt sentinel: returns "never" (account never expires)
    - datetime objects: formatted directly via isoformat()

    Args:
        value: Raw FILETIME integer, datetime, or None.

    Returns:
        ISO 8601 string, "never", or None.

    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if not isinstance(value, int):
        return str(value)
    return _filetime_int_to_str(value)


def _filetime_int_to_str(value: int) -> str | None:
    """Convert a FILETIME integer to an ISO 8601 string, handling sentinel values.

    Extracted from _decode_filetime to handle the integer-specific logic
    after None, datetime, and non-int cases are already ruled out.

    Args:
        value: FILETIME integer (100-ns intervals since 1601-01-01 UTC).

    Returns:
        ISO 8601 string, "never", or None for unset timestamps.

    """
    # Zero means the timestamp was never written (not set)
    if value == TIMESTAMP_NOT_SET:
        return None

    # Max-value sentinels mean "never expires" for accountExpires etc.
    if value in (NEVER_EXPIRES, NEVER_EXPIRES_ALT):
        return "never"

    # Convert FILETIME to Unix timestamp
    try:
        unix_us = (value - _FILETIME_EPOCH_DELTA) / 10  # microseconds since Unix epoch
        dt = datetime.fromtimestamp(unix_us / 1_000_000, tz=UTC)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):  # fmt: skip
        # Out-of-range or negative FILETIME -- return raw value as string
        return str(value)
