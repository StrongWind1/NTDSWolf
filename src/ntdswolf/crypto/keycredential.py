"""Parse ``msDS-KeyCredentialLink`` binary structures (WHfB / Device Registration).

The ``msDS-KeyCredentialLink`` attribute stores key credential information
for Windows Hello for Business (WHfB) and Azure AD device registration.
Each linked value is a binary blob containing metadata about a public key
credential bound to the account.

The blob is a Version DWORD (0x0200 for v2) followed by KEYCREDENTIALLINK_ENTRY
records, each ``Length (WORD) + Identifier (BYTE) + Value`` per [MS-ADTS]
section 2.2.20.  As stored in the NTDS ``link_table`` (a binary-valued link), a
4-byte length prefix precedes the Version DWORD.

Entry identifiers ([MS-ADTS] section 2.2.20.6):

    Id    Name                   Type
    ----  ----                   ----
    0x01  KeyID                  SHA-256 of the public key
    0x02  KeyHash                SHA-256 hash bytes
    0x03  KeyMaterial            DER-encoded public key (RSA or ECC)
    0x04  KeyUsage               BYTE (0x01=NGC, 0x07=FIDO, 0x08=FEK)
    0x05  KeySource              BYTE (0=AD, 1=AzureAD)
    0x06  DeviceId               GUID (16 bytes, big-endian)
    0x07  CustomKeyInformation   Variable-length blob
    0x08  KeyApproximateLastLogonTimeStamp   FILETIME
    0x09  KeyCreationTime        FILETIME
"""

from __future__ import annotations

import logging
import struct
import uuid
from typing import TYPE_CHECKING

from ntdswolf.constants import DWORD_SIZE, FILETIME_BYTE_LENGTH, UUID_BYTE_LENGTH

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.database.ese.ntds.objects import Object as DissectObject

logger = logging.getLogger(__name__)

# KEYCREDENTIALLINK_BLOB Version DWORD values ([MS-ADTS] section 2.2.20.2).
_KC_VERSIONS: frozenset[int] = frozenset({0x0000, 0x0100, 0x0200})

# KEYCREDENTIALLINK_ENTRY header: Length (WORD) + Identifier (BYTE) = 3 bytes.
_KC_ENTRY_HEADER_SIZE: int = 2 + 1

# --- Key credential entry identifiers ([MS-ADTS] section 2.2.20.6) ---
_TAG_KEY_ID: int = 0x01
_TAG_KEY_HASH: int = 0x02
_TAG_KEY_MATERIAL: int = 0x03
_TAG_KEY_USAGE: int = 0x04
_TAG_KEY_SOURCE: int = 0x05
_TAG_DEVICE_ID: int = 0x06
_TAG_CUSTOM_KEY_INFO: int = 0x07
_TAG_KEY_APPROX_LAST_LOGON: int = 0x08
_TAG_KEY_CREATION_TIME: int = 0x09

_TAG_NAMES: dict[int, str] = {
    _TAG_KEY_ID: "KeyID",
    _TAG_KEY_HASH: "KeyHash",
    _TAG_KEY_MATERIAL: "KeyMaterial",
    _TAG_KEY_USAGE: "KeyUsage",
    _TAG_KEY_SOURCE: "KeySource",
    _TAG_DEVICE_ID: "DeviceId",
    _TAG_CUSTOM_KEY_INFO: "CustomKeyInformation",
    _TAG_KEY_APPROX_LAST_LOGON: "KeyApproximateLastLogonTimeStamp",
    _TAG_KEY_CREATION_TIME: "KeyCreationTime",
}

# Key usage values ([MS-ADTS] section 2.2.20.5 / DSInternals KeyUsage).
_KEY_USAGE_NAMES: dict[int, str] = {
    0x01: "NGC",  # Windows Hello for Business (Next Generation Credential)
    0x02: "STK",  # Session Transport Key
    0x07: "FIDO",  # FIDO2 security key
    0x08: "FEK",  # File Encryption Key
}

# Key source values.
_KEY_SOURCE_NAMES: dict[int, str] = {
    0: "AD",  # On-premises Active Directory
    1: "AzureAD",  # Azure Active Directory
}


def parse_key_credential(blob: bytes) -> dict | None:
    """Parse one ``msDS-KeyCredentialLink`` KEYCREDENTIALLINK_BLOB.

    The blob is the binary half of the DN-with-binary link value (stored in the
    NTDS ``link_table``): a Version DWORD followed by KEYCREDENTIALLINK_ENTRY
    records of ``Length (WORD) + Identifier (BYTE) + Value`` per [MS-ADTS]
    section 2.2.20.  ``link_table`` values carry a 4-byte length prefix ahead of
    the Version DWORD; it is skipped automatically.

    Args:
        blob: Raw KEYCREDENTIALLINK_BLOB bytes (with or without the link-table
            length prefix).

    Returns:
        Dictionary with parsed fields (``Version``, ``KeyID``, ``DeviceId``,
        ``KeyCreationTime``, ``KeyUsage``, ``KeyMaterial`` hex, etc.), or
        ``None`` if the blob cannot be parsed.

    """
    if len(blob) < DWORD_SIZE:
        return None

    # The blob begins with the Version DWORD; link_table values prepend a 4-byte
    # length prefix, so skip it when the leading DWORD is not a known version.
    if struct.unpack_from("<I", blob, 0)[0] not in _KC_VERSIONS and len(blob) >= DWORD_SIZE * 2:
        blob = blob[DWORD_SIZE:]
    if len(blob) < DWORD_SIZE:
        return None

    result: dict = {"Version": struct.unpack_from("<I", blob, 0)[0]}

    # KEYCREDENTIALLINK_ENTRY records: Length (WORD) + Identifier (BYTE) + Value.
    pos = DWORD_SIZE
    while pos + _KC_ENTRY_HEADER_SIZE <= len(blob):
        entry_length = struct.unpack_from("<H", blob, pos)[0]
        identifier = blob[pos + 2]
        pos += _KC_ENTRY_HEADER_SIZE
        if pos + entry_length > len(blob):
            logger.debug("Key credential entry truncated at id %#x (need %d, have %d)", identifier, entry_length, len(blob) - pos)
            break
        _decode_tag(identifier, blob[pos : pos + entry_length], result)
        pos += entry_length

    if not result.get("KeyID") and not result.get("KeyMaterial"):
        logger.debug("Key credential blob contained no KeyID/KeyMaterial")
        return None

    return result


def extract_key_credentials(obj: DissectObject) -> list[dict]:
    """Read and parse every ``msDS-KeyCredentialLink`` blob bound to an object.

    The KEYCREDENTIALLINK_BLOBs are stored in the NTDS ``link_table``'s
    ``link_data`` column (a binary-valued link), which dissect's ``links()`` does
    not surface, so they are read directly via the link index on the object's DNT.

    Args:
        obj: A dissect NTDS object (exposes ``db`` and ``dnt``).

    Returns:
        List of parsed key-credential dicts (empty if the object has none).

    """
    return [kc for blob in _read_key_credential_blobs(obj) if (kc := parse_key_credential(blob)) is not None]


def _read_key_credential_blobs(obj: DissectObject) -> list[bytes]:
    """Read the raw ``msDS-KeyCredentialLink`` link_data blobs for *obj* from the link table."""
    blobs: list[bytes] = []
    try:
        db = obj.db
        schema = db.data.schema.lookup_attribute(name="msDS-KeyCredentialLink")
        if schema is None or not schema.link_id:
            return []
        base = schema.link_id // 2
        dnt = obj.dnt
        cursor = db.link.table.index("link_index").cursor()
        cursor.seek([dnt, base])
        record = cursor.record()
        while record is not None and record.get("link_DNT") == dnt and record.get("link_base") == base:
            data = record.get("link_data")
            if data:
                blobs.append(bytes(data))
            record = cursor.next()
    except (AttributeError, ValueError, KeyError, TypeError):
        logger.debug("Failed to read key-credential link data", exc_info=True)
        return []
    return blobs


def _decode_key_id(data: bytes, result: dict) -> None:
    """Decode a KeyID tag (UTF-8 string, typically base64-encoded SHA-256)."""
    try:
        result["KeyID"] = data.decode("utf-8")
    except UnicodeDecodeError:
        result["KeyID"] = data.hex()


def _decode_dword_or_byte(data: bytes) -> int:
    """Read a DWORD or single-byte integer from *data*, returning -1 if empty."""
    if len(data) >= DWORD_SIZE:
        return struct.unpack_from("<I", data, 0)[0]
    if len(data) >= 1:
        return data[0]
    return -1


def _decode_key_usage(data: bytes, result: dict) -> None:
    """Decode a KeyUsage tag (DWORD enum)."""
    usage_val = _decode_dword_or_byte(data)
    result["KeyUsage"] = _KEY_USAGE_NAMES.get(usage_val, f"Unknown({usage_val})")
    result["KeyUsageRaw"] = usage_val


def _decode_key_source(data: bytes, result: dict) -> None:
    """Decode a KeySource tag (DWORD enum)."""
    source_val = _decode_dword_or_byte(data)
    result["KeySource"] = _KEY_SOURCE_NAMES.get(source_val, f"Unknown({source_val})")


def _decode_device_id(data: bytes, result: dict) -> None:
    """Decode a DeviceId tag (16-byte GUID, big-endian per the KeyCredential blob)."""
    if len(data) == UUID_BYTE_LENGTH:
        try:
            result["DeviceId"] = str(uuid.UUID(bytes=data))
        except (ValueError, OverflowError):
            result["DeviceId"] = data.hex()
    else:
        result["DeviceId"] = data.hex()


def _decode_filetime(data: bytes, result: dict, key: str) -> None:
    """Decode a FILETIME tag (8-byte unsigned little-endian)."""
    if len(data) == FILETIME_BYTE_LENGTH:
        result[key] = struct.unpack_from("<Q", data, 0)[0]
    else:
        result[key] = data.hex()


def _decode_hex_tag(data: bytes, result: dict, key: str) -> None:
    """Store raw hex under *key*."""
    result[key] = data.hex()


def _decode_approx_last_logon(data: bytes, result: dict) -> None:
    """Decode the KeyApproximateLastLogonTimeStamp tag."""
    _decode_filetime(data, result, "KeyApproximateLastLogonTimeStamp")


def _decode_creation_time(data: bytes, result: dict) -> None:
    """Decode the KeyCreationTime tag."""
    _decode_filetime(data, result, "KeyCreationTime")


def _decode_key_hash(data: bytes, result: dict) -> None:
    """Decode the KeyHash tag."""
    _decode_hex_tag(data, result, "KeyHash")


def _decode_key_material(data: bytes, result: dict) -> None:
    """Decode the KeyMaterial tag."""
    _decode_hex_tag(data, result, "KeyMaterial")


def _decode_custom_key_info(data: bytes, result: dict) -> None:
    """Decode the CustomKeyInformation tag."""
    _decode_hex_tag(data, result, "CustomKeyInformation")


_TAG_DECODERS: dict[int, Callable[..., None]] = {
    _TAG_KEY_ID: _decode_key_id,
    _TAG_KEY_HASH: _decode_key_hash,
    _TAG_KEY_MATERIAL: _decode_key_material,
    _TAG_KEY_USAGE: _decode_key_usage,
    _TAG_KEY_SOURCE: _decode_key_source,
    _TAG_DEVICE_ID: _decode_device_id,
    _TAG_CUSTOM_KEY_INFO: _decode_custom_key_info,
    _TAG_KEY_APPROX_LAST_LOGON: _decode_approx_last_logon,
    _TAG_KEY_CREATION_TIME: _decode_creation_time,
}


def _decode_tag(tag: int, data: bytes, result: dict) -> None:
    """Decode a single TLV entry and add it to *result*."""
    decoder = _TAG_DECODERS.get(tag)
    if decoder is not None:
        decoder(data, result)
    else:
        # Unknown tag -- store raw hex under the numeric tag name.
        tag_name = _TAG_NAMES.get(tag, f"Unknown({tag})")
        result[tag_name] = data.hex()
