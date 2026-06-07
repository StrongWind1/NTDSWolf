r"""Extract the SYSTEM boot key (SysKey) from a Windows SYSTEM registry hive.

The boot key is a 16-byte value derived from the class names of four registry
keys under ``HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa``.  It serves as
the root secret that protects the Password Encryption Key (PEK) list stored
inside NTDS.dit.

The four class-name fragments are concatenated in the order JD, Skew1, GBG,
Data, hex-decoded, then permuted through a fixed table to yield the final
16-byte boot key.  The permutation table is documented in numerous public
references and matches the behavior of ``syskey.exe``.

This module uses ``dissect.regf`` for hive parsing so it works fully offline
without any Windows API calls.
"""

from __future__ import annotations

import logging
from binascii import unhexlify
from pathlib import Path

from dissect.regf import RegistryHive

from ntdswolf.constants import BOOTKEY_HEX_LENGTH

logger = logging.getLogger(__name__)

# Order in which the four Lsa sub-key class names are concatenated.
_LSA_KEY_NAMES: list[str] = ["JD", "Skew1", "GBG", "Data"]

# Permutation table applied to the 16 raw bytes after hex-decoding.
# This scramble is the same one ``syskey.exe`` applies; it is not
# documented in any public Microsoft spec but has been stable across
# every Windows version from 2000 through Server 2025.
_BOOT_KEY_PERMUTATION: list[int] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]


def extract_bootkey_from_hive(hive_path: str | Path) -> bytes:
    """Read a SYSTEM registry hive file and derive the 16-byte boot key.

    Args:
        hive_path: Filesystem path to the SYSTEM hive (offline copy).

    Returns:
        The 16-byte boot key.

    Raises:
        FileNotFoundError: If *hive_path* does not exist.
        ValueError: If the hive cannot be parsed or the required keys are
            missing.

    """
    hive_path = Path(hive_path)
    if not hive_path.is_file():
        msg = f"SYSTEM hive not found: {hive_path}"
        raise FileNotFoundError(msg)

    with hive_path.open("rb") as fh:
        hive = RegistryHive(fh)

        # Determine the active ControlSet.  The ``Select\Current`` value is a
        # DWORD that tells us which ControlSetNNN is currently active.
        select_key = hive.open("Select")
        current_cs_number = select_key.value("Current").value
        control_set = f"ControlSet{current_cs_number:03d}"
        logger.debug("Active control set: %s", control_set)

        # Collect the 4 class-name fragments and concatenate them.
        hex_fragments: str = ""
        lsa_path = f"{control_set}\\Control\\Lsa"
        for key_name in _LSA_KEY_NAMES:
            full_path = f"{lsa_path}\\{key_name}"
            key_node = hive.open(full_path)
            # The class_name attribute holds the UTF-16LE-decoded string.
            # We only need the first 16 characters (8 hex bytes per fragment).
            class_name: str | None = key_node.class_name
            if class_name is None:
                msg = f"Registry key {full_path} has no class name"
                raise ValueError(msg)
            hex_fragments += class_name[:16]
            logger.debug("Key %s class name fragment: %s", key_name, class_name[:16])

    # hex_fragments is now a 32-character hex string (4 x 8 hex chars).
    raw_bytes = unhexlify(hex_fragments)

    # Apply the permutation to get the final boot key.
    boot_key = bytes(raw_bytes[i] for i in _BOOT_KEY_PERMUTATION)
    logger.info("Extracted boot key from SYSTEM hive: %s", boot_key.hex())
    return boot_key


def parse_bootkey_hex(hex_string: str) -> bytes:
    """Validate and convert a 32-character hex string to a 16-byte boot key.

    This is the simple path for users who already know their boot key and
    pass it on the command line rather than supplying a SYSTEM hive.

    Args:
        hex_string: Exactly 32 hex characters (case-insensitive).

    Returns:
        The 16-byte boot key.

    Raises:
        ValueError: If the string is not valid 32-char hex.

    """
    cleaned = hex_string.strip()
    if len(cleaned) != BOOTKEY_HEX_LENGTH:
        msg = f"Boot key hex must be exactly 32 characters, got {len(cleaned)}"
        raise ValueError(msg)

    try:
        return unhexlify(cleaned)
    except (ValueError, TypeError) as exc:
        msg = f"Invalid hex in boot key: {exc}"
        raise ValueError(msg) from exc


def auto_detect_system_hive(ntds_dir: str | Path) -> Path | None:
    """Search for a SYSTEM hive file near the NTDS.dit location.

    Looks in *ntds_dir* itself and its parent directory for files named
    ``SYSTEM`` (case-insensitive).  This covers the common case where a
    forensic image has both ``ntds.dit`` and ``SYSTEM`` extracted to the
    same folder.

    Args:
        ntds_dir: Directory containing (or near) the NTDS.dit file.

    Returns:
        Path to the SYSTEM hive if found, otherwise ``None``.

    """
    ntds_dir = Path(ntds_dir)
    search_dirs = [ntds_dir]
    if ntds_dir.parent != ntds_dir:
        search_dirs.append(ntds_dir.parent)

    for directory in search_dirs:
        if not directory.is_dir():
            continue
        for entry in directory.iterdir():
            if entry.is_file() and entry.name.upper() == "SYSTEM":
                logger.info("Auto-detected SYSTEM hive: %s", entry)
                return entry

    return None


def _try_extract_from_hive(hive_path: str | Path, label: str) -> bytes | None:
    """Attempt boot key extraction from a SYSTEM hive, returning None on failure."""
    try:
        return extract_bootkey_from_hive(hive_path)
    except (FileNotFoundError, ValueError, EOFError):
        # dissect raises EOFError when parsing a truncated/garbage hive; treat
        # any of these as "no usable boot key here" rather than crashing.
        logger.exception("Failed to extract boot key from %s", label)
        return None


def resolve_bootkey(
    bootkey_hex: str | None,
    system_path: str | Path | None,
    ntds_dir: str | Path | None,
) -> bytes | None:
    """Resolve a boot key from whichever source is available.

    Priority chain (first match wins):
    1. Explicit hex string (``--bootkey`` CLI flag).
    2. Explicit SYSTEM hive path (``--system`` CLI flag).
    3. Auto-detected SYSTEM hive near the NTDS.dit file.

    Args:
        bootkey_hex: 32-character hex boot key, or ``None``.
        system_path: Path to a SYSTEM registry hive, or ``None``.
        ntds_dir: Directory where NTDS.dit lives, used for auto-detection.

    Returns:
        The 16-byte boot key, or ``None`` if no source was available.

    """
    # 1. Direct hex value takes highest priority.
    if bootkey_hex:
        try:
            return parse_bootkey_hex(bootkey_hex)
        except ValueError:
            logger.exception("Failed to parse boot key hex")
            return None

    # 2. Explicit SYSTEM hive path.
    if system_path:
        return _try_extract_from_hive(system_path, "SYSTEM hive")

    # 3. Auto-detect near the NTDS.dit.
    if ntds_dir:
        detected = auto_detect_system_hive(ntds_dir)
        if detected:
            return _try_extract_from_hive(detected, "auto-detected SYSTEM hive")

    logger.warning("No boot key source available -- encrypted attributes cannot be decrypted")
    return None
