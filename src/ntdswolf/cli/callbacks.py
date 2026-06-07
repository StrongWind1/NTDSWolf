"""CLI argument validation callbacks for typer.

These functions are used as ``callback`` parameters on typer options to
validate user input before the pipeline starts.  Validation here gives
immediate feedback with clear error messages rather than failing deep
inside the extraction pipeline.
"""

from __future__ import annotations

import re

import typer

# Regex for a valid 32-character hex string (the boot key format).
_HEX32_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-fA-F]{32}$")

# Object classes that can be specified with --extract/-e.
# These match the lDAPDisplayName values used internally -- the _object_class
# values that decoders emit and that the OutputManager filters on.
VALID_EXTRACT_CLASSES: frozenset[str] = frozenset(
    {
        "user",
        "computer",
        "group",
        "trustedDomain",
        "domainDNS",
        "organizationalUnit",
        "groupPolicyContainer",
        "msDS-GroupManagedServiceAccount",
        "msKds-ProvRootKey",
        "msFVE-RecoveryInformation",
    }
)

# Sentinel --extract value meaning "extract every object class" (no filter).
_EXTRACT_ALL: str = "all"

# Friendly --extract aliases (matched case-insensitively) mapped to the
# canonical _object_class value the OutputManager filters on. The documented
# plural names (``users``, ``groups``, ``trusts``, ``domains``) and bare class
# names both resolve here; anything not listed passes through unchanged so
# custom schema classes still work.
_EXTRACT_ALIASES: dict[str, str] = {
    "user": "user",
    "users": "user",
    "computer": "computer",
    "computers": "computer",
    "group": "group",
    "groups": "group",
    "trust": "trustedDomain",
    "trusts": "trustedDomain",
    "trusteddomain": "trustedDomain",
    "domain": "domainDNS",
    "domains": "domainDNS",
    "domaindns": "domainDNS",
    "ou": "organizationalUnit",
    "organizationalunit": "organizationalUnit",
    "gpo": "groupPolicyContainer",
    "grouppolicycontainer": "groupPolicyContainer",
    "gmsa": "msDS-GroupManagedServiceAccount",
    "msds-groupmanagedserviceaccount": "msDS-GroupManagedServiceAccount",
    "kds": "msKds-ProvRootKey",
    "mskds-provrootkey": "msKds-ProvRootKey",
    "bitlocker": "msFVE-RecoveryInformation",
    "msfve-recoveryinformation": "msFVE-RecoveryInformation",
}


def validate_bootkey(value: str | None) -> str | None:
    """Validate that a --bootkey value is exactly 32 hex characters.

    Args:
        value: The raw CLI argument, or None if not provided.

    Returns:
        The validated hex string (stripped of whitespace), or None.

    Raises:
        typer.BadParameter: If the value is not valid 32-char hex.

    """
    if value is None:
        return None

    cleaned = value.strip()
    if not _HEX32_PATTERN.match(cleaned):
        msg = f"Boot key must be exactly 32 hex characters, got {len(cleaned)} chars: {cleaned!r}"
        raise typer.BadParameter(msg)

    return cleaned


def validate_extract_classes(value: list[str] | None) -> set[str] | None:
    """Validate and normalize --extract class names.

    Accepts the documented friendly names (``users``, ``computers``,
    ``groups``, ``trusts``, ``domains``) as well as raw lDAPDisplayName class
    values, in any case, and maps them to the canonical ``_object_class``
    values that the OutputManager filters on. This is what makes
    ``--extract users,groups`` actually select objects: decoders emit the
    singular class name (``user``), so the plural CLI names must be normalized.

    The special value ``all`` (or no value at all) means "extract everything"
    and returns ``None``. Names not in the alias table pass through unchanged
    so custom schema classes can still be requested by their exact name.

    Args:
        value: List of class name strings from the CLI, or None if not provided.

    Returns:
        A set of canonical class names to extract, or None if all classes
        should be extracted.

    """
    if value is None or len(value) == 0:
        return None

    classes: set[str] = set()
    for cls_name in value:
        # Allow comma-separated values within a single argument.
        for part in cls_name.split(","):
            stripped_part = part.strip()
            if not stripped_part:
                continue
            # "all" disables filtering entirely -- extract every class.
            if stripped_part.lower() == _EXTRACT_ALL:
                return None
            # Normalize friendly/plural aliases to the canonical class name;
            # unknown names pass through unchanged for custom schema classes.
            classes.add(_EXTRACT_ALIASES.get(stripped_part.lower(), stripped_part))

    if not classes:
        return None

    return classes
