"""Serialize a dissect security descriptor to an SDDL string.

Per [MS-DTYP] section 2.5.1 (Security Descriptor String Format). dissect parses
the binary security descriptor into owner/group SIDs and DACL/SACL ACE lists but
does not emit SDDL, so we serialize it here, matching the abbreviations and
ordering that Windows' ``ConvertSecurityDescriptorToStringSecurityDescriptor``
produces (calibrated against the ``defaultSecurityDescriptor`` SDDL strings AD
stores on schema classes).

Import rules: decoders import from crypto/, models/, constants ONLY -- this
module imports nothing from ntdswolf.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.database.ese.ntds.sd import ACE, SecurityDescriptor

# ACE type byte -> SDDL abbreviation. [MS-DTYP] section 2.5.1.1.
_ACE_TYPE_SDDL: dict[int, str] = {
    0x00: "A",  # ACCESS_ALLOWED
    0x01: "D",  # ACCESS_DENIED
    0x02: "AU",  # SYSTEM_AUDIT
    0x03: "AL",  # SYSTEM_ALARM
    0x05: "OA",  # ACCESS_ALLOWED_OBJECT
    0x06: "OD",  # ACCESS_DENIED_OBJECT
    0x07: "OU",  # SYSTEM_AUDIT_OBJECT
    0x08: "OL",  # SYSTEM_ALARM_OBJECT
    0x09: "XA",  # ACCESS_ALLOWED_CALLBACK
    0x0A: "XD",  # ACCESS_DENIED_CALLBACK
    0x0B: "ZA",  # ACCESS_ALLOWED_CALLBACK_OBJECT
    0x0D: "XU",  # SYSTEM_AUDIT_CALLBACK
    0x11: "ML",  # SYSTEM_MANDATORY_LABEL
    0x12: "RA",  # SYSTEM_RESOURCE_ATTRIBUTE
    0x13: "SP",  # SYSTEM_SCOPED_POLICY_ID
    0x14: "TL",  # SYSTEM_PROCESS_TRUST_LABEL
    0x15: "FL",  # SYSTEM_ACCESS_FILTER
}

# ACE flag bit -> SDDL abbreviation, in canonical emission order. [MS-DTYP] 2.5.1.2.
_ACE_FLAG_SDDL: tuple[tuple[int, str], ...] = (
    (0x02, "CI"),  # CONTAINER_INHERIT
    (0x01, "OI"),  # OBJECT_INHERIT
    (0x04, "NP"),  # NO_PROPAGATE_INHERIT
    (0x08, "IO"),  # INHERIT_ONLY
    (0x10, "ID"),  # INHERITED
    (0x40, "SA"),  # SUCCESSFUL_ACCESS
    (0x80, "FA"),  # FAILED_ACCESS
)

# Access-mask bit -> SDDL abbreviation, in canonical emission order. [MS-DTYP] 2.5.1.3.
# Bits without an abbreviation (SYNCHRONIZE, ACCESS_SYSTEM_SECURITY, MAXIMUM_ALLOWED)
# force the whole rights field to hex, matching Windows.
_RIGHTS_SDDL: tuple[tuple[int, str], ...] = (
    (0x00000001, "CC"),  # ADS_RIGHT_DS_CREATE_CHILD
    (0x00000002, "DC"),  # ADS_RIGHT_DS_DELETE_CHILD
    (0x00000004, "LC"),  # ADS_RIGHT_DS_LIST_CONTENTS
    (0x00000008, "SW"),  # ADS_RIGHT_DS_SELF
    (0x00000010, "RP"),  # ADS_RIGHT_DS_READ_PROP
    (0x00000020, "WP"),  # ADS_RIGHT_DS_WRITE_PROP
    (0x00000040, "DT"),  # ADS_RIGHT_DS_DELETE_TREE
    (0x00000080, "LO"),  # ADS_RIGHT_DS_LIST_OBJECT
    (0x00000100, "CR"),  # ADS_RIGHT_DS_CONTROL_ACCESS
    (0x00010000, "SD"),  # DELETE
    (0x00020000, "RC"),  # READ_CONTROL
    (0x00040000, "WD"),  # WRITE_DAC
    (0x00080000, "WO"),  # WRITE_OWNER
    (0x10000000, "GA"),  # GENERIC_ALL
    (0x80000000, "GR"),  # GENERIC_READ
    (0x40000000, "GW"),  # GENERIC_WRITE
    (0x20000000, "GX"),  # GENERIC_EXECUTE
)
_RIGHTS_KNOWN_MASK: int = 0
for _bit, _abbr in _RIGHTS_SDDL:
    _RIGHTS_KNOWN_MASK |= _bit

# Universal well-known SIDs -> SDDL alias. [MS-DTYP] section 2.4.2.4.
_WELL_KNOWN_SID_SDDL: dict[str, str] = {
    "S-1-1-0": "WD",  # Everyone
    "S-1-3-0": "CO",  # Creator Owner
    "S-1-3-1": "CG",  # Creator Group
    "S-1-5-2": "NU",  # Network
    "S-1-5-4": "IU",  # Interactive
    "S-1-5-6": "SU",  # Service
    "S-1-5-7": "AN",  # Anonymous
    "S-1-5-9": "ED",  # Enterprise Domain Controllers
    "S-1-5-10": "PS",  # Principal Self
    "S-1-5-11": "AU",  # Authenticated Users
    "S-1-5-12": "RC",  # Restricted Code
    "S-1-5-18": "SY",  # Local System
    "S-1-5-19": "LS",  # Local Service
    "S-1-5-20": "NS",  # Network Service
    "S-1-5-32-544": "BA",  # Builtin Administrators
    "S-1-5-32-545": "BU",  # Builtin Users
    "S-1-5-32-546": "BG",  # Builtin Guests
    "S-1-5-32-547": "PU",  # Power Users
    "S-1-5-32-548": "AO",  # Account Operators
    "S-1-5-32-549": "SO",  # Server Operators
    "S-1-5-32-550": "PO",  # Print Operators
    "S-1-5-32-551": "BO",  # Backup Operators
    "S-1-5-32-552": "RE",  # Replicator
    "S-1-5-32-554": "RU",  # Pre-Windows 2000 Compatible Access
    "S-1-5-32-555": "RD",  # Remote Desktop Users
    "S-1-5-32-556": "NO",  # Network Configuration Operators
    "S-1-5-32-558": "MU",  # Performance Monitoring Users
    "S-1-5-32-559": "LU",  # Performance Log Users
    "S-1-5-32-568": "IS",  # IIS Users
    "S-1-5-32-569": "CY",  # Crypto Operators
    "S-1-5-32-573": "ER",  # Event Log Readers
    "S-1-5-32-574": "CD",  # Certificate Service DCOM Access
    "S-1-5-32-578": "HA",  # Hyper-V Admins
    "S-1-5-32-579": "AA",  # Access Control Assistance Operators
    "S-1-5-32-580": "RM",  # Remote Management Users
}

# Domain-relative RIDs (under an S-1-5-21-domain prefix) -> SDDL alias. [MS-DTYP] 2.4.2.4.
_DOMAIN_RID_SDDL: dict[int, str] = {
    498: "RO",  # Enterprise Read-Only Domain Controllers
    500: "LA",  # Administrator
    501: "LG",  # Guest
    512: "DA",  # Domain Admins
    513: "DU",  # Domain Users
    514: "DG",  # Domain Guests
    515: "DC",  # Domain Computers
    516: "DD",  # Domain Controllers
    517: "CA",  # Cert Publishers
    518: "SA",  # Schema Admins
    519: "EA",  # Enterprise Admins
    520: "PA",  # Group Policy Creator Owners
    553: "RS",  # RAS and IAS Servers
}

# SD control-flag bits used in the DACL/SACL flags field. [MS-DTYP] section 2.5.1.4.
_SE_DACL_AUTO_INHERIT_REQ = 0x0100
_SE_SACL_AUTO_INHERIT_REQ = 0x0200
_SE_DACL_AUTO_INHERITED = 0x0400
_SE_SACL_AUTO_INHERITED = 0x0800
_SE_DACL_PROTECTED = 0x1000
_SE_SACL_PROTECTED = 0x2000


def _sid_to_sddl(sid: str | None) -> str:
    """Return the 2-letter SDDL alias for a SID, or the full SID string."""
    if not sid:
        return ""
    if sid in _WELL_KNOWN_SID_SDDL:
        return _WELL_KNOWN_SID_SDDL[sid]
    if sid.startswith("S-1-5-21-"):
        try:
            alias = _DOMAIN_RID_SDDL.get(int(sid.rsplit("-", 1)[-1]))
        except ValueError:
            alias = None
        if alias:
            return alias
    return sid


def _mask_to_sddl(mask: int) -> str:
    """Return the SDDL rights string: concatenated abbreviations, or hex."""
    value = int(mask)
    if value == 0:
        return ""
    # Any bit without an abbreviation forces the whole field to hex (Windows behavior).
    if value & ~_RIGHTS_KNOWN_MASK:
        return f"0x{value:x}"
    return "".join(abbr for bit, abbr in _RIGHTS_SDDL if value & bit)


def _ace_to_sddl(ace: ACE) -> str:
    """Serialize one ACE to ``(type;flags;rights;object_guid;inherit_guid;sid)``."""
    ace_type = _ACE_TYPE_SDDL.get(int(ace.type), f"0x{int(ace.type):02x}")
    flags = "".join(abbr for bit, abbr in _ACE_FLAG_SDDL if int(ace.flags) & bit)
    rights = _mask_to_sddl(ace.mask) if ace.mask is not None else ""
    obj_guid = str(ace.object_type).upper() if ace.object_type is not None else ""
    inherit_guid = str(ace.inherited_object_type).upper() if ace.inherited_object_type is not None else ""
    return f"({ace_type};{flags};{rights};{obj_guid};{inherit_guid};{_sid_to_sddl(ace.sid)})"


def _acl_flags(control: int, *, dacl: bool) -> str:
    """Return the SDDL control-flag string (P/AR/AI) for a DACL or SACL."""
    protected = _SE_DACL_PROTECTED if dacl else _SE_SACL_PROTECTED
    auto_req = _SE_DACL_AUTO_INHERIT_REQ if dacl else _SE_SACL_AUTO_INHERIT_REQ
    auto_inherited = _SE_DACL_AUTO_INHERITED if dacl else _SE_SACL_AUTO_INHERITED
    flags = ""
    if control & protected:
        flags += "P"
    if control & auto_req:
        flags += "AR"
    if control & auto_inherited:
        flags += "AI"
    return flags


def to_sddl(sd: SecurityDescriptor) -> str:
    """Serialize a dissect SecurityDescriptor to an SDDL string.

    Per [MS-DTYP] section 2.5.1: ``O:owner G:group D:dacl_flags(ace)... S:sacl_flags(ace)...``.

    Args:
        sd: A dissect ``SecurityDescriptor`` (from ``obj.sd``).

    Returns:
        The SDDL string. Sections are emitted only when present.

    """
    control = int(sd.header.Control)
    parts: list[str] = []
    if sd.owner:
        parts.append(f"O:{_sid_to_sddl(sd.owner)}")
    if sd.group:
        parts.append(f"G:{_sid_to_sddl(sd.group)}")
    if sd.dacl is not None:
        aces = "".join(_ace_to_sddl(ace) for ace in sd.dacl.ace)
        parts.append(f"D:{_acl_flags(control, dacl=True)}{aces}")
    if sd.sacl is not None:
        aces = "".join(_ace_to_sddl(ace) for ace in sd.sacl.ace)
        parts.append(f"S:{_acl_flags(control, dacl=False)}{aces}")
    return "".join(parts)
