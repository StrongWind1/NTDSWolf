"""Unit tests for decoders/sddl.py -- security descriptor to SDDL serialization.

Expected strings are hand-derived from [MS-DTYP] section 2.5.1 so they validate
the serializer deterministically without needing a real database.
"""

from __future__ import annotations

from ntdswolf.decoders.sddl import _ace_to_sddl, _mask_to_sddl, _sid_to_sddl, to_sddl


class _ACE:
    def __init__(self, type_, flags, mask, sid, object_type=None, inherited_object_type=None):
        self.type = type_
        self.flags = flags
        self.mask = mask
        self.sid = sid
        self.object_type = object_type
        self.inherited_object_type = inherited_object_type


class _ACL:
    def __init__(self, aces):
        self.ace = aces


class _Header:
    def __init__(self, control):
        self.Control = control


class _SD:
    def __init__(self, owner, group, dacl=None, sacl=None, control=0):
        self.owner = owner
        self.group = group
        self.dacl = dacl
        self.sacl = sacl
        self.header = _Header(control)


def test_sid_well_known_aliases():
    assert _sid_to_sddl("S-1-5-18") == "SY"
    assert _sid_to_sddl("S-1-1-0") == "WD"
    assert _sid_to_sddl("S-1-5-32-544") == "BA"
    assert _sid_to_sddl("S-1-5-11") == "AU"


def test_sid_domain_relative_rids():
    assert _sid_to_sddl("S-1-5-21-1-2-3-512") == "DA"
    assert _sid_to_sddl("S-1-5-21-1-2-3-500") == "LA"
    assert _sid_to_sddl("S-1-5-21-1-2-3-519") == "EA"


def test_sid_unknown_passes_through():
    assert _sid_to_sddl("S-1-5-21-1-2-3-1234") == "S-1-5-21-1-2-3-1234"
    assert _sid_to_sddl(None) == ""


def test_mask_abbreviations_in_canonical_order():
    assert _mask_to_sddl(0x00020000) == "RC"  # READ_CONTROL
    assert _mask_to_sddl(0x10000000) == "GA"  # GENERIC_ALL
    assert _mask_to_sddl(0x1 | 0x2 | 0x4 | 0x20000) == "CCDCLCRC"


def test_mask_hex_fallback_for_unmapped_bits():
    assert _mask_to_sddl(0x00100000) == "0x100000"  # SYNCHRONIZE has no abbreviation
    assert _mask_to_sddl(0x00120000) == "0x120000"  # SYNCHRONIZE | READ_CONTROL


def test_standard_ace():
    assert _ace_to_sddl(_ACE(0, 0x02, 0x00020000, "S-1-5-18")) == "(A;CI;RC;;;SY)"


def test_object_ace_includes_uppercase_guid():
    ace = _ACE(5, 0, 0x10, "S-1-5-11", object_type="bf967aba-0de6-11d0-a285-00aa003049e2")
    assert _ace_to_sddl(ace) == "(OA;;RP;BF967ABA-0DE6-11D0-A285-00AA003049E2;;AU)"


def test_full_sddl_with_dacl_flags():
    sd = _SD(
        owner="S-1-5-32-544",
        group="S-1-5-18",
        dacl=_ACL([_ACE(0, 0x02, 0x00020000, "S-1-5-18"), _ACE(1, 0, 0x10000000, "S-1-1-0")]),
        control=0x0400,  # SE_DACL_AUTO_INHERITED -> "AI"
    )
    assert to_sddl(sd) == "O:BAG:SYD:AI(A;CI;RC;;;SY)(D;;GA;;;WD)"
