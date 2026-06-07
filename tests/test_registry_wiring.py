"""Integration tests for the decoder-registry path now wired into the pipeline.

Uses a MockObject that mimics dissect's ``Object.get(name, raw=bool)`` contract
(raising AttributeError for attributes not present, matching the real object) so
the decoders run exactly as they will against a live database -- without needing
a real ntds.dit. The credential test reuses the NT-hash round-trip construction
(PEK RC4 wrap + per-RID DES) to prove the whole UserDecoder credential path.
"""

from __future__ import annotations

import hashlib
import struct

from Crypto.Cipher import ARC4, DES

from ntdswolf.crypto.hashes import _derive_des_keys
from ntdswolf.crypto.pek import PEKList
from ntdswolf.decoders._supplemental import merge_supplemental
from ntdswolf.decoders.base import DecoderContext
from ntdswolf.decoders.registry import DecoderRegistry, build_default_registry
from ntdswolf.decoders.users import UserDecoder

_NT = bytes.fromhex("7facdc498ed1680c4fd1448319a8c04f")


class _Linked:
    """A linked object stand-in exposing just ``.dn`` (like dissect's link targets)."""

    def __init__(self, dn: str) -> None:
        self.dn = dn


class MockObject:
    """Minimal stand-in for dissect's ntds Object (get, object_class, links/backlinks)."""

    def __init__(self, attrs: dict[str, object], raw: dict[str, object] | None = None, links: list[tuple[str, str]] | None = None, backlinks: list[tuple[str, str]] | None = None) -> None:
        self._attrs = attrs
        self._raw = raw or {}
        self._links = links or []
        self._backlinks = backlinks or []

    def get(self, name: str, *, raw: bool = False) -> object:
        store = self._raw if raw else self._attrs
        if name in store:
            return store[name]
        raise AttributeError(name)

    @property
    def object_class(self) -> object:
        return self._attrs.get("objectClass")

    def links(self) -> list[tuple[str, _Linked]]:
        return [(attr, _Linked(dn)) for attr, dn in self._links]

    def backlinks(self) -> list[tuple[str, _Linked]]:
        return [(attr, _Linked(dn)) for attr, dn in self._backlinks]


def _sid_bytes(rid: int) -> bytes:
    # S-1-5-21-1-2-3-<rid>: rev=1, count=5, authority=5, subauths 21,1,2,3,rid.
    # NTDS stores the RID (last sub-authority) big-endian (dissect swap_last=True).
    return struct.pack("<BB", 1, 5) + (5).to_bytes(6, "big") + struct.pack("<4I", 21, 1, 2, 3) + struct.pack(">I", rid)


def _wrap_nt_for_rid(nt: bytes, rid: int, pek_key: bytes) -> bytes:
    k1, k2 = _derive_des_keys(rid)
    obf = DES.new(k1, DES.MODE_ECB).encrypt(nt[:8]) + DES.new(k2, DES.MODE_ECB).encrypt(nt[8:])  # noqa: S304 -- builds NTDS hash test vector
    salt = b"\x22" * 16
    rc4_key = hashlib.md5(pek_key + salt).digest()  # noqa: S324 -- NTDS PEK key derivation
    return struct.pack("<HHI", 0x10, 0, 0) + salt + ARC4.new(rc4_key).encrypt(obf)


# --- Registry dispatch ---


def test_registry_dispatches_known_classes():
    registry = build_default_registry()
    assert type(registry.get(["user"])).__name__ == "UserDecoder"
    assert type(registry.get(["computer"])).__name__ == "UserDecoder"
    assert type(registry.get(["group"])).__name__ == "GroupDecoder"
    assert type(registry.get(["trustedDomain"])).__name__ == "TrustDecoder"


def test_registry_unknown_class_falls_back_to_generic():
    registry = build_default_registry()
    assert type(registry.get(["somethingWeird"])).__name__ == "GenericDecoder"
    assert type(registry.get(None)).__name__ == "GenericDecoder"


# --- Link resolver adapter (the one piece of glue the wiring adds) ---


# --- UserDecoder via the registry: the keystone path ---


def test_user_decoder_extracts_nt_hash_end_to_end():
    pek_key = b"\x11" * 16
    obj = MockObject(
        attrs={"objectClass": ["user"], "DNT": 100, "sAMAccountName": "Administrator", "name": "Administrator", "objectSid": "S-1-5-21-1-2-3-500"},
        raw={"unicodePwd": _wrap_nt_for_rid(_NT, 500, pek_key)},
    )
    result = build_default_registry().get(obj.object_class).decode(obj, DecoderContext(pek_list=PEKList(keys={0: pek_key})))

    assert result["_object_class"] == "user"
    assert result["objectSid"] == "S-1-5-21-1-2-3-500"
    assert result["sAMAccountName"] == "Administrator"
    assert result["credentials"]["ntHash"] == _NT.hex()


def test_user_decoder_resolves_member_of_via_dissect_backlinks():
    obj = MockObject(
        attrs={"objectClass": ["user"], "DNT": 7, "sAMAccountName": "u"},
        backlinks=[("memberOf", "CN=Admins,DC=x")],
    )
    result = build_default_registry().get(obj.object_class).decode(obj, DecoderContext())
    assert result["memberOf"] == ["CN=Admins,DC=x"]


def test_user_decoder_without_pek_has_no_credentials():
    obj = MockObject(attrs={"objectClass": ["user"], "DNT": 1, "sAMAccountName": "u"}, raw={"objectSid": _sid_bytes(1105)})
    result = build_default_registry().get(obj.object_class).decode(obj, DecoderContext(pek_list=None))
    assert result.get("credentials") is None


# --- TrustDecoder metadata via the registry ---


def test_trust_decoder_metadata():
    obj = MockObject(
        attrs={"objectClass": ["trustedDomain"], "DNT": 5, "trustPartner": "corp.local", "flatName": "CORP", "trustType": 2, "trustDirection": 3, "trustAttributes": 8},
    )
    result = build_default_registry().get(obj.object_class).decode(obj, DecoderContext())
    assert result["trustPartner"] == "corp.local"
    assert result["trustType"] == "UPLEVEL"
    assert result["trustDirection"]["flags"] == ["INBOUND", "OUTBOUND"]
    assert result["trustAttributes"]["flags"] == ["FOREST_TRANSITIVE"]


# --- Supplemental merge (maps dissect/parsed properties into creds) ---


def test_merge_supplemental_maps_all_types():
    creds: dict[str, object] = {}
    merge_supplemental(
        {
            "Primary:Kerberos-Newer-Keys": {
                "DefaultSalt": "CORP.LOCALhostuser".encode("utf-16-le"),
                "Credentials": [
                    {"KeyType": 18, "Key": bytes.fromhex("aa" * 32), "IterationCount": 4096},
                    {"KeyType": 3, "Key": bytes.fromhex("bb" * 8), "IterationCount": 4096},
                ],
            },
            "Primary:WDigest": [b"\x01" * 16],
            "Primary:CLEARTEXT": "Sup3r$ecret",
            "Primary:NTLM-Strong-NTOWF": b"\x02" * 16,
        },
        creds,
    )
    kerb = creds["kerberos"]
    assert kerb[0]["etype"] == 18
    assert kerb[0]["etypeName"] == "AES256-CTS-HMAC-SHA1-96"
    assert kerb[0]["key"] == "aa" * 32
    assert kerb[0]["salt"] == "CORP.LOCALhostuser"
    assert kerb[1]["etype"] == 3
    assert creds["wdigest"] == ["01" * 16]
    assert creds["cleartextPassword"] == "Sup3r$ecret"
    assert creds["ntlmStrongNTOWF"] == "02" * 16


def test_apply_naming_modes():
    base = {"distinguishedName": "CN=A,OU=x,DC=y", "sAMAccountName": "alice", "name": "A"}
    dn = dict(base)
    UserDecoder._apply_naming(dn, "dn")
    assert dn["_name"] == "CN=A,OU=x,DC=y"
    sam = dict(base)
    UserDecoder._apply_naming(sam, "sam")
    assert sam["_name"] == "alice"
    cn = dict(base)
    UserDecoder._apply_naming(cn, "cn")
    assert cn["_name"] == "A"  # no cn key -> falls back to name


def test_registry_is_built_with_expected_size():
    registry = build_default_registry()
    assert isinstance(registry, DecoderRegistry)
    assert len(registry) >= 8
