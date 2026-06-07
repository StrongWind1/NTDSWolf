"""End-to-end integration tests against public synthetic NTDS fixtures.

Fixtures come from skelsec/aesedb (synthetic test databases, paired ntds.dit +
SYSTEM across Windows Server versions). They are large binaries kept out of git;
these tests skip when the fixtures are absent, so CI stays green without them.

To fetch them locally::

    BASE=https://raw.githubusercontent.com/skelsec/aesedb/main/tests/testdata
    for v in win2012_64 win2016_64 win2019_64_clear; do
      mkdir -p tests/fixtures/aesedb/$v
      curl -sL -o tests/fixtures/aesedb/$v/ntds.dit "$BASE/$v/ntds.dit"
      curl -sL -o tests/fixtures/aesedb/$v/SYSTEM "$BASE/$v/SYSTEM"
    done
"""

from __future__ import annotations

import multiprocessing
from functools import cache
from pathlib import Path

import pytest

from ntdswolf.core.database import NTDSDatabase
from ntdswolf.core.pipeline import ExtractionConfig, PipelineOrchestrator
from ntdswolf.crypto.bootkey import resolve_bootkey
from ntdswolf.crypto.pek import PEKList
from ntdswolf.decoders.base import DecoderContext
from ntdswolf.decoders.registry import build_default_registry

_FIXTURES = Path(__file__).parent / "fixtures" / "aesedb"

# Administrator shares this password (and therefore NT hash) across the aesedb
# test databases; a wrong RID (the SID-endianness bug) corrupts this value.
_ADMIN_NT = "f8963568a1ec62a3161d9d6449baba93"


@cache
def _extract_accounts(version: str) -> dict[str, dict]:
    """Decode all user/computer accounts from a fixture, keyed by sAMAccountName."""
    base = _FIXTURES / version
    if not (base / "ntds.dit").is_file() or not (base / "SYSTEM").is_file():
        pytest.skip(f"aesedb fixture {version!r} not present")

    db = NTDSDatabase.open(base / "ntds.dit")
    db.pek.unlock(resolve_bootkey(None, base / "SYSTEM", None))
    ctx = DecoderContext(pek_list=PEKList(keys=dict(db.pek.keys)))
    registry = build_default_registry()

    accounts: dict[str, dict] = {}
    for obj in db.iter_all():
        try:
            classes = obj.object_class
        except (AttributeError, ValueError, KeyError, TypeError):
            continue
        if not classes or classes[0] not in ("user", "computer"):
            continue
        decoded = registry.get(classes).decode(obj, ctx)
        sam = decoded.get("sAMAccountName")
        if sam:
            accounts[sam] = decoded
    return accounts


@pytest.mark.parametrize("version", ["win2008r2_64", "win2012_64", "win2016_64", "win2019_64", "win2022_64"])
def test_administrator_rid_and_nt_hash(version):
    admin = _extract_accounts(version).get("Administrator")
    assert admin is not None
    assert admin["objectSid"].endswith("-500")  # RID 500, not the byte-swapped value
    assert admin["credentials"]["ntHash"] == _ADMIN_NT


def test_guest_no_password_account_has_empty_nt_hash_win2016():
    # impacket parity: built-in accounts with no password are emitted with the
    # empty NT hash (MD4 of "") rather than dropped.
    guest = _extract_accounts("win2016_64").get("Guest")
    assert guest is not None
    assert guest["objectSid"].endswith("-501")
    assert guest["credentials"]["ntHash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_krbtgt_rid_502_win2016():
    krbtgt = _extract_accounts("win2016_64").get("krbtgt")
    assert krbtgt is not None
    assert krbtgt["objectSid"].endswith("-502")


def test_kerberos_keys_extracted_win2016():
    accounts = _extract_accounts("win2016_64")
    kerb = next((c["kerberos"] for a in accounts.values() if (c := a.get("credentials")) and c.get("kerberos")), None)
    assert kerb is not None
    by_etype = {k["etype"]: k for k in kerb}
    assert 18 in by_etype  # AES256
    assert 17 in by_etype  # AES128
    assert by_etype[18]["etypeName"] == "AES256-CTS-HMAC-SHA1-96"
    assert len(by_etype[18]["key"]) == 64  # 32-byte key as hex
    assert len(by_etype[17]["key"]) == 32  # 16-byte key as hex


def test_wdigest_has_29_hashes_win2016():
    accounts = _extract_accounts("win2016_64")
    wdigest = next((c["wdigest"] for a in accounts.values() if (c := a.get("credentials")) and c.get("wdigest")), None)
    assert wdigest is not None
    assert len(wdigest) == 29
    assert all(len(h) == 32 for h in wdigest)


def test_cleartext_password_win2019_clear():
    accounts = _extract_accounts("win2019_64_clear")
    cleartexts = {c.get("cleartextPassword") for a in accounts.values() if (c := a.get("credentials"))}
    assert "Passw0rd!1" in cleartexts


def test_security_descriptor_sddl_win2016():
    admin = _extract_accounts("win2016_64").get("Administrator")
    assert admin is not None
    sddl = admin.get("nTSecurityDescriptor")
    assert isinstance(sddl, str)
    assert sddl.startswith("O:")  # owner section
    assert "D:" in sddl  # DACL section
    assert sddl.count("(") >= 1  # at least one ACE


def test_replication_metadata_win2016():
    admin = _extract_accounts("win2016_64").get("Administrator")
    meta = admin.get("replPropertyMetaData")
    assert isinstance(meta, list)
    assert len(meta) > 0
    by_attr = {e["attribute"]: e for e in meta}
    assert "objectClass" in by_attr  # attribute id resolved to its name
    oc = by_attr["objectClass"]
    assert oc["version"] >= 1
    assert oc["originatingChange"].startswith("20")  # plausible ISO year (20xx)
    assert isinstance(oc["originatingUSN"], int)


def test_service_principal_names_win2016():
    accounts = _extract_accounts("win2016_64")
    spns = next((a.get("servicePrincipalName") for a in accounts.values() if a.get("servicePrincipalName")), None)
    assert spns is not None
    assert any(s.startswith("ldap/") for s in spns)


def test_naming_modes_win2016():
    base = _FIXTURES / "win2016_64"
    if not (base / "ntds.dit").is_file() or not (base / "SYSTEM").is_file():
        pytest.skip("aesedb fixture win2016_64 not present")
    db = NTDSDatabase.open(base / "ntds.dit")
    db.pek.unlock(resolve_bootkey(None, base / "SYSTEM", None))
    registry = build_default_registry()
    for obj in db.iter_all():
        try:
            if obj.get("sAMAccountName") != "Administrator":
                continue
        except (AttributeError, ValueError, KeyError, TypeError):
            continue
        dn = registry.get(obj.object_class).decode(obj, DecoderContext(naming="dn"))
        sam = registry.get(obj.object_class).decode(obj, DecoderContext(naming="sam"))
        assert dn["_name"] == dn["distinguishedName"]
        assert sam["_name"] == "Administrator"
        return
    pytest.fail("Administrator not found")


def test_gpo_and_domain_decoders_win2016():
    base = _FIXTURES / "win2016_64"
    if not (base / "ntds.dit").is_file() or not (base / "SYSTEM").is_file():
        pytest.skip("aesedb fixture win2016_64 not present")
    db = NTDSDatabase.open(base / "ntds.dit")
    db.pek.unlock(resolve_bootkey(None, base / "SYSTEM", None))
    registry = build_default_registry()
    gpo = domain = None
    for obj in db.iter_all():
        try:
            classes = obj.object_class
        except (AttributeError, ValueError, KeyError, TypeError):
            continue
        if not classes:
            continue
        if classes[0] == "groupPolicyContainer" and gpo is None:
            gpo = registry.get(classes).decode(obj, DecoderContext())
        if classes[0] == "domainDNS" and domain is None:
            domain = registry.get(classes).decode(obj, DecoderContext())
        if gpo and domain:
            break
    assert gpo is not None
    assert gpo.get("displayName")
    assert str(gpo.get("gPCFileSysPath", "")).startswith("\\\\")
    assert domain is not None
    assert domain.get("msDS-Behavior-Version") is not None
    pwd_props = domain.get("pwdProperties")
    assert isinstance(pwd_props, dict)
    assert "flags" in pwd_props


def _run_format(version: str, tmp_path: Path, fmt: str, *, extract_classes: set[str] | None = None, label: str = "out") -> Path:
    """Run the full pipeline to a hash output format and return the output directory."""
    base = _FIXTURES / version
    if not (base / "ntds.dit").is_file() or not (base / "SYSTEM").is_file():
        pytest.skip(f"aesedb fixture {version!r} not present")
    out_dir = tmp_path / label
    PipelineOrchestrator(
        ExtractionConfig(
            ntds_path=base / "ntds.dit",
            system_path=base / "SYSTEM",
            output_dir=out_dir,
            output_format=fmt,
            extract_classes=extract_classes,
            quiet=True,
        )
    ).run()
    return out_dir


def test_hashcat_emits_no_kerberos_keys_win2016(tmp_path):
    # The hashcat writer outputs only crackable NT/LM hashes. Kerberos keys are
    # pass-the-key material, not hashcat-crackable, so they are intentionally
    # omitted (they live in the pwdump .ntds.kerberos sidecar instead).
    out_dir = _run_format("win2016_64", tmp_path, "hashcat")
    names = sorted(p.name for p in out_dir.iterdir())
    assert names  # something was written
    assert all("kerberos" not in n and "krb" not in n for n in names)
    # The NT hashes are present as username:hash lines for `hashcat --username`.
    nt_users = out_dir / "ntlm_user_current.txt"
    assert nt_users.is_file()
    admin = [ln for ln in nt_users.read_text().splitlines() if ln.startswith("Administrator:")]
    assert admin
    assert len(admin[0].split(":", 1)[1]) == 32  # full 32-hex NT hash


def test_pwdump_kerberos_file_matches_secretsdump_win2016(tmp_path):
    # R-7.1: decoded Kerberos keys reach the secretsdump-format output as
    # principal:etype:key, with lowercase etypes and no RC4 (RC4 == the NT hash).
    out_dir = _run_format("win2016_64", tmp_path, "pwdump")
    kerb_file = out_dir / "hashes.ntds.kerberos"
    assert kerb_file.is_file()
    lines = kerb_file.read_text().splitlines()
    assert lines
    allowed = {"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des-cbc-md5"}
    for ln in lines:
        principal, etype, key = ln.split(":")
        assert principal  # non-empty principal
        assert etype in allowed  # lowercase etype label, never RC4
        assert key  # non-empty key
    aes256 = [ln for ln in lines if ":aes256-cts-hmac-sha1-96:" in ln]
    assert aes256
    assert len(aes256[0].split(":")[2]) == 64  # 32-byte AES256 key as hex


def test_pwdump_history_matches_secretsdump_win2016(tmp_path):
    # Regression: ntPwdHistory was silently dropped (dissect returns it as a
    # one-element list, which failed an isinstance(bytes) check) and the AES
    # padding block was stripped by unpad(). krbtgt's history must now match
    # `secretsdump -history` byte-for-byte, including the DES-un-obfuscated
    # trailing padding block secretsdump emits as history0.
    out_dir = _run_format("win2016_64", tmp_path, "pwdump")
    lines = (out_dir / "hashes.ntds").read_text().splitlines()
    assert "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:07eeeab9174bbe37ca33e062801819cc:::" in lines
    assert "krbtgt_history0:502:aad3b435b51404eeaad3b435b51404ee:b5ca59b606a13445af2043409d2c0086:::" in lines


def test_extract_filter_respected_by_hashcat_format_win2016(tmp_path):
    # R-7.2: --extract must filter credential-bearing classes too. Machine
    # accounts (sAMAccountName ending in "$") must not leak into a users-only
    # run, and vice versa.
    users_dir = _run_format("win2016_64", tmp_path, "hashcat", extract_classes={"user"}, label="users")
    computers_dir = _run_format("win2016_64", tmp_path, "hashcat", extract_classes={"computer"}, label="computers")

    def _usernames(out_dir: Path, filename: str) -> list[str]:
        f = out_dir / filename  # username:hash per line (sAMAccountName by default)
        assert f.is_file()
        return [line.split(":", 1)[0] for line in f.read_text().splitlines()]

    user_names = _usernames(users_dir, "ntlm_user_current.txt")
    computer_names = _usernames(computers_dir, "ntlm_computer_current.txt")
    assert "Administrator" in user_names
    assert all(not n.endswith("$") for n in user_names)  # no machine accounts leaked in
    assert all(n.endswith("$") for n in computer_names)  # only machine accounts
    # A users-only run must not produce a computer hash file, and vice versa.
    assert not (users_dir / "ntlm_computer_current.txt").exists()
    assert not (computers_dir / "ntlm_user_current.txt").exists()


def test_parallel_extraction_matches_single_threaded(tmp_path):
    base = _FIXTURES / "win2016_64"
    if not (base / "ntds.dit").is_file() or not (base / "SYSTEM").is_file():
        pytest.skip("aesedb fixture win2016_64 not present")
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork start method unavailable")

    def _run(workers: int) -> list[str]:
        out_dir = tmp_path / f"workers{workers}"
        PipelineOrchestrator(
            ExtractionConfig(
                ntds_path=base / "ntds.dit",
                system_path=base / "SYSTEM",
                output_dir=out_dir,
                output_format="ndjson",
                workers=workers,
                quiet=True,
            )
        ).run()
        lines: list[str] = []
        for ndjson in sorted(out_dir.glob("*.ndjson")):
            lines.extend(ndjson.read_text().splitlines())
        return sorted(lines)

    assert _run(2) == _run(1)
