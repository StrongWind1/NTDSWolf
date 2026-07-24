# SPDX-License-Identifier: Apache-2.0
r"""secretsdump-compatible "newer pwdump" output writer.

Produces files byte-compatible with ``impacket-secretsdump -outputfile``:

    hashes.ntds            username:rid:lm:nt:::   (+ inline username_historyN lines)
    hashes.ntds.kerberos   username:<etype>:<key>  (lowercase etypes, no RC4)
    hashes.ntds.cleartext  username:CLEARTEXT:<password>

This is the modern "pwdump" format secretsdump emits. It supersedes the classic
``username:rid:lm:nt:::`` pwdump by adding the Kerberos-key and cleartext sidecar
files; the ``.ntds`` line itself is the same format NTDSWolf already produces
byte-identically to secretsdump on single-domain databases.

Objects without credentials are silently skipped.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, cast

from ntdswolf.constants import (
    KERBEROS_ETYPE_AES128_CTS_HMAC_SHA1_96,
    KERBEROS_ETYPE_AES256_CTS_HMAC_SHA1_96,
    KERBEROS_ETYPE_DES_CBC_CRC,
    KERBEROS_ETYPE_DES_CBC_MD5,
    KERBEROS_KEYTYPE_RC4_MS,
    SID_RSPLIT_PART_COUNT,
)
from ntdswolf.output.credfiles import account_username

if TYPE_CHECKING:
    import io
    from pathlib import Path

logger = logging.getLogger(__name__)

# LM/NT hash of an empty password -- secretsdump substitutes these when an
# account has no stored LM/NT hash.
_EMPTY_LM_HASH: str = "aad3b435b51404eeaad3b435b51404ee"
_EMPTY_NT_HASH: str = "31d6cfe0d16ae931b73c59d7e0c089c0"

# Default RID when the objectSid cannot be parsed (should not happen in a
# well-formed NTDS.dit).
_DEFAULT_RID: int = 0

# Length of a valid hex-encoded 16-byte NT/LM hash.
_HASH_HEX_LEN: int = 32

_WRITE_BUFFER_SIZE: int = 65_536

# Numeric Kerberos KeyType -> secretsdump's label, mirroring impacket's
# NTDSHashes.KERBEROS_TYPE exactly: the "dec-cbc-crc" spelling, and rc4_hmac for
# the 0xFFFFFF74 marker Windows stores for the RC4 / NT-hash key. Keyed on the
# numeric KeyType (not the name) so both selection and labels match byte-for-byte;
# any KeyType outside this table falls back to its hex form. Server 2008 databases
# carry all five KeyTypes; 2016+ store only AES256/AES128/DES-CBC-MD5.
_SECRETSDUMP_ETYPES: dict[int, str] = {
    KERBEROS_ETYPE_DES_CBC_CRC: "dec-cbc-crc",
    KERBEROS_ETYPE_DES_CBC_MD5: "des-cbc-md5",
    KERBEROS_ETYPE_AES128_CTS_HMAC_SHA1_96: "aes128-cts-hmac-sha1-96",
    KERBEROS_ETYPE_AES256_CTS_HMAC_SHA1_96: "aes256-cts-hmac-sha1-96",
    KERBEROS_KEYTYPE_RC4_MS: "rc4_hmac",
}


class PwdumpWriter:
    r"""secretsdump-format writer: ``.ntds`` + ``.ntds.kerberos`` + ``.ntds.cleartext``."""

    def __init__(self) -> None:
        """Initialize the writer in a closed state; files open lazily on first matching write."""
        self._ntds: io.TextIOWrapper | None = None
        self._kerberos: io.TextIOWrapper | None = None
        self._cleartext: io.TextIOWrapper | None = None
        self._output_dir: Path | None = None

    def open(self, output_dir: Path, _object_class: str) -> None:
        """Store the output directory; the three secretsdump files are created on demand."""
        self._output_dir = output_dir
        logger.debug("Pwdump (secretsdump) writer ready, output dir: %s", output_dir)

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Emit this object's NTLM line, Kerberos keys, and cleartext in secretsdump format."""
        credentials = obj_dict.get("credentials")
        if not isinstance(credentials, dict):
            return
        username = _secretsdump_username(obj_dict)
        rid = _extract_rid(obj_dict)
        self._write_ntds(credentials, username, rid)
        self._write_kerberos(credentials, username)
        self._write_cleartext(credentials, username)

    def _write_ntds(self, credentials: dict[str, object], username: str, rid: int) -> None:
        """Write the current ``username:rid:lm:nt:::`` line plus inline ``_historyN`` lines."""
        nt = _validate_hash(credentials.get("ntHash"))
        lm = _validate_hash(credentials.get("lmHash"))
        if nt is not None or lm is not None:
            self._ntds_line(f"{username}:{rid}:{lm or _EMPTY_LM_HASH}:{nt or _EMPTY_NT_HASH}:::")

        # secretsdump pairs NT/LM history via zip (shortest wins) and, with its
        # NTDS default of noLMHash=True, forces the LM field to the empty-LM
        # constant -- the LM history values matter only for their count.
        nt_hist = credentials.get("ntHistory")
        lm_hist = credentials.get("lmHistory")
        nt_hist = nt_hist if isinstance(nt_hist, list) else []
        lm_hist = lm_hist if isinstance(lm_hist, list) else []
        for idx in range(min(len(nt_hist), len(lm_hist))):
            h_nt = _validate_hash(nt_hist[idx]) or _EMPTY_NT_HASH
            self._ntds_line(f"{username}_history{idx}:{rid}:{_EMPTY_LM_HASH}:{h_nt}:::")

    def _write_kerberos(self, credentials: dict[str, object], username: str) -> None:
        """Write ``username:<label>:<key>`` lines, mirroring secretsdump's KERBEROS_TYPE.

        Keyed on the numeric Kerberos KeyType (not the etype name), so both the
        selection and the labels match impacket byte-for-byte: known KeyTypes use
        secretsdump's label, any other uses its hex form (``0x...``). Every current
        Kerberos key in supplementalCredentials is emitted, in stored order.
        """
        keys = credentials.get("kerberos")
        if not isinstance(keys, list):
            return
        for entry in keys:
            if not isinstance(entry, dict):
                continue
            key_entry = cast("dict[str, object]", entry)
            etype = key_entry.get("etype")
            key = key_entry.get("key")
            if not isinstance(etype, int) or not isinstance(key, str) or not key:
                continue
            label = _SECRETSDUMP_ETYPES.get(etype, hex(etype))
            self._kerberos_line(f"{username}:{label}:{key}")

    def _write_cleartext(self, credentials: dict[str, object], username: str) -> None:
        """Write the ``username:CLEARTEXT:<password>`` line for reversibly-encrypted passwords."""
        pw = credentials.get("cleartextPassword")
        if isinstance(pw, str) and pw:
            self._cleartext_line(f"{username}:CLEARTEXT:{pw}")

    # --- line writers (open the relevant file on first use) ---

    def _ntds_line(self, line: str) -> None:
        if self._ntds is None:
            self._ntds = self._open("hashes.ntds")
        self._ntds.write(line + "\n")

    def _kerberos_line(self, line: str) -> None:
        if self._kerberos is None:
            self._kerberos = self._open("hashes.ntds.kerberos")
        self._kerberos.write(line + "\n")

    def _cleartext_line(self, line: str) -> None:
        if self._cleartext is None:
            self._cleartext = self._open("hashes.ntds.cleartext")
        self._cleartext.write(line + "\n")

    def _open(self, filename: str) -> io.TextIOWrapper:
        if self._output_dir is None:
            msg = "Writer not opened: call open() before write()"
            raise RuntimeError(msg)
        return (self._output_dir / filename).open(mode="w", encoding="utf-8", newline="\n", buffering=_WRITE_BUFFER_SIZE)

    def close(self) -> None:
        """Close every open output file (idempotent)."""
        for fh in (self._ntds, self._kerberos, self._cleartext):
            if fh is not None:
                fh.close()
        self._ntds = None
        self._kerberos = None
        self._cleartext = None


def _validate_hash(value: object) -> str | None:
    """Return the hash string if it is exactly 32 hex characters, else None."""
    if isinstance(value, str) and len(value) == _HASH_HEX_LEN:
        return value
    return None


def _extract_rid(obj_dict: dict[str, Any]) -> int:
    """Return the RID (last objectSid component), or 0 if the SID cannot be parsed."""
    sid = obj_dict.get("objectSid")
    if not isinstance(sid, str):
        return _DEFAULT_RID
    parts = sid.rsplit("-", maxsplit=1)
    if len(parts) == SID_RSPLIT_PART_COUNT:
        try:
            return int(parts[1])
        except ValueError:
            logger.warning("Could not parse RID from SID: %s", sid)
            return _DEFAULT_RID
    return _DEFAULT_RID


def _secretsdump_username(obj_dict: dict[str, Any]) -> str:
    r"""Return the username exactly as secretsdump writes it.

    secretsdump prefixes ``<UPN-domain>\`` only for accounts that carry a
    userPrincipalName (e.g. ``test@TEST.corp`` -> ``TEST.corp\test``); built-in
    and machine accounts, which have no UPN, are emitted as the bare
    sAMAccountName.
    """
    sam = account_username(obj_dict)
    upn = obj_dict.get("userPrincipalName")
    if isinstance(upn, str) and "@" in upn:
        domain = upn.rsplit("@", 1)[1]
        if domain:
            return f"{domain}\\{sam}"
    return sam
