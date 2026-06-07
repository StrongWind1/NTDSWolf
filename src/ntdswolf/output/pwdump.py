"""Classic pwdump format hash output writer -- username:rid:lm:nt::: lines."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ntdswolf.constants import SID_RSPLIT_PART_COUNT
from ntdswolf.output.credfiles import account_domain, account_username, credential_principal, kerberos_key_lines, trust_credential_lines

if TYPE_CHECKING:
    import io
    from pathlib import Path

logger = logging.getLogger(__name__)

# The classic pwdump format has been around since the original L0phtCrack days:
#   username:rid:lm_hash:nt_hash:::
# The trailing three colons represent empty fields (comment, homedir, etc.)
# that were part of the original Unix passwd format adaptation.

# Empty LM hash value -- used when no LM hash is available for an account.
# This is the LM hash of an empty password and signals "no LM hash stored".
_EMPTY_LM_HASH: str = "aad3b435b51404eeaad3b435b51404ee"

# Empty NT hash value -- used when no NT hash is available.
_EMPTY_NT_HASH: str = "31d6cfe0d16ae931b73c59d7e0c089c0"

# Default RID when the objectSid cannot be parsed. This should not happen
# in a well-formed NTDS.dit, but we handle it defensively.
_DEFAULT_RID: int = 0

# Write buffer size for output files (64KB).
_WRITE_BUFFER_SIZE: int = 65_536


class PwdumpWriter:
    """Classic pwdump format hash output writer.

    Produces hash files in the traditional pwdump format used by tools
    like L0phtCrack, ophcrack, and many others::

        jsmith:1104:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::
        Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::

    Format breakdown: ``username:rid:lm_hash:nt_hash:::``

    Output files:

    - ``hashes.pwdump`` -- current hashes for all credentialed objects.
    - ``hashes_history.pwdump`` -- historical hashes (only created if any
      objects contain hash history entries).
    - ``kerberos_keys.txt`` -- ``principal:etype:key`` Kerberos keys for
      pass-the-key (only created if any object carries decoded keys).

    History entries use the format ``username__historyN:rid:lm:nt:::``
    where N is the zero-based history index.

    Objects without credentials are silently skipped.
    """

    def __init__(self) -> None:
        """Initialize the writer in a closed state."""
        self._file: io.TextIOWrapper | None = None
        self._history_file: io.TextIOWrapper | None = None
        self._kerberos_file: io.TextIOWrapper | None = None
        self._output_dir: Path | None = None

    def open(self, output_dir: Path, _object_class: str) -> None:
        """Store the output directory for lazy file creation.

        Files are created on demand when the first relevant hash data
        arrives, avoiding empty output files.

        Args:
            output_dir: Directory where hash files will be written.
            _object_class: Ignored. Pwdump writer uses fixed filenames.

        """
        self._output_dir = output_dir
        logger.debug("Pwdump writer ready, output dir: %s", output_dir)

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Extract hashes from an object and write in pwdump format.

        Each line follows ``username:rid:lm_hash:nt_hash:::``. If either
        hash is missing, the well-known empty hash value is substituted.

        The RID is extracted from the ``objectSid`` field by taking the
        last component after the final hyphen (e.g.
        ``S-1-5-21-...-1104`` -> RID ``1104``).

        Silently returns if the object has no credentials or no hash data.

        Args:
            obj_dict: Serialized AD object dict from a decoder.

        """
        # Trust objects carry keys under trustCredentials (not credentials), so
        # emit those before the credentials early-return below.
        self._write_kerberos_lines(trust_credential_lines(obj_dict))

        credentials = obj_dict.get("credentials")
        if not isinstance(credentials, dict):
            return

        # Extract identity fields needed for the pwdump line.
        username = account_username(obj_dict)
        rid = _extract_rid(obj_dict)

        self._write_current_hashes(credentials, username, rid)
        self._write_history_hashes(credentials, username, rid)
        self._write_kerberos(credentials, obj_dict)

    def _write_kerberos(self, credentials: dict[str, object], obj_dict: dict[str, Any]) -> None:
        """Write Kerberos keys to kerberos_keys.txt as ``principal:etype:key``."""
        principal = credential_principal(account_domain(obj_dict), account_username(obj_dict))
        self._write_kerberos_lines(kerberos_key_lines(credentials, principal))

    def _write_kerberos_lines(self, lines: list[str]) -> None:
        """Append already-formatted ``principal:etype:key`` lines to kerberos_keys.txt."""
        if not lines:
            return
        self._ensure_kerberos_file()
        if self._kerberos_file is None:
            msg = "Kerberos keys file not opened: _ensure_kerberos_file() failed"
            raise RuntimeError(msg)
        self._kerberos_file.write("\n".join(lines) + "\n")

    def _write_current_hashes(self, credentials: dict[str, object], username: str, rid: int) -> None:
        """Write the current NT/LM hash line if at least one hash is present."""
        nt_hash = _validate_hash(credentials.get("ntHash"))
        lm_hash = _validate_hash(credentials.get("lmHash"))

        if nt_hash is not None or lm_hash is not None:
            self._ensure_main_file()
            if self._file is None:
                msg = "Main hash file not opened: _ensure_main_file() failed"
                raise RuntimeError(msg)

            effective_nt = nt_hash if nt_hash is not None else _EMPTY_NT_HASH
            effective_lm = lm_hash if lm_hash is not None else _EMPTY_LM_HASH

            # Classic pwdump format: username:rid:lm_hash:nt_hash:::
            self._file.write(f"{username}:{rid}:{effective_lm}:{effective_nt}:::\n")

    def _write_history_hashes(self, credentials: dict[str, object], username: str, rid: int) -> None:
        """Write paired NT/LM history hash lines."""
        nt_history = credentials.get("ntHistory", [])
        lm_history = credentials.get("lmHistory", [])

        if not isinstance(nt_history, list):
            nt_history = []
        if not isinstance(lm_history, list):
            lm_history = []

        max_history = max(len(nt_history), len(lm_history))

        for idx in range(max_history):
            hist_nt = _validate_hash(nt_history[idx]) if idx < len(nt_history) else None
            hist_lm = _validate_hash(lm_history[idx]) if idx < len(lm_history) else None

            if hist_nt is not None or hist_lm is not None:
                self._ensure_history_file()
                if self._history_file is None:
                    msg = "History file not opened: _ensure_history_file() failed"
                    raise RuntimeError(msg)

                effective_hist_nt = hist_nt if hist_nt is not None else _EMPTY_NT_HASH
                effective_hist_lm = hist_lm if hist_lm is not None else _EMPTY_LM_HASH

                hist_username = f"{username}__history{idx}"
                self._history_file.write(f"{hist_username}:{rid}:{effective_hist_lm}:{effective_hist_nt}:::\n")

    def close(self) -> None:
        """Close all open output files.

        Safe to call multiple times -- subsequent calls are no-ops.
        """
        if self._file is not None:
            self._file.close()
            self._file = None
            logger.debug("Closed pwdump output: hashes.pwdump")

        if self._history_file is not None:
            self._history_file.close()
            self._history_file = None
            logger.debug("Closed pwdump output: hashes_history.pwdump")

        if self._kerberos_file is not None:
            self._kerberos_file.close()
            self._kerberos_file = None
            logger.debug("Closed pwdump output: kerberos_keys.txt")

    # --- Lazy file creation helpers ---

    def _ensure_main_file(self) -> None:
        """Open the main hash file if not already open."""
        if self._file is None:
            if self._output_dir is None:
                msg = "Writer not opened: call open() before write()"
                raise RuntimeError(msg)
            path = self._output_dir / "hashes.pwdump"
            self._file = path.open(mode="w", encoding="utf-8", buffering=_WRITE_BUFFER_SIZE)

    def _ensure_history_file(self) -> None:
        """Open the history hash file if not already open."""
        if self._history_file is None:
            if self._output_dir is None:
                msg = "Writer not opened: call open() before write()"
                raise RuntimeError(msg)
            path = self._output_dir / "hashes_history.pwdump"
            self._history_file = path.open(mode="w", encoding="utf-8", buffering=_WRITE_BUFFER_SIZE)

    def _ensure_kerberos_file(self) -> None:
        """Open the Kerberos keys file if not already open."""
        if self._kerberos_file is None:
            if self._output_dir is None:
                msg = "Writer not opened: call open() before write()"
                raise RuntimeError(msg)
            path = self._output_dir / "kerberos_keys.txt"
            self._kerberos_file = path.open(mode="w", encoding="utf-8", buffering=_WRITE_BUFFER_SIZE)


# --- Hash validation ---

# Length of a valid hex-encoded 16-byte hash (NT or LM).
_HASH_HEX_LEN: int = 32


def _validate_hash(value: object) -> str | None:
    """Return the hash string if it is exactly 32 hex characters, else None."""
    if isinstance(value, str) and len(value) == _HASH_HEX_LEN:
        return value
    return None


# --- Identity extraction helpers ---


def _extract_rid(obj_dict: dict[str, Any]) -> int:
    """Extract the RID (Relative Identifier) from the object's SID.

    The RID is the last component of an AD SID string. For example,
    ``S-1-5-21-3623811015-3361044348-30300510-1104`` has RID ``1104``.

    The RID is the per-domain unique identifier used in the pwdump format
    to differentiate accounts. Well-known accounts have well-known RIDs
    (e.g. Administrator=500, Guest=501).

    Args:
        obj_dict: Serialized AD object dict.

    Returns:
        The integer RID, or 0 if the SID cannot be parsed.

    """
    sid = obj_dict.get("objectSid")
    if not isinstance(sid, str):
        return _DEFAULT_RID

    # SID format: S-1-5-21-<sub1>-<sub2>-<sub3>-<rid>
    # The RID is always the last hyphen-separated component.
    parts = sid.rsplit("-", maxsplit=1)
    if len(parts) == SID_RSPLIT_PART_COUNT:
        try:
            return int(parts[1])
        except ValueError:
            # Malformed SID -- the last component is not a number.
            logger.warning("Could not parse RID from SID: %s", sid)
            return _DEFAULT_RID

    return _DEFAULT_RID
