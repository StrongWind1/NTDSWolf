"""Hashcat-compatible hash output writer -- NT/LM hashes split for mode 1000/3000."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ntdswolf.constants import MD4_HEX_LENGTH
from ntdswolf.output.credfiles import account_domain, account_username, credential_principal, kerberos_key_lines, trust_credential_lines

if TYPE_CHECKING:
    import io
    from pathlib import Path

logger = logging.getLogger(__name__)

# Well-known empty hash values. These represent accounts with no password
# set and are generally excluded from cracking runs, but we still write
# them to the output for completeness. The user can grep them out.
_EMPTY_LM_HASH: str = "aad3b435b51404eeaad3b435b51404ee"
_EMPTY_NT_HASH: str = "31d6cfe0d16ae931b73c59d7e0c089c0"

# LM hashes are 16 bytes (32 hex chars). Each half is an independent
# DES-encrypted block that hashcat cracks separately as mode 3000.
_LM_HALF_LEN: int = 16  # 16 hex chars = 8 bytes per half

# Write buffer size for output files (64KB).
_WRITE_BUFFER_SIZE: int = 65_536


class HashcatWriter:
    r"""Hashcat-compatible hash output writer.

    Produces hash files suitable for direct use with ``hashcat``:

    - ``hashes_nt.hashcat`` -- one bare NT hash per line (mode 1000).
    - ``hashes_lm.hashcat`` -- LM hash halves, one per line (mode 3000).
    - ``hashes_nt.hashcat.users`` -- mapping file with ``hash:DOMAIN\\username``
      entries for correlating cracked results back to accounts.
    - ``hashes_nt_history.hashcat`` -- historical NT hashes (optional, only
      written if any objects contain NT hash history).
    - ``hashes_lm_history.hashcat`` -- historical LM hash halves (optional).
    - ``kerberos_keys.txt`` -- ``principal:etype:key`` lines for pass-the-key
      (optional, only written if any objects carry decoded Kerberos keys).

    Objects without credentials are silently skipped. This writer receives
    all object types from the OutputManager but only processes those with
    a ``credentials`` dict containing hash data.

    Usage with hashcat::

        hashcat -m 1000 hashes_nt.hashcat wordlist.txt
        hashcat -m 3000 hashes_lm.hashcat wordlist.txt
    """

    def __init__(self) -> None:
        """Initialize the writer in a closed state."""
        # File handles for each output file. Opened lazily on first relevant write.
        self._nt_file: io.TextIOWrapper | None = None
        self._lm_file: io.TextIOWrapper | None = None
        self._nt_users_file: io.TextIOWrapper | None = None
        self._nt_history_file: io.TextIOWrapper | None = None
        self._lm_history_file: io.TextIOWrapper | None = None
        self._kerberos_file: io.TextIOWrapper | None = None
        self._output_dir: Path | None = None

    def open(self, output_dir: Path, _object_class: str) -> None:
        """Store the output directory for lazy file creation.

        Files are not actually opened here -- they are created on demand
        when the first relevant hash data arrives. This avoids creating
        empty files when no credentialed objects exist.

        Args:
            output_dir: Directory where hash files will be written.
            _object_class: Ignored. Hashcat writer uses fixed filenames.

        """
        self._output_dir = output_dir
        logger.debug("Hashcat writer ready, output dir: %s", output_dir)

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Extract hashes from an object and write them in hashcat format.

        Silently returns if the object has no ``credentials`` key or if
        the credentials contain no hash data.

        Args:
            obj_dict: Serialized AD object dict from a decoder.

        """
        # Trust objects carry keys under trustCredentials (not credentials), so
        # emit those before the credentials early-return below.
        self._write_kerberos_lines(trust_credential_lines(obj_dict))

        credentials = obj_dict.get("credentials")
        if not isinstance(credentials, dict):
            # No credentials on this object -- skip silently.
            return

        # Build the username string for the mapping file.
        # Prefer sAMAccountName, fall back to the DN-derived name.
        username = account_username(obj_dict)
        domain = account_domain(obj_dict)

        self._write_nt_hash(credentials, username, domain)
        self._write_lm_hash(credentials)
        self._write_nt_history(credentials)
        self._write_lm_history(credentials)
        self._write_kerberos(credentials, username, domain)

    def _write_kerberos(self, credentials: dict[str, object], username: str, domain: str) -> None:
        """Write Kerberos keys as ``principal:etype:key`` for pass-the-key use."""
        self._write_kerberos_lines(kerberos_key_lines(credentials, credential_principal(domain, username)))

    def _write_kerberos_lines(self, lines: list[str]) -> None:
        """Append already-formatted ``principal:etype:key`` lines to kerberos_keys.txt."""
        if not lines:
            return
        self._ensure_kerberos_file()
        if self._kerberos_file is None:
            msg = "Kerberos keys file not opened: _ensure_kerberos_file() failed"
            raise RuntimeError(msg)
        self._kerberos_file.write("\n".join(lines) + "\n")

    def _write_nt_hash(self, credentials: dict[str, object], username: str, domain: str) -> None:
        """Write the current NT hash and user mapping entry."""
        nt_hash = credentials.get("ntHash")
        if not isinstance(nt_hash, str) or len(nt_hash) != MD4_HEX_LENGTH:
            return

        self._ensure_nt_files()
        if self._nt_file is None or self._nt_users_file is None:
            msg = "NT hash files not opened: _ensure_nt_files() failed"
            raise RuntimeError(msg)

        # One bare hash per line for hashcat mode 1000.
        self._nt_file.write(nt_hash)
        self._nt_file.write("\n")

        # Mapping file: hash:DOMAIN\username for result correlation.
        domain_user = f"{domain}\\{username}" if domain else username
        self._nt_users_file.write(f"{nt_hash}:{domain_user}\n")

    def _write_lm_hash(self, credentials: dict[str, object]) -> None:
        """Write the current LM hash as two halves for mode 3000."""
        lm_hash = credentials.get("lmHash")
        if not isinstance(lm_hash, str) or len(lm_hash) != MD4_HEX_LENGTH:
            return

        self._ensure_lm_file()
        if self._lm_file is None:
            msg = "LM hash file not opened: _ensure_lm_file() failed"
            raise RuntimeError(msg)

        # Split LM hash into two independent 8-byte halves for mode 3000.
        # Each half is a separate DES encryption that hashcat cracks independently.
        lm_first_half = lm_hash[:_LM_HALF_LEN]
        lm_second_half = lm_hash[_LM_HALF_LEN:]
        self._lm_file.write(lm_first_half)
        self._lm_file.write("\n")
        self._lm_file.write(lm_second_half)
        self._lm_file.write("\n")

    def _write_nt_history(self, credentials: dict[str, object]) -> None:
        """Write NT hash history entries."""
        nt_history = credentials.get("ntHistory")
        if not isinstance(nt_history, list):
            return

        for hist_hash in nt_history:
            if isinstance(hist_hash, str) and len(hist_hash) == MD4_HEX_LENGTH:
                self._ensure_nt_history_file()
                if self._nt_history_file is None:
                    msg = "NT history file not opened: _ensure_nt_history_file() failed"
                    raise RuntimeError(msg)
                self._nt_history_file.write(hist_hash)
                self._nt_history_file.write("\n")

    def _write_lm_history(self, credentials: dict[str, object]) -> None:
        """Write LM hash history entries as halves."""
        lm_history = credentials.get("lmHistory")
        if not isinstance(lm_history, list):
            return

        for hist_hash in lm_history:
            if isinstance(hist_hash, str) and len(hist_hash) == MD4_HEX_LENGTH:
                self._ensure_lm_history_file()
                if self._lm_history_file is None:
                    msg = "LM history file not opened: _ensure_lm_history_file() failed"
                    raise RuntimeError(msg)
                # Split each historical LM hash into halves, same as current.
                lm_first_half = hist_hash[:_LM_HALF_LEN]
                lm_second_half = hist_hash[_LM_HALF_LEN:]
                self._lm_history_file.write(lm_first_half)
                self._lm_history_file.write("\n")
                self._lm_history_file.write(lm_second_half)
                self._lm_history_file.write("\n")

    def close(self) -> None:
        """Close all open hash output files.

        Safe to call multiple times -- subsequent calls are no-ops.
        """
        for name, fh in [
            ("hashes_nt.hashcat", self._nt_file),
            ("hashes_lm.hashcat", self._lm_file),
            ("hashes_nt.hashcat.users", self._nt_users_file),
            ("hashes_nt_history.hashcat", self._nt_history_file),
            ("hashes_lm_history.hashcat", self._lm_history_file),
            ("kerberos_keys.txt", self._kerberos_file),
        ]:
            if fh is not None:
                fh.close()
                logger.debug("Closed hashcat output: %s", name)

        # Reset all handles so close() is idempotent.
        self._nt_file = None
        self._lm_file = None
        self._nt_users_file = None
        self._nt_history_file = None
        self._lm_history_file = None
        self._kerberos_file = None

    # --- Lazy file creation helpers ---

    def _open_file(self, filename: str) -> io.TextIOWrapper:
        """Open a hash output file with buffered writing.

        Args:
            filename: Name of the file to create in the output directory.

        Returns:
            An open text file handle ready for writing.

        """
        if self._output_dir is None:
            msg = "Writer not opened: call open() before write()"
            raise RuntimeError(msg)
        path = self._output_dir / filename
        return path.open(mode="w", encoding="utf-8", buffering=_WRITE_BUFFER_SIZE)

    def _ensure_nt_files(self) -> None:
        """Open the NT hash file and user mapping file if not already open."""
        if self._nt_file is None:
            self._nt_file = self._open_file("hashes_nt.hashcat")
            self._nt_users_file = self._open_file("hashes_nt.hashcat.users")

    def _ensure_lm_file(self) -> None:
        """Open the LM hash file if not already open."""
        if self._lm_file is None:
            self._lm_file = self._open_file("hashes_lm.hashcat")

    def _ensure_nt_history_file(self) -> None:
        """Open the NT history hash file if not already open."""
        if self._nt_history_file is None:
            self._nt_history_file = self._open_file("hashes_nt_history.hashcat")

    def _ensure_lm_history_file(self) -> None:
        """Open the LM history hash file if not already open."""
        if self._lm_history_file is None:
            self._lm_history_file = self._open_file("hashes_lm_history.hashcat")

    def _ensure_kerberos_file(self) -> None:
        """Open the Kerberos keys file if not already open."""
        if self._kerberos_file is None:
            self._kerberos_file = self._open_file("kerberos_keys.txt")
