"""John the Ripper format hash output writer -- username:$NT$hexhash lines."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ntdswolf.constants import MD4_HEX_LENGTH

if TYPE_CHECKING:
    import io
    from pathlib import Path

logger = logging.getLogger(__name__)

# John the Ripper NT hash format prefix. Each line is:
#   username:$NT$hexhash
# This corresponds to John's "nt" format (--format=nt).
_NT_PREFIX: str = "$NT$"

# Write buffer size for output files (64KB).
_WRITE_BUFFER_SIZE: int = 65_536


class JohnWriter:
    """John the Ripper format hash output writer.

    Produces hash files in John the Ripper's native NT hash format::

        jsmith:$NT$e52cac67419a9a224a3b108f3fa6cb6d
        WORKSTATION01$:$NT$a1b2c3d4e5f67890a1b2c3d4e5f67890

    Output files:

    - ``hashes.john`` -- current NT hashes for all credentialed objects.
    - ``hashes_history.john`` -- historical NT hashes (only created if any
      objects contain NT hash history entries).

    Objects without credentials are silently skipped. This writer receives
    all object types from the OutputManager but only processes those with
    a ``credentials`` dict containing NT hash data.

    Usage with John::

        john --format=nt hashes.john
    """

    def __init__(self) -> None:
        """Initialize the writer in a closed state."""
        self._file: io.TextIOWrapper | None = None
        self._history_file: io.TextIOWrapper | None = None
        self._output_dir: Path | None = None

    def open(self, output_dir: Path, _object_class: str) -> None:
        """Store the output directory for lazy file creation.

        Files are created on demand when the first relevant hash data
        arrives, avoiding empty output files.

        Args:
            output_dir: Directory where hash files will be written.
            _object_class: Ignored. John writer uses fixed filenames.

        """
        self._output_dir = output_dir
        logger.debug("John writer ready, output dir: %s", output_dir)

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Extract NT hashes from an object and write in John format.

        The John format for NT hashes is ``username:$NT$hexhash``, one
        entry per line. The username is taken from ``sAMAccountName``.

        Silently returns if the object has no credentials or no NT hash.

        Args:
            obj_dict: Serialized AD object dict from a decoder.

        """
        credentials = obj_dict.get("credentials")
        if not isinstance(credentials, dict):
            # No credentials on this object -- skip silently.
            return

        username = _extract_username(obj_dict)

        # --- Current NT hash ---
        nt_hash = credentials.get("ntHash")
        if isinstance(nt_hash, str) and len(nt_hash) == MD4_HEX_LENGTH:
            self._ensure_main_file()
            if self._file is None:
                msg = "Main hash file not opened: _ensure_main_file() failed"
                raise RuntimeError(msg)

            # Format: username:$NT$hexhash
            self._file.write(f"{username}:{_NT_PREFIX}{nt_hash}\n")

        # --- NT hash history ---
        nt_history = credentials.get("ntHistory")
        if isinstance(nt_history, list):
            for idx, hist_hash in enumerate(nt_history):
                if isinstance(hist_hash, str) and len(hist_hash) == MD4_HEX_LENGTH:
                    self._ensure_history_file()
                    if self._history_file is None:
                        msg = "History file not opened: _ensure_history_file() failed"
                        raise RuntimeError(msg)

                    # History entries use a suffixed username to differentiate
                    # them from the current hash and from each other.
                    hist_username = f"{username}__history{idx}"
                    self._history_file.write(f"{hist_username}:{_NT_PREFIX}{hist_hash}\n")

    def close(self) -> None:
        """Close all open output files.

        Safe to call multiple times -- subsequent calls are no-ops.
        """
        if self._file is not None:
            self._file.close()
            self._file = None
            logger.debug("Closed John output: hashes.john")

        if self._history_file is not None:
            self._history_file.close()
            self._history_file = None
            logger.debug("Closed John output: hashes_history.john")

    # --- Lazy file creation helpers ---

    def _ensure_main_file(self) -> None:
        """Open the main hash file if not already open."""
        if self._file is None:
            if self._output_dir is None:
                msg = "Writer not opened: call open() before write()"
                raise RuntimeError(msg)
            path = self._output_dir / "hashes.john"
            self._file = path.open(mode="w", encoding="utf-8", buffering=_WRITE_BUFFER_SIZE)

    def _ensure_history_file(self) -> None:
        """Open the history hash file if not already open."""
        if self._history_file is None:
            if self._output_dir is None:
                msg = "Writer not opened: call open() before write()"
                raise RuntimeError(msg)
            path = self._output_dir / "hashes_history.john"
            self._history_file = path.open(mode="w", encoding="utf-8", buffering=_WRITE_BUFFER_SIZE)


def _extract_username(obj_dict: dict[str, Any]) -> str:
    """Extract the best available username from an object dict.

    Prefers ``sAMAccountName``, falls back to ``name``, and finally
    to ``"unknown"``.

    Args:
        obj_dict: Serialized AD object dict.

    Returns:
        The username string.

    """
    sam = obj_dict.get("sAMAccountName")
    if isinstance(sam, str) and sam:
        return sam

    name = obj_dict.get("name")
    if isinstance(name, str) and name:
        return name

    return "unknown"
