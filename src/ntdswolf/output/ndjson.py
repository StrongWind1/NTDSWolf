# SPDX-License-Identifier: Apache-2.0
"""Newline-delimited JSON (NDJSON) output writer -- one JSON object per line."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from ntdswolf.output.base import output_filename

if TYPE_CHECKING:
    import io
    from pathlib import Path

logger = logging.getLogger(__name__)

# Buffer size for the underlying file stream. 64KB gives a good balance
# between syscall frequency and memory usage for line-oriented output.
_WRITE_BUFFER_SIZE: int = 65_536  # 64KB


class NDJSONWriter:
    r"""Newline-delimited JSON output writer.

    Produces one JSON object per line, following the NDJSON / JSON Lines
    specification (https://jsonlines.org/). Each line is a complete,
    self-contained JSON object terminated by ``\\n``.

    Files are named by object class: ``users.ndjson``, ``computers.ndjson``,
    ``groups.ndjson``, etc. Names come from :func:`output_filename`, which maps
    common classes to friendly plurals and sanitizes anything else.

    This format is ideal for streaming ingestion into tools like ``jq``,
    Elasticsearch, or Splunk. It avoids the framing overhead of JSON arrays
    and allows line-by-line processing without loading the whole file.
    """

    def __init__(self) -> None:
        """Initialize the writer in a closed state."""
        self._file: io.TextIOWrapper | None = None
        self._path: Path | None = None

    def open(self, output_dir: Path, object_class: str) -> None:
        """Create the NDJSON output file for a specific object class.

        The file is opened in text mode with UTF-8 encoding and a 64KB
        write buffer. If the file already exists it is overwritten.

        Args:
            output_dir: Directory where the file will be created.
            object_class: AD object class name (e.g. "user"). Used to
                          derive the filename (``users.ndjson``).

        """
        # Derive a filesystem-safe per-class filename (user->users.ndjson,
        # dHCPClass->dhcpclass.ndjson). See output_filename for the mapping.
        filename = output_filename(object_class, "ndjson")
        self._path = output_dir / filename

        # Open with explicit buffering -- we want to control flush frequency.
        self._file = self._path.open(
            mode="w",
            encoding="utf-8",
            buffering=_WRITE_BUFFER_SIZE,
        )
        logger.debug("Opened NDJSON output: %s", self._path)

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Serialize one object as a single JSON line.

        Uses ``default=str`` so that any non-serializable values (dates,
        bytes, enums, etc.) are converted to their string representation
        rather than raising.

        Args:
            obj_dict: Serialized AD object dict from a decoder.

        Raises:
            RuntimeError: If the writer has not been opened yet.

        """
        if self._file is None:
            msg = "NDJSONWriter.write() called before open()"
            raise RuntimeError(msg)

        # json.dumps with ensure_ascii=False preserves Unicode characters
        # (e.g. international display names) without escaping them to \\uXXXX.
        # default=str is the catch-all serializer for datetime, bytes, etc.
        line = json.dumps(obj_dict, ensure_ascii=False, default=str)
        self._file.write(line)
        self._file.write("\n")

    def close(self) -> None:
        """Flush the buffer and close the output file.

        Safe to call multiple times -- subsequent calls are no-ops.
        """
        if self._file is not None:
            self._file.close()
            self._file = None
            logger.debug("Closed NDJSON output: %s", self._path)
