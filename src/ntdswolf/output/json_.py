# SPDX-License-Identifier: Apache-2.0
"""Pretty-printed JSON array output writer -- single file per object class."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from ntdswolf.output.base import output_filename

if TYPE_CHECKING:
    import io
    from pathlib import Path

logger = logging.getLogger(__name__)


class JSONWriter:
    """Pretty-printed JSON array output writer.

    Produces a single JSON file containing an array of objects, formatted
    with 2-space indentation for human readability.

    The output structure is::

        [
          { ... first object ... },
          { ... second object ... },
          { ... last object ... }
        ]

    Files are named by object class: ``users.json``, ``computers.json``, etc.

    Because JSON arrays require commas between elements but not after the
    last one, this writer tracks whether it has written the first object
    and handles comma insertion accordingly. The opening ``[`` is written
    at open time and the closing ``]`` at close time.
    """

    def __init__(self) -> None:
        """Initialize the writer in a closed state."""
        self._file: io.TextIOWrapper | None = None
        self._path: Path | None = None
        # Tracks whether we have written at least one object. Needed to
        # correctly insert commas between array elements.
        self._first_written: bool = False

    def open(self, output_dir: Path, object_class: str) -> None:
        """Create the JSON output file and write the opening bracket.

        Args:
            output_dir: Directory where the file will be created.
            object_class: AD object class name (e.g. "user"). Used to
                          derive the filename (``users.json``).

        """
        filename = output_filename(object_class, "json")
        self._path = output_dir / filename
        self._first_written = False

        self._file = self._path.open(
            mode="w",
            encoding="utf-8",
        )

        # Write the opening bracket of the JSON array.
        self._file.write("[\n")

        logger.debug("Opened JSON output: %s", self._path)

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Serialize one object as an indented JSON element in the array.

        Handles comma placement between array elements: the first object
        gets no leading comma, every subsequent object is preceded by a
        comma and newline separator.

        Args:
            obj_dict: Serialized AD object dict from a decoder.

        Raises:
            RuntimeError: If the writer has not been opened yet.

        """
        if self._file is None:
            msg = "JSONWriter.write() called before open()"
            raise RuntimeError(msg)

        # Serialize the object with 2-space indent. default=str catches
        # datetime, bytes, and other non-JSON-native types.
        serialized = json.dumps(obj_dict, indent=2, ensure_ascii=False, default=str)

        if self._first_written:
            # Separate from the previous object with a comma.
            self._file.write(",\n")
        else:
            self._first_written = True

        # Indent each line of the serialized object by 2 spaces so it sits
        # inside the top-level array bracket. json.dumps already indents
        # internal structure; we add one more level for the array nesting.
        indented = _indent_block(serialized, prefix="  ")
        self._file.write(indented)

    def close(self) -> None:
        """Write the closing bracket and close the output file.

        Produces valid JSON even if zero objects were written (result: ``[]``).
        Safe to call multiple times -- subsequent calls are no-ops.
        """
        if self._file is not None:
            if self._first_written:
                # End the last object's line before the closing bracket.
                self._file.write("\n")
            self._file.write("]\n")
            self._file.close()
            self._file = None
            logger.debug("Closed JSON output: %s", self._path)


def _indent_block(text: str, prefix: str) -> str:
    """Prepend ``prefix`` to every line in ``text``.

    Used to nest the 2-space-indented json.dumps output one level deeper
    inside the top-level JSON array.

    Args:
        text: Multi-line string to indent.
        prefix: String to prepend to each line.

    Returns:
        The indented text with the prefix on every line.

    """
    lines = text.split("\n")
    return "\n".join(prefix + line for line in lines)
