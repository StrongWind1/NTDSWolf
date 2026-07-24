# SPDX-License-Identifier: Apache-2.0
"""CSV output writer -- flat CSV with automatic header discovery and nested-dict flattening."""

from __future__ import annotations

import csv
import json
import logging
from typing import TYPE_CHECKING, Any

from ntdswolf.constants import FLAG_DICT_KEY_COUNT
from ntdswolf.output.base import output_filename

if TYPE_CHECKING:
    import io
    from pathlib import Path

logger = logging.getLogger(__name__)

# Separator used when joining multi-valued fields (list items) into a
# single CSV cell. Pipe is chosen because it is uncommon in AD attribute
# values and does not conflict with CSV quoting.
_LIST_SEPARATOR: str = "|"

# Suffix appended to flag field column names to create the companion
# human-readable flags column. E.g. "userAccountControl" gets a sibling
# column "userAccountControl_flags" containing the decoded flag names.
_FLAGS_SUFFIX: str = "_flags"


class CSVWriter:
    """Flat CSV output writer with automatic header discovery.

    Produces a standard RFC 4180 CSV file with one row per AD object.
    Column headers are discovered from the first object of each class and
    then held fixed for all subsequent objects of that class.

    Nested dicts are flattened using dot notation (e.g.
    ``credentials.ntHash``). Lists are joined with pipe ``|`` separators.
    Flag dicts (``{"value": 66048, "flags": ["A", "B"]}``) produce two
    columns: the raw value column and a companion ``_flags`` column with
    the pipe-joined flag names.

    Files are named by object class: ``users.csv``, ``computers.csv``, etc.
    """

    def __init__(self) -> None:
        """Initialize the writer in a closed state."""
        self._file: io.TextIOWrapper | None = None
        self._path: Path | None = None
        self._csv_writer: csv.DictWriter[str] | None = None
        # Column names in insertion order, discovered from the first object.
        self._fieldnames: list[str] | None = None

    def open(self, output_dir: Path, object_class: str) -> None:
        """Create the CSV output file.

        Headers are not written until the first object arrives, because we
        need to inspect the object's keys to build the column list.

        Args:
            output_dir: Directory where the file will be created.
            object_class: AD object class name. Used to derive the filename.

        """
        filename = output_filename(object_class, "csv")
        self._path = output_dir / filename

        self._file = self._path.open(
            mode="w",
            encoding="utf-8",
            newline="",  # csv module requires this per the docs
        )
        self._fieldnames = None
        self._csv_writer = None

        logger.debug("Opened CSV output: %s", self._path)

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Flatten and write one object as a CSV row.

        On the first call, the object's structure is analyzed to build the
        column header list. The header row is written immediately, then
        this object becomes the first data row.

        Args:
            obj_dict: Serialized AD object dict from a decoder.

        Raises:
            RuntimeError: If the writer has not been opened yet.

        """
        if self._file is None:
            msg = "CSVWriter.write() called before open()"
            raise RuntimeError(msg)

        # Flatten the nested dict into a single-level dict suitable for CSV.
        flat = _flatten_dict(obj_dict)

        if self._csv_writer is None:
            # First object -- discover headers from its keys and write them.
            self._fieldnames = list(flat.keys())
            self._csv_writer = csv.DictWriter(
                self._file,
                fieldnames=self._fieldnames,
                quoting=csv.QUOTE_MINIMAL,
                extrasaction="ignore",  # silently drop keys not in fieldnames
            )
            self._csv_writer.writeheader()

        self._csv_writer.writerow(flat)

    def close(self) -> None:
        """Flush and close the CSV output file.

        Safe to call multiple times -- subsequent calls are no-ops.
        """
        if self._file is not None:
            self._file.close()
            self._file = None
            self._csv_writer = None
            self._fieldnames = None
            logger.debug("Closed CSV output: %s", self._path)


# --- Flattening helpers ---


def _flatten_dict(d: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, str]:
    """Recursively flatten a nested dict into a single-level dict with string values.

    Handles three kinds of nested structures:

    1. **Flag dicts** -- ``{"value": 66048, "flags": ["A", "B"]}`` -- produce
       two entries: ``key`` with the raw value and ``key_flags`` with the
       pipe-joined flag names.

    2. **Regular dicts** -- recursively flattened with dot-separated keys.
       ``{"credentials": {"ntHash": "abc"}}`` becomes ``credentials.ntHash``.

    3. **Lists** -- joined with pipe separators.
       ``["CN=A,DC=x", "CN=B,DC=x"]`` becomes ``"CN=A,DC=x|CN=B,DC=x"``.

    All other values are converted to strings via ``str()``.

    Args:
        d: The dict to flatten.
        parent_key: Prefix for nested keys (used in recursion).
        sep: Separator between parent and child key names.

    Returns:
        A flat dict where every value is a string.

    """
    items: dict[str, str] = {}

    for key, value in d.items():
        # Build the full dotted key path for nested structures.
        full_key = f"{parent_key}{sep}{key}" if parent_key else key

        if isinstance(value, dict):
            if _is_flag_dict(value):
                # Flag dict: emit both the raw numeric value and the decoded
                # flag names as a companion column.
                items[full_key] = str(value.get("value", ""))
                flags = value.get("flags", [])
                flags_str = _LIST_SEPARATOR.join(str(f) for f in flags) if isinstance(flags, list) else str(flags)
                items[full_key + _FLAGS_SUFFIX] = flags_str
            else:
                # Regular nested dict: recurse with dot-separated keys.
                nested = _flatten_dict(value, parent_key=full_key, sep=sep)
                items.update(nested)

        elif isinstance(value, list):
            # Multi-valued attribute: join all elements with pipe.
            # Each element might itself be a dict (e.g. kerberos keys),
            # so we stringify each one.
            items[full_key] = _LIST_SEPARATOR.join(_stringify_list_element(elem) for elem in value)

        else:
            # Scalar value: convert to string. None becomes empty string
            # for cleaner CSV output.
            items[full_key] = "" if value is None else str(value)

    return items


def _is_flag_dict(d: dict[str, Any]) -> bool:
    """Check whether a dict represents a flag field.

    Flag dicts follow the schema convention from the architecture doc:
    ``{"value": <int>, "flags": [<str>, ...]}``. We detect this pattern
    to emit both the raw value and decoded flags as separate CSV columns.

    Args:
        d: The dict to test.

    Returns:
        True if the dict looks like a flag field.

    """
    # Must have exactly "value" and "flags" keys (and optionally nothing else)
    # to be recognized as a flag dict. This avoids false positives on dicts
    # that happen to contain a "value" key for other reasons.
    return "value" in d and "flags" in d and len(d) == FLAG_DICT_KEY_COUNT


def _stringify_list_element(elem: object) -> str:
    """Convert a list element to a string suitable for CSV cell content.

    Dicts within lists (e.g. individual Kerberos key objects) are serialized
    as compact JSON strings so they remain parseable from the CSV cell.

    Args:
        elem: Any value found inside a list attribute.

    Returns:
        String representation of the element.

    """
    if isinstance(elem, dict):
        # Nested dicts in lists (like kerberos key entries) get compact JSON
        # representation. This preserves structure while fitting in a cell.
        return json.dumps(elem, ensure_ascii=False, default=str, separators=(",", ":"))

    if elem is None:
        return ""

    return str(elem)
