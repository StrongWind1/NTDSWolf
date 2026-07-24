# SPDX-License-Identifier: Apache-2.0
"""Output base module -- OutputWriter protocol, OutputManager dispatcher, and format registry."""

from __future__ import annotations

import importlib
import logging
import re
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# --- Format constants ---

# Formats that produce per-class output files (users.ndjson, groups.ndjson, etc.)
_STRUCTURED_FORMATS: frozenset[str] = frozenset({"ndjson", "json", "csv"})

# Formats that produce hash-specific output files (the hashcat and
# secretsdump-style pwdump writers). These writers receive ALL objects but
# silently skip those without credentials.
_HASH_FORMATS: frozenset[str] = frozenset({"hashcat", "pwdump"})

# Every format we support -- used for CLI validation
SUPPORTED_FORMATS: frozenset[str] = _STRUCTURED_FORMATS | _HASH_FORMATS

# The key in each object dict that identifies which AD class the object belongs to.
# Decoders set this to values like "user", "computer", "group", "trustedDomain", etc.
_CLASS_KEY: str = "_object_class"

# Friendly per-class output filenames for the common AD classes. Any other class
# is sanitized from its objectClass to a filesystem-safe name (so e.g.
# "dHCPClass" becomes "dhcpclass.ndjson" rather than the crude "dHCPClasss").
_CLASS_FILENAMES: dict[str, str] = {
    "user": "users",
    "computer": "computers",
    "group": "groups",
    "trustedDomain": "trusts",
    "domainDNS": "domains",
    "groupPolicyContainer": "gpos",
    "organizationalUnit": "ous",
    "msDS-GroupManagedServiceAccount": "gmsa",
    "msKds-ProvRootKey": "kds_root_keys",
    "msFVE-RecoveryInformation": "bitlocker",
    "secret": "secrets",
    "container": "containers",
    "foreignSecurityPrincipal": "foreign_security_principals",
    "dpapiBackupKey": "dpapi_backup_keys",
}

# Characters not allowed in the sanitized portion of an output filename.
_UNSAFE_FILENAME_CHARS: re.Pattern[str] = re.compile(r"[^a-z0-9._-]+")


def output_filename(object_class: str, extension: str) -> str:
    """Return a filesystem-safe per-class output filename.

    Common classes map to friendly names (user -> users.ndjson); anything else is
    derived from a lowercased, sanitized objectClass to avoid invalid filenames
    and the awkward double-``s`` of naive pluralization.
    """
    base = _CLASS_FILENAMES.get(object_class)
    if base is None:
        base = _UNSAFE_FILENAME_CHARS.sub("_", object_class.lower()).strip("_") or "objects"
    return f"{base}.{extension}"


@runtime_checkable
class OutputWriter(Protocol):
    """Protocol that all output format writers must satisfy.

    Writers have a simple lifecycle: open -> write (repeated) -> close.
    The OutputManager handles dispatching objects to the correct writer
    instance based on object class.
    """

    def open(self, output_dir: Path, object_class: str, /) -> None:
        """Prepare the writer for output.

        Creates or opens the target file(s) in ``output_dir``. The
        ``object_class`` determines the filename for structured formats
        (e.g. ``users.ndjson``). Hash-format writers ignore ``object_class``
        and use fixed filenames -- hence it is positional-only, so those
        writers may bind it to an unused ``_object_class`` parameter.

        Args:
            output_dir: Directory where output files are written.
            object_class: AD object class name (e.g. "user", "group").

        """
        ...

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Write a single extracted object to the output file.

        Args:
            obj_dict: Serialized AD object as produced by a decoder.
                      Must contain ``_object_class`` at minimum.

        """
        ...

    def close(self) -> None:
        """Flush any buffered data and close the output file."""
        ...


# Writer class registry -- maps format name to (module_path, class_name).
# Imports happen lazily on first use, cached in _WRITER_CACHE.
_WRITER_REGISTRY: dict[str, tuple[str, str]] = {
    "ndjson": ("ntdswolf.output.ndjson", "NDJSONWriter"),
    "json": ("ntdswolf.output.json_", "JSONWriter"),
    "csv": ("ntdswolf.output.csv_", "CSVWriter"),
    "hashcat": ("ntdswolf.output.hashcat", "HashcatWriter"),
    "pwdump": ("ntdswolf.output.pwdump", "PwdumpWriter"),
}
_WRITER_CACHE: dict[str, type[OutputWriter]] = {}


def _get_writer_class(fmt: str) -> type[OutputWriter]:
    """Return the writer class for the given format, importing lazily on first use.

    Uses ``importlib.import_module`` so writer modules are loaded on demand
    and cached for subsequent calls.

    Args:
        fmt: One of the values in SUPPORTED_FORMATS.

    Returns:
        The writer class (not an instance).

    Raises:
        KeyError: If ``fmt`` is not in the registry.

    """
    if fmt not in _WRITER_CACHE:
        module_path, class_name = _WRITER_REGISTRY[fmt]
        module = importlib.import_module(module_path)
        _WRITER_CACHE[fmt] = getattr(module, class_name)
    return _WRITER_CACHE[fmt]


def _create_writer(fmt: str, hashcat_username: str = "sam") -> OutputWriter:
    """Instantiate the appropriate writer for the given format string.

    Uses the lazily-populated writer registry so that writer modules are only
    imported when their format is actually requested. ``hashcat_username``
    selects the hashcat writer's username field and is ignored by other formats.

    Args:
        fmt: One of the values in SUPPORTED_FORMATS.
        hashcat_username: Username source for the hashcat writer (sam/upn/rid/sid).

    Returns:
        A fresh, unopened writer instance.

    Raises:
        ValueError: If ``fmt`` is not a recognized format.

    """
    if fmt == "hashcat":
        from ntdswolf.output.hashcat import HashcatWriter  # noqa: PLC0415 -- writer modules are imported lazily (matching the registry)

        return HashcatWriter(username_field=hashcat_username)
    try:
        cls = _get_writer_class(fmt)
    except KeyError:
        msg = f"Unsupported output format: {fmt!r}. Choose from: {', '.join(sorted(SUPPORTED_FORMATS))}"
        raise ValueError(msg) from None
    return cls()


class OutputManager:
    """Dispatches extracted objects to per-class output writers.

    Manages the lifecycle of output files -- opening them lazily on first
    write, buffering output, and closing all files on finalize.

    For structured formats (ndjson, json, csv), each AD object class gets its
    own writer and output file (e.g. ``users.ndjson``, ``computers.ndjson``).

    For hash formats (hashcat, pwdump), a single writer handles all objects and
    writes to fixed-name files. Objects without credentials are silently skipped
    by the writer itself.
    """

    def __init__(self, fmt: str, output_dir: Path, extract_classes: set[str] | None = None, hashcat_username: str = "sam") -> None:
        """Initialize the output manager.

        Args:
            fmt: Output format name (must be in SUPPORTED_FORMATS).
            output_dir: Directory where output files will be created.
                        Created automatically if it does not exist.
            extract_classes: If provided, only objects whose ``_object_class``
                             is in this set will be written. ``None`` means
                             write everything.
            hashcat_username: Username source for the hashcat writer (sam/upn/rid/sid).

        Raises:
            ValueError: If ``fmt`` is not recognized.

        """
        if fmt not in SUPPORTED_FORMATS:
            msg = f"Unsupported output format: {fmt!r}. Choose from: {', '.join(sorted(SUPPORTED_FORMATS))}"
            raise ValueError(msg)

        self._fmt: str = fmt
        self._output_dir: Path = output_dir
        self._extract_classes: set[str] | None = extract_classes
        self._hashcat_username: str = hashcat_username

        # Per-class writers for structured formats.  Keyed by object class
        # name (e.g. "user", "group").  Lazily populated on first write.
        self._writers: dict[str, OutputWriter] = {}

        # For hash formats we use a single shared writer for all classes.
        # It stays None until the first credentialed object arrives.
        self._hash_writer: OutputWriter | None = None

        # Track how many objects we wrote per class for the final summary.
        self._counts: dict[str, int] = {}

        # Whether this is a hash format (single writer) vs structured (per-class).
        self._is_hash_format: bool = fmt in _HASH_FORMATS

    # --- Public API ---

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Write a single object dict to the appropriate output file.

        Objects are routed to per-class writers for structured formats, or
        to a single shared writer for hash formats. If ``extract_classes``
        was specified at init time, objects outside that set are silently
        dropped.

        Args:
            obj_dict: Serialized AD object. Must contain ``_object_class``.

        """
        object_class = obj_dict.get(_CLASS_KEY)
        if object_class is None:
            logger.warning("Object dict missing '%s' key, skipping: %s", _CLASS_KEY, obj_dict.get("distinguishedName", "<unknown>"))
            return

        # If the caller restricted which classes to extract, enforce it here.
        if self._extract_classes is not None and object_class not in self._extract_classes:
            return

        if self._is_hash_format:
            self._write_hash(obj_dict, object_class)
        else:
            self._write_structured(obj_dict, object_class)

    def write_batch(self, dicts: list[dict[str, Any]]) -> None:
        """Write a batch of object dicts.

        Convenience wrapper around :meth:`write` for the worker pool, which
        returns results in batches.

        Args:
            dicts: List of serialized AD objects.

        """
        for obj_dict in dicts:
            self.write(obj_dict)

    def finalize(self) -> dict[str, int]:
        """Close all open writers and return extraction counts.

        Returns:
            Mapping of object class name to number of objects written for
            that class.  Example: ``{"user": 1234, "computer": 567}``.

        """
        # Close all per-class structured writers.
        for object_class, writer in self._writers.items():
            try:
                writer.close()
            except Exception:
                logger.exception("Error closing writer for class %r", object_class)

        # Close the single hash writer if it was opened.
        if self._hash_writer is not None:
            try:
                self._hash_writer.close()
            except Exception:
                logger.exception("Error closing hash writer")

        return dict(self._counts)  # return a copy so callers can't mutate our state

    # --- Private helpers ---

    def _ensure_output_dir(self) -> None:
        """Create the output directory tree if it does not already exist."""
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def _write_structured(self, obj_dict: dict[str, Any], object_class: str) -> None:
        """Route an object to its per-class writer, creating it lazily.

        Args:
            obj_dict: Serialized AD object.
            object_class: The value of ``_object_class`` from the dict.

        """
        writer = self._writers.get(object_class)
        if writer is None:
            # First object of this class -- spin up a new writer.
            self._ensure_output_dir()
            writer = _create_writer(self._fmt)
            writer.open(self._output_dir, object_class)
            self._writers[object_class] = writer

        writer.write(obj_dict)
        self._counts[object_class] = self._counts.get(object_class, 0) + 1

    def _write_hash(self, obj_dict: dict[str, Any], object_class: str) -> None:
        """Route an object to the single hash writer, creating it lazily.

        Hash writers handle the filtering internally -- they silently skip
        objects that lack credential data. We still count objects here based
        on what the writer reports (no write exception = object was accepted).

        Args:
            obj_dict: Serialized AD object.
            object_class: The value of ``_object_class`` from the dict.

        """
        if self._hash_writer is None:
            # First object arriving -- open the hash writer with a dummy class
            # name. Hash writers ignore the class and use fixed filenames.
            self._ensure_output_dir()
            self._hash_writer = _create_writer(self._fmt, self._hashcat_username)
            self._hash_writer.open(self._output_dir, object_class)

        self._hash_writer.write(obj_dict)
        # Count every object dispatched, regardless of whether the hash writer
        # actually wrote anything (it skips non-credentialed objects silently).
        self._counts[object_class] = self._counts.get(object_class, 0) + 1
