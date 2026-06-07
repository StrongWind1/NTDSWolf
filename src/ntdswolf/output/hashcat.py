r"""Hashcat-compatible hash output writer.

For every object class that carries NT/LM hashes, this writes ``username:hash``
lines split by hash type, age, and class -- ready for ``hashcat --username``::

    ntlm_<type>_current.txt   username:nt_hash       (hashcat -m 1000)
    ntlm_<type>_history.txt   username:nt_hash        historical NT
    lm_<type>_current.txt     username:lm_half        (hashcat -m 3000)
    lm_<type>_history.txt     username:lm_half          historical LM

``<type>`` is the object class (``user``, ``computer``, ``gmsa``, ...). The LM
hash is emitted as its two independent 8-byte (16-hex) halves, one per line,
because mode 3000 cracks each half separately. ``username`` is the
sAMAccountName by default and can be switched to the UPN, the RID, or the full
objectSid via ``--hashcat-username``.

Files are ASCII with ``\n`` line endings. Kerberos keys are intentionally not
emitted: they are pass-the-key material, not hashcat-crackable hashes.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, cast

from ntdswolf.constants import MD4_HEX_LENGTH
from ntdswolf.output.credfiles import account_username

if TYPE_CHECKING:
    import io
    from pathlib import Path

logger = logging.getLogger(__name__)

# Valid sources for the ``username`` field of each ``username:hash`` line.
USERNAME_FIELDS: frozenset[str] = frozenset({"sam", "upn", "rid", "sid"})

# hashcat mode 3000 cracks each 8-byte (16-hex) LM half separately, so a stored
# 16-byte LM hash is emitted as two lines.
_LM_HALF_LEN: int = 16

# Short, filesystem-friendly names for the ``<type>`` filename segment.
_TYPE_NAMES: dict[str, str] = {
    "user": "user",
    "computer": "computer",
    "msDS-GroupManagedServiceAccount": "gmsa",
    "msDS-ManagedServiceAccount": "smsa",
    "msDS-DelegatedManagedServiceAccount": "dmsa",
}
_UNSAFE_FILENAME_CHARS: re.Pattern[str] = re.compile(r"[^a-z0-9._-]+")

# Hash files are written as ASCII; the rare non-ASCII username byte is replaced
# rather than crashing extraction.
_ENCODING: str = "ascii"


class HashcatWriter:
    r"""Writes ``username:hash`` files grouped by class / hash type / age."""

    def __init__(self, username_field: str = "sam") -> None:
        """Initialize the writer; ``username_field`` selects the line's username source."""
        self._username_field: str = username_field if username_field in USERNAME_FIELDS else "sam"
        self._output_dir: Path | None = None
        # Open file handles keyed by filename (lazily created on first matching write).
        self._files: dict[str, io.TextIOWrapper] = {}

    def open(self, output_dir: Path, _object_class: str) -> None:
        """Store the output directory; files are created lazily per (type, hash, age)."""
        self._output_dir = output_dir
        logger.debug("Hashcat writer ready (username=%s), output dir: %s", self._username_field, output_dir)

    def write(self, obj_dict: dict[str, Any]) -> None:
        """Emit this object's NT/LM hashes (current + history) as ``username:hash`` lines."""
        credentials = obj_dict.get("credentials")
        if not isinstance(credentials, dict):
            return

        username = self._resolve_username(obj_dict)
        type_name = self._type_name(obj_dict.get("_object_class"))

        self._write_nt(credentials.get("ntHash"), username, f"ntlm_{type_name}_current.txt")
        for hist in _hash_list(credentials.get("ntHistory")):
            self._write_nt(hist, username, f"ntlm_{type_name}_history.txt")

        self._write_lm(credentials.get("lmHash"), username, f"lm_{type_name}_current.txt")
        for hist in _hash_list(credentials.get("lmHistory")):
            self._write_lm(hist, username, f"lm_{type_name}_history.txt")

    def _write_nt(self, value: object, username: str, filename: str) -> None:
        """Write one ``username:nt_hash`` line (mode 1000) if the hash is valid."""
        if isinstance(value, str) and len(value) == MD4_HEX_LENGTH:
            self._line(filename, f"{username}:{value}")

    def _write_lm(self, value: object, username: str, filename: str) -> None:
        """Write the two ``username:lm_half`` lines (mode 3000) if the hash is valid."""
        if isinstance(value, str) and len(value) == MD4_HEX_LENGTH:
            self._line(filename, f"{username}:{value[:_LM_HALF_LEN]}")
            self._line(filename, f"{username}:{value[_LM_HALF_LEN:]}")

    def _line(self, filename: str, text: str) -> None:
        """Append a line to ``filename``, opening it on first use."""
        fh = self._files.get(filename)
        if fh is None:
            if self._output_dir is None:
                msg = "Writer not opened: call open() before write()"
                raise RuntimeError(msg)
            fh = (self._output_dir / filename).open(mode="w", encoding=_ENCODING, errors="replace", newline="\n")
            self._files[filename] = fh
        fh.write(text + "\n")

    def _resolve_username(self, obj_dict: dict[str, Any]) -> str:
        """Return the line's username per ``--hashcat-username`` (falling back to sAMAccountName)."""
        if self._username_field == "upn":
            upn = obj_dict.get("userPrincipalName")
            return upn if isinstance(upn, str) and upn else account_username(obj_dict)
        if self._username_field in {"rid", "sid"}:
            sid = obj_dict.get("objectSid")
            if isinstance(sid, str) and sid:
                return sid.rsplit("-", 1)[-1] if self._username_field == "rid" else sid
            return account_username(obj_dict)
        return account_username(obj_dict)

    @staticmethod
    def _type_name(object_class: object) -> str:
        """Map an objectClass to its short filename segment (``user``, ``gmsa``, ...)."""
        if not isinstance(object_class, str) or not object_class:
            return "object"
        return _TYPE_NAMES.get(object_class) or _UNSAFE_FILENAME_CHARS.sub("_", object_class.lower()).strip("_") or "object"

    def close(self) -> None:
        """Close every open hash file (idempotent)."""
        for filename, fh in self._files.items():
            fh.close()
            logger.debug("Closed hashcat output: %s", filename)
        self._files = {}


def _hash_list(value: object) -> list[object]:
    """Return ``value`` if it is a list of history hashes, else an empty list."""
    return cast("list[object]", value) if isinstance(value, list) else []
