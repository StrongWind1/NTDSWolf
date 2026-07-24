# SPDX-License-Identifier: Apache-2.0
"""NTDSDatabase -- thin wrapper around dissect.database NTDS for consistent access.

This module exists to isolate all direct interactions with the dissect.database
library behind a single interface.  The rest of NTDSWolf imports only this
wrapper, never dissect.database directly, which makes the dissect API surface
explicit and testable.

The wrapper delegates iteration, schema access, and PEK operations to the
underlying dissect ``NTDS`` / ``Database`` objects while adding input
validation and clear error types for the pipeline layer.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.database.ese.ntds.ntds import NTDS

from ntdswolf.crypto.gkdi import KdsRootKey

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.database import DataTable, LinkTable, SecurityDescriptorTable
    from dissect.database.ese.ntds.objects.object import Object
    from dissect.database.ese.ntds.pek import PEK
    from dissect.database.ese.ntds.schema import Schema

logger = logging.getLogger(__name__)


class InvalidDatabaseError(Exception):
    """Raised when the NTDS.dit file cannot be opened or is structurally invalid."""


class NTDSDatabase:
    """Wrapper around dissect.database's NTDS parser.

    Provides a focused interface for the extraction pipeline: iterate objects,
    access schema, resolve PEK, and query the link/SD tables.  The underlying
    ``NTDS`` instance is retained for any advanced operations that dissect
    supports directly.
    """

    def __init__(self, ntds: NTDS, path: Path) -> None:
        """Wrap an already-opened NTDS instance.

        Callers should use :meth:`open` instead of constructing directly.
        """
        self._ntds: NTDS = ntds
        self._path: Path = path

    # --- Factory ---

    @staticmethod
    def open(path: str | Path) -> NTDSDatabase:
        """Open an NTDS.dit file and validate that it is a usable ESE database.

        Args:
            path: Filesystem path to the ntds.dit file.

        Returns:
            An :class:`NTDSDatabase` wrapping the opened database.

        Raises:
            InvalidDatabaseError: If the file does not exist, cannot be parsed
                as an ESE database, or lacks required NTDS tables.

        """
        path = Path(path)
        if not path.is_file():
            msg = f"NTDS.dit file not found: {path}"
            raise InvalidDatabaseError(msg)

        try:
            fh = path.open("rb")
            ntds = NTDS(fh)
        except Exception as exc:
            msg = f"Failed to open NTDS.dit database: {exc}"
            raise InvalidDatabaseError(msg) from exc

        logger.info("Opened NTDS.dit database: %s", path)
        return NTDSDatabase(ntds, path)

    # --- Path ---

    @property
    def path(self) -> Path:
        """Filesystem path to the underlying ntds.dit file."""
        return self._path

    # --- Underlying dissect objects ---

    @property
    def ntds(self) -> NTDS:
        """Raw dissect NTDS instance for advanced operations."""
        return self._ntds

    @property
    def data_table(self) -> DataTable:
        """The ESE datatable (all directory objects)."""
        return self._ntds.db.data

    @property
    def link_table(self) -> LinkTable:
        """The ESE link_table (object relationships)."""
        return self._ntds.db.link

    @property
    def sd_table(self) -> SecurityDescriptorTable:
        """The ESE sd_table (security descriptors)."""
        return self._ntds.db.sd

    @property
    def schema(self) -> Schema:
        """The loaded NTDS schema (attribute/class definitions)."""
        return self._ntds.db.data.schema

    @property
    def pek(self) -> PEK | None:
        """PEK handle from the root domain. Must call unlock(syskey) before use."""
        return self._ntds.pek

    # --- Iteration ---

    def walk(self) -> Iterator[Object]:
        """Walk the directory tree depth-first, yielding every object.

        This uses the PDNT parent chain and is the same traversal order as
        ``NTDS.walk()``.  Objects are upcast to their specific dissect types
        (User, Computer, Group, etc.) where the objectClass is recognized.
        """
        yield from self._ntds.walk()

    def iter_all(self) -> Iterator[Object]:
        """Iterate every record in the datatable sequentially.

        This is faster than :meth:`walk` because it reads the table linearly
        instead of following the PDNT tree, but objects come in ESE physical
        order rather than logical hierarchy order.
        """
        # The iter() method signature varies between dissect-database versions.
        # Older releases (1.x) have no ``raw`` parameter; newer releases add it.
        # We call without keyword arguments for maximum compatibility.
        yield from self._ntds.db.data.iter()

    def get_object(self, dnt: int) -> Object:
        """Look up a single object by its DNT (Directory Number Tag).

        Args:
            dnt: The DNT value to look up.

        Returns:
            The dissect Object at that DNT.

        """
        return self._ntds.db.data.get(dnt)

    def domain(self) -> Object | None:
        """Return the root domainDNS object, or None for AD LDS databases."""
        return self._ntds.domain()

    def root(self) -> Object:
        """Return the root object of the directory tree."""
        return self._ntds.root()

    def kds_root_keys(self) -> list[KdsRootKey]:
        """Read KDS root keys (raw ``msKds-*`` material) for offline GKDI / LAPS v2 decryption.

        Captures every ``msKds-ProvRootKey`` object's raw root-key bytes and
        KDF / secret-agreement parameters -- the inputs the offline MS-GKDI
        derivation needs.  Returns an empty list when the directory has no KDS
        root keys (gMSA / LAPS v2 never configured).  The raw values are read
        (not the hex/XML forms the KDS decoder surfaces) because dpapi-ng's KDF
        consumes them verbatim.
        """
        keys: list[KdsRootKey] = []
        for obj in self._ntds.db.data.iter():
            try:
                classes = obj.object_class or []
            except (AttributeError, ValueError, KeyError, TypeError):  # fmt: skip
                continue
            if "msKds-ProvRootKey" not in (classes if isinstance(classes, list) else [classes]):
                continue
            try:
                keys.append(
                    KdsRootKey(
                        guid=str(obj.get("cn")),
                        root_key_data=bytes(obj.get("msKds-RootKeyData", raw=True)),
                        kdf_parameters=bytes(obj.get("msKds-KDFParam", raw=True)),
                        secret_agreement_parameters=bytes(obj.get("msKds-SecretAgreementParam", raw=True)),
                        private_key_length=int(obj.get("msKds-PrivateKeyLength")),
                        public_key_length=int(obj.get("msKds-PublicKeyLength")),
                    )
                )
            except (AttributeError, ValueError, KeyError, TypeError):  # fmt: skip
                logger.debug("Failed to read a KDS root key", exc_info=True)
        return keys
