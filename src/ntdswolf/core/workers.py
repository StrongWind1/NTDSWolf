# SPDX-License-Identifier: Apache-2.0
"""Multiprocessing worker pool for parallel object decoding (Phase 4).

dissect Objects cannot cross process boundaries (they hold a live database
reference), so each worker opens its own database handle and re-reads objects by
DNT. The expensive per-object work -- credential decryption and
supplementalCredentials decoding -- is what gets parallelized.

The link resolver is shared with workers via fork inheritance: the pool stores
it in a module global before the executor is created, and forked children
inherit it copy-on-write without pickling (which matters because the resolver
holds large link maps and non-picklable defaultdicts). Only small, picklable
values (the database path and boot key) are passed as initializer arguments.

Fork is required (the default start method on Linux); on spawn-only platforms
the pipeline falls back to single-threaded extraction.
"""

from __future__ import annotations

import logging
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from typing import TYPE_CHECKING, Any

from ntdswolf.core.database import NTDSDatabase
from ntdswolf.decoders.base import DecoderContext
from ntdswolf.decoders.registry import build_default_registry

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.database.ese.ntds.objects import Object as DissectObject
    from dpapi_ng import KeyCache

    from ntdswolf.crypto.gkdi import KdsRootKey

logger = logging.getLogger(__name__)

# Shared with forked workers (set by WorkerPool before the executor is created).
_SHARED_INCLUDE_DELETED: bool = False
_SHARED_NAMING: str = "dn"
_SHARED_KDS_CACHE: KeyCache | None = None  # dpapi-ng cache for LAPS v2 / GKDI, inherited via fork
_SHARED_KDS_ROOT_KEYS: list[KdsRootKey] = []  # raw KDS root keys for gMSA/dMSA password derivation, inherited via fork

# Per-worker state, populated by _worker_init in each child process.
_WORKER: dict[str, Any] = {}


def _worker_init(db_path: Path, bootkey: bytes | None) -> None:
    """Open a per-worker database handle and build the decode context.

    Runs once in each child process. Reads the shared include-deleted flag and
    naming from module globals inherited via fork.
    """
    db = NTDSDatabase.open(db_path)
    # Each worker unlocks its own dissect PEK and passes it straight through;
    # the decoders accept it via the PekDecryptor interface.
    pek = None
    if bootkey is not None and db.pek is not None:
        db.pek.unlock(bootkey)
        if db.pek.unlocked:
            pek = db.pek
    _WORKER["db"] = db
    _WORKER["registry"] = build_default_registry()
    _WORKER["ctx"] = DecoderContext(pek_list=pek, kds_cache=_SHARED_KDS_CACHE, kds_root_keys=_SHARED_KDS_ROOT_KEYS, include_deleted=_SHARED_INCLUDE_DELETED, naming=_SHARED_NAMING)


def _decode_dnt_batch(dnts: list[int]) -> list[dict[str, Any]]:
    """Decode a batch of objects (looked up by DNT) inside a worker process."""
    db = _WORKER["db"]
    registry = _WORKER["registry"]
    ctx = _WORKER["ctx"]
    decoded: list[dict[str, Any]] = []
    for dnt in dnts:
        try:
            obj = db.get_object(dnt)
            if _should_skip(obj):
                continue
            result = registry.get(obj.object_class).decode(obj, ctx)
            if result:
                # _picklable runs inside the catch so a value whose __str__
                # touches the forked file handle can't escape and crash the pool.
                decoded.append(_picklable(result))
        except Exception:
            logger.debug("Worker failed to decode DNT %s", dnt, exc_info=True)
            continue
    return decoded


def _picklable(value: Any) -> Any:  # noqa: ANN401 -- recursive sanitizer over arbitrary decoded values
    """Convert decoded values to plain JSON-native types for the pickle round-trip.

    dissect leaves some attribute values as objects that hold a live file handle
    (e.g. distinguished-name wrappers), which cannot be pickled back from a
    worker. Coercing non-native leaves to ``str`` mirrors what the output writers
    already do via ``json.dumps(default=str)``, so parallel output matches the
    single-threaded path.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return {str(k): _picklable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_picklable(v) for v in value]
    # Flatten int subclasses (IntFlag/IntEnum) to plain int; everything else --
    # including str subclasses like dissect's DN, which carry .object/.parent
    # references reaching a live file handle -- becomes a plain str (matching the
    # output writers' json.dumps(default=str) behavior).
    if isinstance(value, int):
        return int(value)
    return str(value)


def _should_skip(obj: DissectObject) -> bool:
    """Mirror the pipeline's phantom/deleted skip logic inside a worker."""
    try:
        if obj.is_phantom:
            return True
    except (AttributeError, TypeError):
        pass
    try:
        if obj.is_deleted and not _SHARED_INCLUDE_DELETED:
            return True
    except (AttributeError, TypeError):
        pass
    return False


class WorkerPool:
    """Process pool that decodes object batches in parallel.

    Submit batches of DNTs via :meth:`map_batches`; each yields a list of decoded
    object dicts. Call :meth:`shutdown` when done (or use as a context manager).
    """

    def __init__(self, db_path: Path, bootkey: bytes | None, workers: int, *, include_deleted: bool, naming: str = "dn", kds_cache: KeyCache | None = None, kds_root_keys: list[KdsRootKey] | None = None) -> None:
        """Create the pool and publish the shared state for forked workers."""
        global _SHARED_INCLUDE_DELETED, _SHARED_NAMING, _SHARED_KDS_CACHE, _SHARED_KDS_ROOT_KEYS  # noqa: PLW0603 -- inherited by forked workers
        _SHARED_INCLUDE_DELETED = include_deleted
        _SHARED_NAMING = naming
        _SHARED_KDS_CACHE = kds_cache
        _SHARED_KDS_ROOT_KEYS = kds_root_keys or []
        self._executor = ProcessPoolExecutor(
            max_workers=workers,
            mp_context=multiprocessing.get_context("fork"),
            initializer=_worker_init,
            initargs=(db_path, bootkey),
        )

    def map_batches(self, batches: list[list[int]]) -> Iterator[list[dict[str, Any]]]:
        """Decode each DNT batch in parallel, yielding results in batch order."""
        yield from self._executor.map(_decode_dnt_batch, batches)

    def shutdown(self) -> None:
        """Shut down the pool and wait for workers to exit."""
        self._executor.shutdown(wait=True)
