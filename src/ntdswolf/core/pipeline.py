"""PipelineOrchestrator -- coordinates the three extraction phases.

The extraction pipeline has three sequential phases:

1. **Open** -- Open the NTDS.dit ESE database and load the schema.
2. **Decrypt** -- Resolve the boot key (from SYSTEM hive or hex) and unlock the
   PEK list so encrypted attributes can be decrypted.
3. **Extract** -- Iterate all objects in the datatable, classify each by
   objectClass, decode attributes (member/memberOf and other links resolved
   natively by dissect, credentials decrypted), and write serialized dicts to
   the OutputManager.

Phase 3 runs single-threaded by default, or distributes object decoding across
worker processes when ``--workers`` is greater than 1 (see ``core.workers``).

All progress feedback uses ``rich.progress`` on stderr so that stdout remains
clean for piped output.
"""

from __future__ import annotations

import logging
import multiprocessing
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects.object import Object
    from dpapi_ng import KeyCache

    from ntdswolf.crypto.gkdi import KdsRootKey

from ntdswolf.constants import (
    EXIT_BOOTKEY_FAILED,
    EXIT_GENERAL_ERROR,
    EXIT_INVALID_DATABASE,
    EXIT_PARTIAL_EXTRACTION,
    EXIT_SUCCESS,
)
from ntdswolf.core.database import InvalidDatabaseError, NTDSDatabase
from ntdswolf.core.workers import WorkerPool
from ntdswolf.crypto.bootkey import resolve_bootkey
from ntdswolf.crypto.gkdi import build_kds_cache
from ntdswolf.decoders.base import DecoderContext
from ntdswolf.decoders.registry import build_default_registry
from ntdswolf.output.base import OutputManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExtractionConfig:
    """All user-facing options that control the extraction pipeline.

    Populated from CLI arguments and passed into ``PipelineOrchestrator.run()``.
    """

    # --- Input ---
    ntds_path: Path  # Path to the ntds.dit file
    system_path: Path | None = None  # Path to the SYSTEM registry hive
    bootkey_hex: str | None = None  # 32-char hex boot key (alternative to SYSTEM hive)

    # --- Output ---
    output_dir: Path = field(default_factory=lambda: Path("ntdswolf-output"))  # Output directory
    output_format: str = "ndjson"  # Output format (ndjson, json, csv, hashcat, pwdump)

    # --- Extraction scope ---
    extract_classes: set[str] | None = None  # Which object classes to extract (None = all)
    include_deleted: bool = False  # Include tombstoned objects
    no_history: bool = False  # Skip hash history attributes

    # --- Processing ---
    workers: int = 1  # Number of worker processes (1 = single-threaded)

    # --- Output style ---
    naming: str = "dn"  # DN format for object naming ("dn" or "sam")
    hashcat_username: str = "sam"  # Username field for hashcat output (sam/upn/rid/sid)

    # --- Logging ---
    verbose: bool = False  # Debug-level logging
    quiet: bool = False  # Suppress non-error output


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExtractionResult:
    """Summary of a completed extraction run."""

    exit_code: int = EXIT_SUCCESS
    objects_total: int = 0  # Total objects iterated
    objects_decoded: int = 0  # Objects successfully decoded
    objects_skipped: int = 0  # Objects skipped (filtered, phantom, etc.)
    objects_errored: int = 0  # Objects that raised during decoding
    counts_by_class: dict[str, int] = field(default_factory=dict)  # Per-class output counts
    duration_seconds: float = 0.0  # Wall-clock time
    errors: list[str] = field(default_factory=list)  # Collected error messages


# ---------------------------------------------------------------------------
# Pipeline Orchestrator
# ---------------------------------------------------------------------------


class PipelineOrchestrator:
    """Coordinates the three-phase extraction pipeline.

    Construct with an :class:`ExtractionConfig`, then call :meth:`run` to
    execute all phases.  Progress bars are displayed on stderr via rich.
    """

    def __init__(self, config: ExtractionConfig) -> None:
        """Initialize the orchestrator with the given extraction configuration."""
        self._config: ExtractionConfig = config
        self._ntds_db: NTDSDatabase | None = None
        self._registry = build_default_registry()
        self._pek_unlocked: bool = False
        self._bootkey: bytes | None = None
        self._kds_cache: KeyCache | None = None
        self._kds_root_keys: list[KdsRootKey] = []

    def run(self) -> ExtractionResult:
        """Execute all three extraction phases and return the result summary.

        Returns:
            An :class:`ExtractionResult` with counts, timing, and exit code.

        """
        result = ExtractionResult()
        start_time = time.monotonic()

        # Build the progress display on stderr so stdout stays clean for piping.
        stderr_console = Console(stderr=True, quiet=self._config.quiet)
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
            console=stderr_console,
            disable=self._config.quiet,
        )

        with progress:
            if not self._run_phases(progress, result, start_time):
                return result

        # Set exit code based on error count.
        if result.exit_code == EXIT_SUCCESS and result.objects_errored > 0:
            result.exit_code = EXIT_PARTIAL_EXTRACTION

        result.duration_seconds = time.monotonic() - start_time
        return result

    def _run_phases(self, progress: Progress, result: ExtractionResult, start_time: float) -> bool:
        """Execute pipeline phases 1-3 inside the progress context.

        Returns True if all phases completed, False if an early exit occurred
        (result is already populated with error info on False).
        """
        # Phase 1: Open database
        phase1_task = progress.add_task("Phase 1: Opening database...", total=1)
        try:
            self._phase1_open()
            progress.update(phase1_task, advance=1, description="Phase 1: Database opened")
        except InvalidDatabaseError as exc:
            result.exit_code = EXIT_INVALID_DATABASE
            result.errors.append(str(exc))
            result.duration_seconds = time.monotonic() - start_time
            progress.update(phase1_task, description="[red]Phase 1: FAILED")
            logger.exception("Phase 1 failed")
            return False

        # Phase 2: Resolve boot key and decrypt PEK
        if not self._run_phase2(progress, result, start_time):
            return False

        # Phase 3: Extract and decode objects
        try:
            self._phase3_extract(progress, result)
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            result.exit_code = EXIT_GENERAL_ERROR
            result.errors.append(f"Extraction failed: {exc}")
            logger.exception("Phase 3 failed")

        return True

    def _run_phase2(self, progress: Progress, result: ExtractionResult, start_time: float) -> bool:
        """Execute Phase 2 (boot key and PEK decryption). Returns False on failure."""
        phase2_task = progress.add_task("Phase 2: Decrypting PEK...", total=1)
        try:
            self._phase2_decrypt()
            status = "Phase 2: PEK decrypted" if self._pek_unlocked else "Phase 2: No boot key (limited extraction)"
            progress.update(phase2_task, advance=1, description=status)
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            result.exit_code = EXIT_BOOTKEY_FAILED
            result.errors.append(f"PEK decryption failed: {exc}")
            result.duration_seconds = time.monotonic() - start_time
            progress.update(phase2_task, description="[red]Phase 2: FAILED")
            logger.exception("Phase 2 failed")
            return False
        return True

    # --- Phase 1: Open database ---

    def _phase1_open(self) -> None:
        """Open the NTDS.dit file and validate it."""
        self._ntds_db = NTDSDatabase.open(self._config.ntds_path)
        logger.info("Database opened: %s", self._config.ntds_path)

    # --- Phase 2: Decrypt PEK ---

    def _phase2_decrypt(self) -> None:
        """Resolve the boot key and unlock the PEK list for credential decryption."""
        if self._ntds_db is None:
            msg = "Database not opened: run phase 1 first"
            raise RuntimeError(msg)

        bootkey = resolve_bootkey(
            bootkey_hex=self._config.bootkey_hex,
            system_path=self._config.system_path,
            ntds_dir=self._config.ntds_path.parent,
        )

        if bootkey is None:
            logger.warning("No boot key available -- encrypted attributes will be skipped")
            self._pek_unlocked = False
            return

        self._bootkey = bootkey

        pek = self._ntds_db.pek
        if pek is None:
            logger.warning("No PEK list found in database -- encrypted attributes will be skipped")
            self._pek_unlocked = False
            return

        # Unlock the PEK list with the boot key.
        pek.unlock(bootkey)
        self._pek_unlocked = pek.unlocked
        if self._pek_unlocked:
            logger.info("PEK list unlocked successfully")
        else:
            logger.warning("PEK unlock returned but unlocked flag is False")

    # --- Phase 3: Extract and decode ---

    def _phase3_extract(self, progress: Progress, result: ExtractionResult) -> None:
        """Iterate all objects, decode, and write to output.

        Runs single-threaded, or across worker processes when ``--workers`` > 1
        and the fork start method is available.
        """
        if self._ntds_db is None:
            msg = "Database not opened: run phase 1 first"
            raise RuntimeError(msg)

        config = self._config

        # Create the output manager.
        output = OutputManager(
            fmt=config.output_format,
            output_dir=config.output_dir,
            extract_classes=config.extract_classes,
            hashcat_username=config.hashcat_username,
        )

        # We iterate via the datatable's linear scan for maximum speed.
        # The walk() method follows the PDNT tree which is slower for full extraction.
        phase3_task = progress.add_task("Phase 3: Extracting objects...", total=None)

        # Decoders accept dissect's PEK directly -- it exposes decrypt(), so no
        # wrapping is needed (see PekDecryptor).
        pek = self._ntds_db.pek if self._pek_unlocked else None

        # Load KDS root keys once (shared with workers via fork) so the computer
        # decoder can decrypt msLAPS-EncryptedPassword (LAPS v2) offline.  Gated
        # on the boot key being available, i.e. credentials are being extracted.
        if self._pek_unlocked:
            root_keys = self._ntds_db.kds_root_keys()
            if root_keys:
                self._kds_root_keys = root_keys
                self._kds_cache = build_kds_cache(root_keys)
                logger.info("Loaded %d KDS root key(s) for LAPS v2 + gMSA/dMSA derivation", len(root_keys))

        ctx = DecoderContext(
            pek_list=pek,
            kds_cache=self._kds_cache,
            kds_root_keys=self._kds_root_keys,
            include_deleted=config.include_deleted,
            naming=config.naming,
        )

        # Parallel extraction requires the fork start method (Linux); otherwise
        # fall back to the single-threaded loop.
        if config.workers > 1 and "fork" in multiprocessing.get_all_start_methods():
            self._extract_parallel(output, result, progress, phase3_task)
        else:
            if config.workers > 1:
                logger.warning("Parallel extraction needs the 'fork' start method; running single-threaded")
            self._extract_single(output, result, progress, phase3_task, ctx)

        # Emit DPAPI domain backup keys decoded natively by dissect.
        self._emit_backup_keys(output, result)

        # Finalize output and collect per-class counts.
        result.counts_by_class = output.finalize()

        progress.update(phase3_task, completed=result.objects_total, description=f"Phase 3: Done ({result.objects_decoded} decoded)")

    def _emit_backup_keys(self, output: OutputManager, result: ExtractionResult) -> None:
        """Emit DPAPI domain backup keys decoded natively by dissect.

        dissect's ``NTDS.backup_keys`` removes the PEK layer from the
        ``BCKUPKEY_*`` secret objects and parses the legacy key / RSA key pair,
        so we surface those instead of re-implementing DPAPI backup-key parsing.
        Requires an unlocked PEK; a no-op otherwise.
        """
        if not self._pek_unlocked or self._ntds_db is None:
            return
        try:
            backup_keys = list(self._ntds_db.ntds.backup_keys())
        except (AttributeError, ValueError, TypeError, RuntimeError, KeyError):
            logger.debug("DPAPI backup key extraction failed", exc_info=True)
            return
        for bk in backup_keys:
            entry: dict[str, Any] = {
                "_object_class": "dpapiBackupKey",
                "guid": str(getattr(bk, "guid", "")),
                "version": int(getattr(bk, "version", 0)),
                "isLegacy": bool(getattr(bk, "is_legacy", False)),
            }
            # ``key`` is the legacy backup key; v2 keys expose an RSA key pair.
            # Accessing the wrong one for a given version raises -- skip it.
            for attr, name in (("key", "key"), ("public_key", "publicKey"), ("private_key", "privateKey")):
                try:
                    value = getattr(bk, attr)
                except (AttributeError, TypeError, ValueError):
                    continue
                if isinstance(value, bytes | bytearray):
                    entry[name] = value.hex()
                elif value is not None:
                    entry[name] = str(value)
            output.write(entry)
            result.objects_decoded += 1

    def _extract_single(self, output: OutputManager, result: ExtractionResult, progress: Progress, task_id: TaskID, ctx: DecoderContext) -> None:
        """Single-threaded Phase 3 extraction loop."""
        if self._ntds_db is None:
            return
        for obj in self._ntds_db.iter_all():
            result.objects_total += 1

            # Update progress periodically (every 1000 objects) to avoid overhead.
            if result.objects_total % 1000 == 0:
                progress.update(task_id, completed=result.objects_total, description=f"Phase 3: Extracting... ({result.objects_total} objects)")

            try:
                obj_dict = self._decode_object(obj, ctx)
            except (AttributeError, KeyError, TypeError, ValueError, OSError, RuntimeError):  # fmt: skip
                result.objects_errored += 1
                logger.debug("Failed to decode object DNT=%s", getattr(obj, "dnt", "?"), exc_info=True)
                continue

            if obj_dict is None:
                result.objects_skipped += 1
                continue

            output.write(obj_dict)
            result.objects_decoded += 1

    def _extract_parallel(self, output: OutputManager, result: ExtractionResult, progress: Progress, task_id: TaskID) -> None:
        """Phase 3 extraction across multiple worker processes.

        Collects every object's DNT in a single linear scan, then distributes
        batches to worker processes that re-read and decode them in parallel.
        """
        if self._ntds_db is None:
            return

        dnts: list[int] = []
        for obj in self._ntds_db.iter_all():
            try:
                dnts.append(obj.dnt)
            except (AttributeError, ValueError, KeyError, TypeError):  # fmt: skip
                continue
        result.objects_total = len(dnts)

        batch_size = 1000
        batches = [dnts[i : i + batch_size] for i in range(0, len(dnts), batch_size)]

        pool = WorkerPool(
            self._ntds_db.path,
            self._bootkey,
            self._config.workers,
            include_deleted=self._config.include_deleted,
            naming=self._config.naming,
            kds_cache=self._kds_cache,
            kds_root_keys=self._kds_root_keys,
        )
        try:
            for decoded in pool.map_batches(batches):
                output.write_batch(decoded)
                result.objects_decoded += len(decoded)
                progress.update(task_id, completed=result.objects_decoded, description=f"Phase 3: Extracting ({self._config.workers} workers)... ({result.objects_decoded} decoded)")
        finally:
            pool.shutdown()

        result.objects_skipped = result.objects_total - result.objects_decoded

    def _decode_object(self, obj: Object, ctx: DecoderContext) -> dict[str, Any] | None:
        """Decode a single dissect Object via the decoder registry.

        Skips phantom and (unless --include-deleted) deleted objects, then
        dispatches to the decoder registered for the object's most-specific
        objectClass. The decoder returns a dict ready for OutputManager.write().

        Args:
            obj: A dissect Object instance.
            ctx: The DecoderContext shared across the extraction pass.

        Returns:
            A serialized dict, or None if the object should be skipped.

        """
        if self._should_skip(obj):
            return None
        decoder = self._registry.get(obj.object_class)
        result = decoder.decode(obj, ctx)
        return result or None

    def _should_skip(self, obj: Object) -> bool:
        """Return True if the object should be excluded from extraction."""
        # Skip phantom (non-local) objects -- cross-domain references with no local data.
        try:
            if obj.is_phantom:
                return True
        except (AttributeError, TypeError):  # fmt: skip
            pass

        # Skip deleted objects unless --include-deleted was specified.
        try:
            if obj.is_deleted and not self._config.include_deleted:
                return True
        except (AttributeError, TypeError):  # fmt: skip
            pass

        return False
