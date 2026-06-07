"""NTDSWolf CLI application -- typer entry point.

This module defines the main typer application and the ``ntdswolf`` command.
It parses CLI arguments, constructs an :class:`ExtractionConfig`, creates
a :class:`PipelineOrchestrator`, and runs the extraction pipeline.

Exit codes follow the constants in ``ntdswolf.constants``:
    0 -- success
    1 -- general error
    2 -- invalid database
    3 -- boot key failure
    4 -- partial extraction (some objects failed)
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from ntdswolf import __version__
from ntdswolf.cli.callbacks import validate_bootkey, validate_extract_classes
from ntdswolf.core.pipeline import ExtractionConfig, PipelineOrchestrator
from ntdswolf.output.base import SUPPORTED_FORMATS

# Typer application instance -- used by the [project.scripts] entry point.
app = typer.Typer(
    name="ntdswolf",
    help="Offline NTDS.dit parser and credential extractor for Active Directory forensics.",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

# Console for rich output on stderr (keeps stdout clean for piping).
_stderr = Console(stderr=True)

# Logger for this module.
logger = logging.getLogger(__name__)


def _version_callback(*, value: bool | None) -> None:
    """Show version and exit when --version is passed."""
    if value:
        typer.echo(f"ntdswolf {__version__}")
        raise typer.Exit


@app.command()
def extract(
    # --- Positional: path to ntds.dit ---
    ntds_dit: Annotated[
        Path,
        typer.Argument(
            help="Path to the NTDS.dit database file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    # --- Boot key sources ---
    system: Annotated[
        Path | None,
        typer.Option(
            "--system",
            help="Path to the SYSTEM registry hive for boot key extraction.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    bootkey: Annotated[
        str | None,
        typer.Option(
            "--bootkey",
            help="32-character hex boot key (alternative to --system).",
        ),
    ] = None,
    # --- Output ---
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output directory for extracted data.",
            resolve_path=True,
        ),
    ] = Path("ntdswolf-output"),
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help=f"Output format. Choices: {', '.join(sorted(SUPPORTED_FORMATS))}.",
        ),
    ] = "ndjson",
    # --- Extraction scope ---
    extract_classes: Annotated[
        list[str] | None,
        typer.Option(
            "--extract",
            "-e",
            help="Object class(es) to extract (e.g. user,computer,group). Repeat or comma-separate. Default: all.",
        ),
    ] = None,
    workers: Annotated[
        int,
        typer.Option(
            "--workers",
            "-w",
            help="Number of worker processes (1 = single-threaded).",
            min=1,
            max=32,
        ),
    ] = 1,
    *,
    no_history: Annotated[
        bool,
        typer.Option(
            "--no-history",
            help="Skip password hash history attributes.",
        ),
    ] = False,
    include_deleted: Annotated[
        bool,
        typer.Option(
            "--include-deleted",
            help="Include tombstoned (deleted) objects (excluded by default).",
        ),
    ] = False,
    naming: Annotated[
        str,
        typer.Option(
            "--naming",
            help="Naming for the _name field: 'dn' (distinguished name), 'sam' (sAMAccountName), or 'cn' (common name).",
        ),
    ] = "dn",
    raw: Annotated[
        bool,
        typer.Option(
            "--raw",
            help="Include all raw/unmapped attributes in output.",
        ),
    ] = False,
    # --- Verbosity ---
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable debug-level logging.",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress all non-error output.",
        ),
    ] = False,
    _version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            help="Show version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Extract credentials and objects from an NTDS.dit database."""
    # --- Configure logging ---
    if verbose and quiet:
        _stderr.print("[yellow]Warning:[/] --verbose and --quiet are mutually exclusive; using --verbose.")
        quiet = False

    log_level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.WARNING)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,
    )

    # --- Validate arguments ---
    validated_bootkey = validate_bootkey(bootkey)
    validated_classes = validate_extract_classes(extract_classes)

    if fmt not in SUPPORTED_FORMATS:
        _stderr.print(f"[red]Error:[/] Unknown format {fmt!r}. Choose from: {', '.join(sorted(SUPPORTED_FORMATS))}")
        raise typer.Exit(code=1)

    if naming not in ("dn", "sam", "cn"):
        _stderr.print(f"[red]Error:[/] Unknown naming convention {naming!r}. Choose 'dn', 'sam', or 'cn'.")
        raise typer.Exit(code=1)

    # --- Build configuration ---
    config = ExtractionConfig(
        ntds_path=ntds_dit,
        system_path=system,
        bootkey_hex=validated_bootkey,
        output_dir=output,
        output_format=fmt,
        extract_classes=validated_classes,
        include_deleted=include_deleted,
        no_history=no_history,
        workers=workers,
        naming=naming,
        raw=raw,
        verbose=verbose,
        quiet=quiet,
    )

    # --- Run the pipeline ---
    orchestrator = PipelineOrchestrator(config)
    result = orchestrator.run()

    # --- Report results ---
    if not quiet:
        _stderr.print()
        if result.counts_by_class:
            _stderr.print("[bold]Extraction summary:[/]")
            for cls, count in sorted(result.counts_by_class.items()):
                _stderr.print(f"  {cls}: {count}")
        _stderr.print(f"  Total decoded: {result.objects_decoded}")
        _stderr.print(f"  Skipped: {result.objects_skipped}")
        if result.objects_errored > 0:
            _stderr.print(f"  [yellow]Errors: {result.objects_errored}[/]")
        _stderr.print(f"  Duration: {result.duration_seconds:.1f}s")
        _stderr.print(f"  Output: {config.output_dir}")

    if result.errors:
        for err in result.errors:
            _stderr.print(f"[red]Error:[/] {err}")

    raise typer.Exit(code=result.exit_code)


def main() -> None:
    """Entry point for the ``ntdswolf`` console script and ``python -m ntdswolf``."""
    app()
