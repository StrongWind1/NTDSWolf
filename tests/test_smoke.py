"""Smoke tests: import, version, and CLI wiring.

These are intentionally minimal -- a seed so the test gate is non-empty and CI
has something to run. The real coverage (crypto vectors, decoders, end-to-end
extraction against synthetic fixtures) is tracked under the Phase 7 testing plan
in docs/TASKLIST.md and is not implemented here.
"""

from __future__ import annotations

from typer.testing import CliRunner

import ntdswolf
from ntdswolf.cli.app import app

runner = CliRunner()


def test_version_is_present() -> None:
    assert isinstance(ntdswolf.__version__, str)
    assert ntdswolf.__version__


def test_cli_help_runs() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.stdout


def test_cli_requires_ntds_path() -> None:
    # No positional argument -> typer should reject with a non-zero exit code.
    result = runner.invoke(app, [])
    assert result.exit_code != 0
