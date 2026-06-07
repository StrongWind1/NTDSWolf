"""NTDSWolf -- Offline NTDS.dit parser and credential extractor."""

from __future__ import annotations

from importlib.metadata import version

# Single source of truth for the version: the installed package metadata, which
# hatchling populates from the [project] version in pyproject.toml.
__version__ = version("ntdswolf")
