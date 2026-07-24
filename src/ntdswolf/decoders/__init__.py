# SPDX-License-Identifier: Apache-2.0
"""Decoders subpackage -- object extraction from raw ESE records.

Each decoder transforms dissect.database Object instances into flat
dictionaries matching the JSON output schema.  The DecoderRegistry
maps objectClass names to decoder instances; unknown classes fall back
to GenericDecoder.

Public API:
    build_default_registry() -- factory that wires up all standard decoders
    DecoderRegistry          -- class-name -> decoder lookup table
    DecoderContext           -- dependency bundle injected at decode time
    BaseDecoder              -- abstract base for all decoders
"""

from __future__ import annotations

from ntdswolf.decoders.base import BaseDecoder, DecoderContext
from ntdswolf.decoders.registry import DecoderRegistry, build_default_registry

__all__ = [
    "BaseDecoder",
    "DecoderContext",
    "DecoderRegistry",
    "build_default_registry",
]
