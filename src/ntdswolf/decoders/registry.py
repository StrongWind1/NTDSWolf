"""Decoder registry mapping objectClass names to decoder instances.

The registry is the central dispatch table used by the extraction pipeline
to look up the correct decoder for each AD object encountered during the
database walk.  Each objectClass string (e.g., "user", "group",
"trustedDomain") maps to a BaseDecoder subclass instance.

Unknown objectClasses fall back to GenericDecoder, which captures all
attributes without type-specific formatting.

Usage::

    registry = build_default_registry()
    decoder = registry.get("user")       # -> UserDecoder instance
    decoder = registry.get("widget")     # -> GenericDecoder instance (fallback)

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ntdswolf.constants import (
    OBJECT_CLASS_BITLOCKER,
    OBJECT_CLASS_COMPUTER,
    OBJECT_CLASS_DMSA,
    OBJECT_CLASS_DOMAIN_DNS,
    OBJECT_CLASS_GMSA,
    OBJECT_CLASS_GPO,
    OBJECT_CLASS_GROUP,
    OBJECT_CLASS_KDS_ROOT_KEY,
    OBJECT_CLASS_MSA,
    OBJECT_CLASS_TRUSTED_DOMAIN,
    OBJECT_CLASS_USER,
)
from ntdswolf.decoders.bitlocker import BitLockerDecoder
from ntdswolf.decoders.domains import DomainDecoder
from ntdswolf.decoders.generic import GenericDecoder
from ntdswolf.decoders.gmsa import GMSADecoder
from ntdswolf.decoders.gpo import GPODecoder
from ntdswolf.decoders.groups import GroupDecoder
from ntdswolf.decoders.kds import KDSDecoder
from ntdswolf.decoders.trusts import TrustDecoder
from ntdswolf.decoders.users import UserDecoder

if TYPE_CHECKING:
    from ntdswolf.decoders.base import BaseDecoder

logger = logging.getLogger(__name__)


class DecoderRegistry:
    """Maps objectClass names to decoder instances.

    The registry provides O(1) lookup from objectClass strings to the
    decoder that handles that class.  Unknown classes fall back to the
    GenericDecoder so no data is silently dropped.
    """

    def __init__(self) -> None:
        """Initialize with an empty decoder map and GenericDecoder fallback."""
        self._decoders: dict[str, BaseDecoder] = {}
        self._fallback: BaseDecoder = GenericDecoder()

    def register(self, object_class: str, decoder: BaseDecoder) -> None:
        """Register a decoder for a specific objectClass.

        If a decoder is already registered for *object_class*, it is
        silently replaced (last-wins semantics).

        Args:
            object_class: The lDAPDisplayName of the objectClass (e.g., "user").
            decoder: The BaseDecoder subclass instance to handle this class.

        """
        self._decoders[object_class] = decoder
        logger.debug("Registered decoder %s for objectClass %r", type(decoder).__name__, object_class)

    def get(self, object_class: str | list[str] | None) -> BaseDecoder:
        """Look up the decoder for an objectClass.

        If *object_class* is a list (as returned by dissect's objectClass
        attribute), the first element is used as the most-specific class.

        Returns GenericDecoder for unknown or None objectClasses.

        Args:
            object_class: objectClass string, list of strings, or None.

        Returns:
            The registered BaseDecoder, or GenericDecoder as fallback.

        """
        if object_class is None:
            return self._fallback

        # objectClass is multi-valued; first element is the most specific
        if isinstance(object_class, list):
            if not object_class:
                return self._fallback
            # Try each class in order from most specific to least specific
            for cls_name in object_class:
                if cls_name in self._decoders:
                    return self._decoders[cls_name]
            return self._fallback

        return self._decoders.get(object_class, self._fallback)

    @property
    def registered_classes(self) -> list[str]:
        """Return a sorted list of all registered objectClass names."""
        return sorted(self._decoders.keys())

    def __contains__(self, object_class: str) -> bool:
        """Check if an objectClass has a registered decoder."""
        return object_class in self._decoders

    def __len__(self) -> int:
        """Return the number of registered decoders."""
        return len(self._decoders)


def build_default_registry() -> DecoderRegistry:
    """Build a DecoderRegistry with all standard decoders wired up.

    Creates one instance of each decoder and registers it against its
    target objectClass name(s).  The UserDecoder handles both "user"
    and "computer" classes because computers are a subclass of user in
    the AD schema.

    Returns:
        Fully populated DecoderRegistry ready for use.

    """
    registry = DecoderRegistry()

    # --- User and computer accounts ---
    # Computers are a subclass of user in AD; both use UserDecoder
    # because they share identity, timestamp, and credential attributes.
    user_decoder = UserDecoder()
    registry.register(OBJECT_CLASS_USER, user_decoder)
    registry.register(OBJECT_CLASS_COMPUTER, user_decoder)

    # --- Groups ---
    registry.register(OBJECT_CLASS_GROUP, GroupDecoder())

    # --- Trust relationships ---
    registry.register(OBJECT_CLASS_TRUSTED_DOMAIN, TrustDecoder())

    # --- Domain root ---
    registry.register(OBJECT_CLASS_DOMAIN_DNS, DomainDecoder())

    # --- Group Policy Objects ---
    registry.register(OBJECT_CLASS_GPO, GPODecoder())

    # --- Managed Service Accounts ---
    # gMSA and dMSA (Server 2025) are GKDI-managed and share the same credential
    # shape (NT hash + Kerberos keys + managed-password metadata).
    gmsa_decoder = GMSADecoder()
    registry.register(OBJECT_CLASS_GMSA, gmsa_decoder)
    registry.register(OBJECT_CLASS_DMSA, gmsa_decoder)
    # Standalone MSAs are machine-managed like computer accounts (NT hash +
    # Kerberos keys in supplementalCredentials), so they reuse the user decoder.
    registry.register(OBJECT_CLASS_MSA, user_decoder)

    # --- BitLocker recovery keys ---
    registry.register(OBJECT_CLASS_BITLOCKER, BitLockerDecoder())

    # --- KDS root keys ---
    registry.register(OBJECT_CLASS_KDS_ROOT_KEY, KDSDecoder())

    logger.info("Decoder registry built with %d object classes: %s", len(registry), ", ".join(registry.registered_classes))

    return registry
