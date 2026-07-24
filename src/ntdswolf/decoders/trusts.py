# SPDX-License-Identifier: Apache-2.0
"""Decoder for trustedDomain objectClass.

Trust objects represent inter-domain or inter-forest trust relationships.
Each trust has a type, direction, attribute flags, and (for active trusts)
PEK-encrypted authentication credentials for the inbound and outbound
directions.  dissect removes the PEK layer; the plaintext LSAPR_AUTH_INFORMATION
array is parsed and keyed by ``ntdswolf.crypto.trusts``.

Per [MS-ADTS] section 6.1.6 (Trust Objects).

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from typing_extensions import override

from ntdswolf.crypto.trusts import parse_trust_auth
from ntdswolf.decoders.base import BaseDecoder, DecoderContext
from ntdswolf.models.flags import SupportedEncryptionTypes, TrustAttributes, TrustDirection, TrustType

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject

logger = logging.getLogger(__name__)


class TrustDecoder(BaseDecoder):
    """Decoder for ``trustedDomain`` objectClass.

    Extracts trust partner name, flat name, security identifier, type,
    direction, attributes, and decrypts trust authentication credentials
    (RC4-HMAC + AES Kerberos keys) when the boot key is available.
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract trust-specific attributes.

        Per [MS-ADTS] section 6.1.6.9.1 (Trust Object Attributes).
        """
        # --- Trust identity ---
        result["trustPartner"] = self._get_attr(obj, "trustPartner")
        result["flatName"] = self._get_attr(obj, "flatName")

        # securityIdentifier on a trust is the SID of the trusted domain; dissect
        # decodes it to its S-1-... string like any other SID-syntax attribute.
        trust_sid = self._get_attr(obj, "securityIdentifier")
        result["securityIdentifier"] = str(trust_sid) if trust_sid is not None else None

        # --- Trust type (enum). Per [MS-ADTS] section 6.1.6.9.1 (trustType). ---
        trust_type_raw = self._get_attr(obj, "trustType")
        if trust_type_raw is not None:
            try:
                result["trustType"] = TrustType(int(trust_type_raw)).name
            except (ValueError, TypeError):  # fmt: skip
                result["trustType"] = int(trust_type_raw)
        else:
            result["trustType"] = None

        # --- Trust direction (flags). Per [MS-ADTS] section 6.1.6.9.1. ---
        result["trustDirection"] = self._decode_flags_field(self._get_attr(obj, "trustDirection"), TrustDirection)

        # --- Trust attributes (flags). Per [MS-ADTS] section 6.1.6.7.9. ---
        result["trustAttributes"] = self._decode_flags_field(self._get_attr(obj, "trustAttributes"), TrustAttributes)

        # --- Supported encryption types ---
        enc_types = self._get_attr(obj, "msDS-SupportedEncryptionTypes")
        if enc_types is not None:
            result["msDS-SupportedEncryptionTypes"] = self._decode_flags_field(enc_types, SupportedEncryptionTypes)

        # --- Trust credential decryption (requires an unlocked PEK) ---
        if ctx.include_credentials and ctx.pek_list is not None:
            self._decode_trust_credentials(obj, result)

    def _decode_trust_credentials(self, obj: DissectObject, result: dict[str, Any]) -> None:
        """Parse trust credentials (RC4-HMAC + AES keys) for both directions.

        dissect removes the PEK layer, so ``trustAuthIncoming``/``Outgoing``
        come back as the decrypted LSAPR_AUTH_INFORMATION array.  The Kerberos
        salt for an inter-realm trust account is ``<REALM>krbtgt<FLATNAME>``
        (e.g. a PARTNER$ account in EXAMPLE.LAB uses ``EXAMPLE.LABkrbtgtPARTNER``).
        """
        our_realm = self._realm_from_dn(result.get("distinguishedName")).upper()
        our_flat = our_realm.split(".", 1)[0]  # AD defaults the NetBIOS name to the first DNS label
        partner_realm = (result.get("trustPartner") or "").upper()
        partner_flat = (result.get("flatName") or "").upper()

        trust_creds: dict[str, Any] = {}

        # Incoming: the partner authenticates into our domain; the trust account
        # lives in our realm, salted <OUR_REALM>krbtgt<PARTNER_FLAT>.
        incoming = self._get_attr(obj, "trustAuthIncoming")
        if isinstance(incoming, bytes) and incoming:
            parsed = parse_trust_auth(incoming, f"{our_realm}krbtgt{partner_flat}")
            if parsed:
                trust_creds["incoming"] = parsed

        # Outgoing: we authenticate into the partner domain; the trust account
        # lives in the partner realm, salted <PARTNER_REALM>krbtgt<OUR_FLAT>.
        outgoing = self._get_attr(obj, "trustAuthOutgoing")
        if isinstance(outgoing, bytes) and outgoing:
            parsed = parse_trust_auth(outgoing, f"{partner_realm}krbtgt{our_flat}")
            if parsed:
                trust_creds["outgoing"] = parsed

        if trust_creds:
            result["trustCredentials"] = trust_creds

    @staticmethod
    def _realm_from_dn(dn: str | None) -> str:
        """Build the domain DNS name from a DN's ``DC=`` components."""
        if not dn:
            return ""
        labels = [part.strip()[3:] for part in dn.split(",") if part.strip().upper().startswith("DC=")]
        return ".".join(labels)
