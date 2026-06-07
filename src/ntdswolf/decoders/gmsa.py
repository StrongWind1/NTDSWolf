"""Decoder for msDS-GroupManagedServiceAccount objectClass.

Group Managed Service Accounts (gMSAs) have their passwords automatically
managed by AD via the Group Key Distribution Protocol (GKDI).  The password
is derived from KDS root key material combined with a managed password ID
blob that encodes the key derivation parameters.

This decoder extracts the gMSA identity attributes and password derivation
metadata.  Actual password derivation from KDS root keys is handled
separately by the crypto layer.

Per [MS-ADTS] section 3.1.1.4.5.28 (msDS-GroupManagedServiceAccount).

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from Crypto.Hash import MD4
from typing_extensions import override

from ntdswolf.crypto.gkdi import derive_gmsa_password
from ntdswolf.crypto.hashes import decrypt_nt_hash
from ntdswolf.decoders._supplemental import merge_supplemental
from ntdswolf.decoders.base import BaseDecoder, DecoderContext

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject
from ntdswolf.models.flags import SupportedEncryptionTypes, UserAccountControl

logger = logging.getLogger(__name__)


class GMSADecoder(BaseDecoder):
    """Decoder for ``msDS-GroupManagedServiceAccount`` objectClass.

    Extracts sAMAccountName, objectSid, managed password metadata, and
    credentials (if PEK is available and the account has stored hashes).
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract gMSA-specific attributes.

        Per [MS-ADTS] section 3.1.1.4.5.28 and [MS-GKDI] for GKDI params.
        """
        # --- Identity ---
        result["sAMAccountName"] = self._get_attr(obj, "sAMAccountName")

        # --- Account control flags ---
        uac_raw = self._get_attr(obj, "userAccountControl")
        result["userAccountControl"] = self._decode_flags_field(uac_raw, UserAccountControl)

        sam_type = self._get_attr(obj, "sAMAccountType")
        if sam_type is not None:
            result["sAMAccountType"] = int(sam_type) if not isinstance(sam_type, int) else sam_type

        # --- Managed password metadata ---
        self._decode_managed_password_attrs(obj, result)

        # --- Encryption types ---
        enc_types = self._get_attr(obj, "msDS-SupportedEncryptionTypes")
        if enc_types is not None:
            result["msDS-SupportedEncryptionTypes"] = self._decode_flags_field(enc_types, SupportedEncryptionTypes)

        # --- Group membership (memberOf backlinks, via dissect) ---
        if ctx.include_links:
            result["memberOf"] = self._resolve_links(obj, "memberOf", forward=False)
        else:
            result["memberOf"] = []

        # --- Credential extraction ---
        # gMSAs may have stored NT hashes and supplemental credentials
        # even though their passwords are managed.  The PEK-encrypted
        # attributes are the same as for regular user accounts.
        if ctx.include_credentials and ctx.pek_list is not None:
            self._decode_gmsa_credentials(obj, ctx, result)

        # Offline managed-password derivation (gMSA + dMSA), self-verified vs the NT hash.
        if ctx.include_credentials:
            self._decode_managed_password(obj, ctx, result)

    def _decode_managed_password(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Derive the gMSA/dMSA managed password offline and self-verify it.

        The DC-managed password is not stored, but it is reproducible from the
        KDS root key + ``msDS-ManagedPasswordId`` + the account SID (see
        :func:`ntdswolf.crypto.gkdi.derive_gmsa_password`).  ``MD4`` of the
        derived 256-byte password is the account's NT hash, so we cross-check it
        against the decrypted ``ntHash``.
        """
        if not ctx.kds_root_keys:
            return
        managed_pwd_id = self._get_attr(obj, "msDS-ManagedPasswordId", raw=True)
        sid = result.get("objectSid")
        if not isinstance(managed_pwd_id, bytes) or not isinstance(sid, str):
            return
        password = derive_gmsa_password(ctx.kds_root_keys, managed_pwd_id, sid)
        if password is None:
            return
        result["managedPassword"] = password.hex()
        nt_hash = MD4.new(password).digest().hex()  # noqa: S303 -- MD4 is the NT-hash construction
        credentials = result.get("credentials")
        if isinstance(credentials, dict):
            result["managedPasswordVerified"] = nt_hash == credentials.get("ntHash")
        else:
            result["managedPasswordNtHash"] = nt_hash

    def _decode_managed_password_attrs(self, obj: DissectObject, result: dict[str, Any]) -> None:
        """Extract msDS-ManagedPassword* attributes."""
        # msDS-ManagedPasswordId is a binary blob encoding the KDS root key
        # GUID, L0/L1/L2 key identifiers, and the GKDI service name used
        # for password derivation.
        # Per [MS-GKDI] section 2.2.4.
        managed_pwd_id = self._get_attr(obj, "msDS-ManagedPasswordId", raw=True)
        if managed_pwd_id is not None and isinstance(managed_pwd_id, bytes):
            result["msDS-ManagedPasswordId"] = managed_pwd_id.hex()
        else:
            result["msDS-ManagedPasswordId"] = None

        # msDS-ManagedPasswordInterval: number of days between automatic
        # password rotations.  Default is 30.
        result["msDS-ManagedPasswordInterval"] = self._get_attr(obj, "msDS-ManagedPasswordInterval")

        # msDS-ManagedPasswordPreviousId: the managed password ID from the
        # previous rotation cycle (for rollback/transition).
        prev_pwd_id = self._get_attr(obj, "msDS-ManagedPasswordPreviousId", raw=True)
        if prev_pwd_id is not None and isinstance(prev_pwd_id, bytes):
            result["msDS-ManagedPasswordPreviousId"] = prev_pwd_id.hex()

        # msDS-GroupMSAMembership: SDDL of the security descriptor that
        # defines which principals can retrieve the managed password.
        gmsam = self._get_attr(obj, "msDS-GroupMSAMembership")
        if gmsam is not None:
            result["msDS-GroupMSAMembership"] = gmsam.hex() if isinstance(gmsam, bytes) else str(gmsam)

    def _decode_gmsa_credentials(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Decrypt gMSA credential material.

        Same PEK-based decryption as user accounts, but gMSAs typically
        only have NT hashes and Kerberos keys (no LM hash, no password
        history).

        Args:
            obj: dissect Object instance.
            ctx: DecoderContext with pek_list.
            result: Output dict to populate.

        """
        creds: dict[str, Any] = {}

        # Extract RID from objectSid
        sid_str = result.get("objectSid", "")
        rid = self._extract_rid_from_sid(sid_str) if sid_str else None

        # --- NT hash ---
        nt_encrypted = self._get_attr(obj, "unicodePwd", raw=True)
        if nt_encrypted is not None and isinstance(nt_encrypted, bytes) and rid is not None and ctx.pek_list is not None:
            nt_hash = decrypt_nt_hash(nt_encrypted, ctx.pek_list, rid)
            creds["ntHash"] = nt_hash.hex() if nt_hash else None
        else:
            creds["ntHash"] = None

        # --- Supplemental credentials (dissect already decodes the PEK blob) ---
        supp = self._get_attr(obj, "supplementalCredentials")
        if isinstance(supp, list) and supp:
            supp = supp[0]
        if isinstance(supp, dict):
            merge_supplemental(supp, creds)

        result["credentials"] = creds if any(v for v in creds.values()) else None
