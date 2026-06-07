"""Decoder for user and computer objectClasses.

Handles extraction of identity attributes, timestamps, group membership
(via backlinks), delegation settings, LAPS attributes, and credential
material (NT/LM hashes, Kerberos keys, supplementalCredentials).

The UserDecoder covers both ``user`` and ``computer`` objectClasses
because computers in AD are a subclass of user and share nearly all
attributes.  Computer-specific fields (dNSHostName, operatingSystem,
LAPS, delegation) are conditionally included based on the objectClass.

Import rules: decoders import from crypto/, models/, constants ONLY.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

from typing_extensions import override

from ntdswolf.constants import EMPTY_LM_HASH, EMPTY_NT_HASH
from ntdswolf.crypto.hashes import decrypt_hash_history, decrypt_lm_hash, decrypt_nt_hash
from ntdswolf.crypto.keycredential import extract_key_credentials
from ntdswolf.crypto.laps import extract_laps_v1, extract_laps_v2, parse_laps_cleartext
from ntdswolf.decoders._supplemental import merge_supplemental
from ntdswolf.decoders.base import BaseDecoder, DecoderContext, decode_filetime
from ntdswolf.models.flags import SupportedEncryptionTypes, UserAccountControl

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Object as DissectObject

    from ntdswolf.crypto.pek import PekDecryptor

logger = logging.getLogger(__name__)


class UserDecoder(BaseDecoder):
    """Decoder for ``user`` and ``computer`` objectClasses.

    Extracts identity attributes, timestamps, group membership, and
    credentials.  For computer objects, also extracts dNSHostName,
    operatingSystem, LAPS, and delegation attributes.

    Credential decryption requires a valid PEK list in the context and
    a resolvable objectSid (to derive the RID for the DES layer).
    """

    @override
    def _decode_specific(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract user/computer-specific attributes.

        Per [MS-ADA3] and [MS-ADA1] for attribute definitions.
        """
        # --- Identity ---
        result["sAMAccountName"] = self._get_attr(obj, "sAMAccountName")
        result["userPrincipalName"] = self._get_attr(obj, "userPrincipalName")
        result["displayName"] = self._get_attr(obj, "displayName")

        # --- Account control flags ---
        uac_raw = self._get_attr(obj, "userAccountControl")
        result["userAccountControl"] = self._decode_flags_field(uac_raw, UserAccountControl)

        sam_type = self._get_attr(obj, "sAMAccountType")
        if sam_type is not None:
            result["sAMAccountType"] = int(sam_type) if not isinstance(sam_type, int) else sam_type

        result["adminCount"] = self._get_attr(obj, "adminCount")

        # --- Timestamps ---
        # pwdLastSet, lastLogonTimestamp, lastLogon are FILETIME integers.
        # dissect may pre-decode them to datetime objects.
        result["pwdLastSet"] = _format_ts(self._get_attr(obj, "pwdLastSet"))
        result["lastLogonTimestamp"] = _format_ts(self._get_attr(obj, "lastLogonTimestamp"))
        result["lastLogon"] = _format_ts(self._get_attr(obj, "lastLogon"))

        # accountExpires uses special sentinel values for "never".
        # Per [MS-ADTS] section 3.1.1.5.5.2.
        account_expires = self._get_attr(obj, "accountExpires")
        result["accountExpires"] = self._decode_filetime(account_expires)

        result["badPasswordTime"] = _format_ts(self._get_attr(obj, "badPasswordTime"))
        result["badPwdCount"] = self._get_attr(obj, "badPwdCount")
        result["lockoutTime"] = _format_ts(self._get_attr(obj, "lockoutTime"))

        # --- Descriptive ---
        result["description"] = self._get_attr(obj, "description")
        result["mail"] = self._get_attr(obj, "mail")
        result["title"] = self._get_attr(obj, "title")
        result["department"] = self._get_attr(obj, "department")

        # --- Group membership (memberOf backlinks, via dissect) ---
        if ctx.include_links:
            result["memberOf"] = self._resolve_links(obj, "memberOf", forward=False)
        else:
            result["memberOf"] = []

        # --- SID history ---
        self._decode_sid_history(obj, result)

        # --- Kerberos encryption types ---
        enc_types = self._get_attr(obj, "msDS-SupportedEncryptionTypes")
        result["msDS-SupportedEncryptionTypes"] = self._decode_flags_field(enc_types, SupportedEncryptionTypes)

        # --- Service principal names ---
        spns = self._get_attr(obj, "servicePrincipalName")
        if spns:
            result["servicePrincipalName"] = spns if isinstance(spns, list) else [str(spns)]

        # --- Resource-based constrained delegation (binary SD -> SDDL) ---
        # msDS-AllowedToActOnBehalfOfOtherIdentity holds a security descriptor whose
        # DACL lists the principals allowed to impersonate to this account.
        rbcd_sddl = self._sd_bytes_to_sddl(self._get_attr(obj, "msDS-AllowedToActOnBehalfOfOtherIdentity", raw=True))
        if rbcd_sddl is not None:
            result["msDS-AllowedToActOnBehalfOfOtherIdentity"] = rbcd_sddl

        # --- Key credentials (msDS-KeyCredentialLink; WHfB / shadow credentials) ---
        key_creds = extract_key_credentials(obj)
        if key_creds:
            result["msDS-KeyCredentialLink"] = key_creds

        # --- Computer-specific attributes ---
        object_class = result.get("_object_class", "")
        is_computer = object_class == "computer"

        if is_computer:
            self._decode_computer_attrs(obj, ctx, result)

        # --- Credential decryption ---
        if ctx.include_credentials and ctx.pek_list is not None:
            self._decode_credentials(obj, ctx.pek_list, result)

    def _decode_sid_history(self, obj: DissectObject, result: dict[str, Any]) -> None:
        """Surface sIDHistory; dissect decodes each value to a SID string."""
        sid_history = self._get_attr(obj, "sIDHistory")
        if sid_history:
            values = sid_history if isinstance(sid_history, list) else [sid_history]
            result["sIDHistory"] = [str(s) for s in values]

    def _decode_computer_attrs(self, obj: DissectObject, ctx: DecoderContext, result: dict[str, Any]) -> None:
        """Extract computer-specific attributes (dNSHostName, OS, LAPS, delegation)."""
        result["dNSHostName"] = self._get_attr(obj, "dNSHostName")
        result["operatingSystem"] = self._get_attr(obj, "operatingSystem")
        result["operatingSystemVersion"] = self._get_attr(obj, "operatingSystemVersion")

        # Delegation: msDS-AllowedToDelegateTo is a multi-valued string
        # listing SPNs the computer can delegate to.
        # Per [MS-ADA2] section 2.176.
        allowed = self._get_attr(obj, "msDS-AllowedToDelegateTo")
        if allowed:
            result["msDS-AllowedToDelegateTo"] = allowed if isinstance(allowed, list) else [str(allowed)]

        # LAPS v1: ms-Mcs-AdmPwd (plaintext UTF-16LE)
        laps_v1 = self._get_attr(obj, "ms-Mcs-AdmPwd", raw=True)
        if laps_v1 is not None:
            raw_v1 = laps_v1 if isinstance(laps_v1, bytes) else str(laps_v1).encode("utf-16-le")
            result["ms-Mcs-AdmPwd"] = extract_laps_v1(raw_v1)
            result["ms-Mcs-AdmPwdExpirationTime"] = self._decode_filetime(self._get_attr(obj, "ms-Mcs-AdmPwdExpirationTime"))

        # LAPS v2 cleartext: msLAPS-Password JSON envelope {n: account, t: time, p: password}
        laps_cleartext = self._get_attr(obj, "msLAPS-Password")
        if laps_cleartext is not None:
            result["msLAPS-Password"] = parse_laps_cleartext(laps_cleartext) or str(laps_cleartext)

        # LAPS v2 encrypted: msLAPS-EncryptedPassword (CMS + GKDI). Decrypt offline
        # with the domain's KDS root keys when available; otherwise surface the raw blob.
        laps_v2_enc = self._get_attr(obj, "msLAPS-EncryptedPassword", raw=True)
        if isinstance(laps_v2_enc, bytes):
            decrypted = extract_laps_v2(laps_v2_enc, ctx.kds_cache) if ctx.kds_cache is not None else None
            result["msLAPS-EncryptedPassword"] = decrypted if decrypted is not None else laps_v2_enc.hex()
        elif laps_v2_enc is not None:
            result["msLAPS-EncryptedPassword"] = str(laps_v2_enc)

        laps_v2_exp = self._get_attr(obj, "msLAPS-PasswordExpirationTime")
        if laps_v2_exp is not None:
            result["msLAPS-PasswordExpirationTime"] = self._decode_filetime(laps_v2_exp)

    def _decode_credentials(self, obj: DissectObject, pek_list: PekDecryptor, result: dict[str, Any]) -> None:
        """Orchestrate hash and supplemental credential decryption.

        Decrypts unicodePwd (NT hash), dBCSPwd (LM hash), hash histories,
        and supplementalCredentials (Kerberos keys, WDigest, cleartext).

        The RID is extracted from the objectSid to perform the per-account
        DES un-obfuscation layer on NT/LM hashes.
        Per [MS-SAMR] section 2.2.11.1.

        Args:
            obj: dissect Object instance.
            pek_list: Decrypted PEKList for PEK-layer removal.
            result: Output dict to populate with credential fields.

        """
        creds: dict[str, Any] = {}

        # Determine the RID for the DES layer.  The RID is the last component
        # of the objectSid (e.g., S-1-5-21-...-1001 -> RID=1001).
        sid_str = result.get("objectSid", "")
        rid = self._extract_rid_from_sid(sid_str) if sid_str else None

        # --- Current NT/LM hashes ---
        creds["ntHash"] = _current_nt_hash(self._get_attr(obj, "unicodePwd", raw=True), pek_list, rid)
        creds["lmHash"] = _current_lm_hash(self._get_attr(obj, "dBCSPwd", raw=True), pek_list, rid)

        # --- Password history (ntPwdHistory / ATTk589918, lmPwdHistory / ATTk589984) ---
        # dissect returns these single-valued blobs wrapped in a one-element list.
        # Index 0 of the decrypted history is the *current* password (already
        # emitted above as ntHash/lmHash), so it is dropped to leave only previous
        # passwords -- matching secretsdump's ``NTHistory[1:]`` slice. Empty-LM
        # entries are deliberately kept (not filtered): the pwdump writer pairs
        # NT/LM history by count, so the LM list length must mirror secretsdump's.
        nt_hist_blob = _history_blob(self._get_attr(obj, "ntPwdHistory", raw=True))
        if nt_hist_blob is not None and rid is not None:
            creds["ntHistory"] = [h.hex() for h in decrypt_hash_history(nt_hist_blob, pek_list, rid)[1:]]
        else:
            creds["ntHistory"] = []

        lm_hist_blob = _history_blob(self._get_attr(obj, "lmPwdHistory", raw=True))
        if lm_hist_blob is not None and rid is not None:
            creds["lmHistory"] = [h.hex() for h in decrypt_hash_history(lm_hist_blob, pek_list, rid)[1:]]
        else:
            creds["lmHistory"] = []

        # --- Supplemental credentials (Kerberos keys, WDigest, cleartext) ---
        # dissect already decodes supplementalCredentials into a structured dict
        # (wrapped in a single-element list); we surface it rather than
        # re-parsing the raw blob.
        supp = self._get_attr(obj, "supplementalCredentials")
        if isinstance(supp, list) and supp:
            supp = supp[0]
        if isinstance(supp, dict):
            merge_supplemental(supp, creds)

        result["credentials"] = creds if any(v for v in creds.values()) else None


def _history_blob(raw: object) -> bytes | None:
    """Return the encrypted history blob from dissect's raw attribute value.

    dissect surfaces the single-valued ``ntPwdHistory`` / ``lmPwdHistory``
    attributes as a one-element list of bytes (its multi-valued representation);
    other paths may hand back bytes directly. Returns the first usable blob, or
    None when the attribute is absent or empty. Without this coercion the history
    is silently dropped, because a list is not ``bytes``.
    """
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw) or None
    if isinstance(raw, list):
        for element in raw:
            if isinstance(element, (bytes, bytearray)) and element:
                return bytes(element)
    return None


def _current_nt_hash(encrypted: object, pek_list: PekDecryptor, rid: int | None) -> str | None:
    """Return the hex NT hash, the empty-password sentinel, or None.

    An absent unicodePwd means the account has no password set, so we emit the
    empty NT hash (MD4 of "") for it -- matching impacket/secretsdump output.
    """
    if rid is None:
        return None
    if isinstance(encrypted, bytes) and encrypted:
        nt_hash = decrypt_nt_hash(encrypted, pek_list, rid)
        return nt_hash.hex() if nt_hash else None
    return EMPTY_NT_HASH


def _current_lm_hash(encrypted: object, pek_list: PekDecryptor, rid: int | None) -> str | None:
    """Return the hex LM hash, or None.

    The empty LM hash is suppressed here (it means "no LM hash stored"); output
    writers substitute the empty-LM sentinel where the format requires it.
    """
    if rid is None or not (isinstance(encrypted, bytes) and encrypted):
        return None
    lm_hash = decrypt_lm_hash(encrypted, pek_list, rid)
    if lm_hash is None:
        return None
    lm_hex = lm_hash.hex()
    return lm_hex if lm_hex != EMPTY_LM_HASH else None


def _format_ts(value: object) -> str | None:
    """Format a timestamp value to ISO 8601 or None.

    Handles both pre-decoded datetime objects from dissect and raw
    FILETIME integers.

    Args:
        value: datetime, int (FILETIME), or None.

    Returns:
        ISO 8601 string or None.

    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    # dissect often returns datetimes directly
    if isinstance(value, datetime):
        return value.isoformat()
    # Raw FILETIME integer -- delegate to the static method
    return decode_filetime(value)
