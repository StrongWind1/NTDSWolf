# SPDX-License-Identifier: Apache-2.0
"""Unit tests for crypto/kerberos.py -- RFC 3961/3962 AES string-to-key.

The expected keys are the published [RFC 3962] Appendix B sample test vectors, so
these prove the implementation independently of any external Kerberos library.
"""

from __future__ import annotations

from ntdswolf.crypto.kerberos import AES128_KEY_SIZE, AES256_KEY_SIZE, aes_string_to_key

# [RFC 3962] Appendix B uses this realm+principal salt for the "password" cases.
_ATHENA_SALT = b"ATHENA.MIT.EDUraeburn"


def test_rfc3962_iteration_count_1():
    assert aes_string_to_key("password", _ATHENA_SALT, AES128_KEY_SIZE, 1).hex() == "42263c6e89f4fc28b8df68ee09799f15"
    assert aes_string_to_key("password", _ATHENA_SALT, AES256_KEY_SIZE, 1).hex() == "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"


def test_rfc3962_iteration_count_1200():
    assert aes_string_to_key("password", _ATHENA_SALT, AES128_KEY_SIZE, 1200).hex() == "4c01cd46d632d01e6dbe230a01ed642a"
    assert aes_string_to_key("password", _ATHENA_SALT, AES256_KEY_SIZE, 1200).hex() == "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"


def test_default_iteration_count_is_4096():
    # Active Directory (and the trust-key path) relies on the RFC 3962 default of 4096.
    assert aes_string_to_key("password", _ATHENA_SALT, AES256_KEY_SIZE) == aes_string_to_key("password", _ATHENA_SALT, AES256_KEY_SIZE, 4096)


def test_key_sizes():
    assert len(aes_string_to_key("pw", b"salt", AES128_KEY_SIZE)) == 16
    assert len(aes_string_to_key("pw", b"salt", AES256_KEY_SIZE)) == 32


def test_non_ascii_password_uses_utf8():
    # Trust passwords carry arbitrary UTF-16 code points; RFC 3961 folds in their
    # UTF-8 encoding. Fixed oracle (cross-checked against impacket for this input).
    assert aes_string_to_key("Paßwörd-éèê", b"EXAMPLE.LABkrbtgtPARTNER", AES256_KEY_SIZE).hex() == "c4174d4cd71ae7b04eea221becfe98120dbbf6c0e1b6f635a42d16962da435f6"
    assert aes_string_to_key("Paßwörd-éèê", b"EXAMPLE.LABkrbtgtPARTNER", AES128_KEY_SIZE).hex() == "93b7966a5d48691cd9d30518871068eb"
