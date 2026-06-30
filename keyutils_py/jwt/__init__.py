# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""JSON Web Key (JWK) serialisation for keyutils-py keys.

Serialise and deserialise traditional and post-quantum keys to and from the JWK
format defined by JOSE. Supported families:

* ``EC``  — P-256 / P-384 / P-521 / secp256k1 (RFC 7518, RFC 8812).
* ``OKP`` — Ed25519 / Ed448 / X25519 / X448 (RFC 8037).
* ``RSA`` — RFC 7518 §6.3.
* ``AKP`` — ML-DSA / ML-KEM / SLH-DSA (draft-ietf-cose-dilithium,
  draft-ietf-jose-pqc-kem, draft-ietf-cose-sphincs-plus).
* ``AKP`` composite signatures — draft-ietf-jose-pq-composite-sigs.

Example::

    from keyutils_py import generate_key
    from keyutils_py.jwt import key_to_jwk, key_from_jwk

    key = generate_key("ml-dsa-44")
    jwk = key_to_jwk(key)  # private JWK (kty="AKP")
    restored = key_from_jwk(jwk)  # MLDSAPrivateKey
"""

from keyutils_py.jwt.jw_keys import JWK, dumps, key_from_jwk, key_to_jwk, loads
from keyutils_py.jwt.jwt_utils import b64u_decode, b64u_encode, jwk_thumbprint

__all__ = [
    "JWK",
    "key_to_jwk",
    "key_from_jwk",
    "dumps",
    "loads",
    "jwk_thumbprint",
    "b64u_encode",
    "b64u_decode",
]
