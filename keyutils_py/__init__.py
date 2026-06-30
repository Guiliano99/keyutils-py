# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""keyutils-py: PQ + hybrid key library.

Public top-level surface (most callers stop here)::

    from keyutils_py import (
        generate_key,  # keyutils
        sign_data,
        verify_signature,  # compute
        sign_with_alg_id,  # compute
        verify_signature_with_alg_id,  # compute
        validate_sig_alg_id,  # keyutils
        save_key,  # keyutils
        load_private_key_from_file,  # keyutils
        load_public_key_from_file,  # keyutils
        compute_encaps,
        compute_decaps,  # compute
        compute_ecdh,  # compute
        get_rsa_oaep_padding,  # compute
        encrypt_data_with_public_key_alg_id,  # compute
        decrypt_data_with_public_key_alg_id,  # compute
        get_key_name,  # keyutils
        estimate_key_security_strength,  # security
        manipulate_sig_based_on_key,  # keyutils
        prepare_spki,  # keyutils
    )

Submodules (when you need more):

* ``keyutils_py.compute`` — sign / verify / RSA-PSS / encaps / decaps / ECDH.
* ``keyutils_py.keyutils`` — generate, save/load, SPKI, alg-id builders, manipulation.
* ``keyutils_py.security`` — security-strength estimation.
* ``keyutils_py.jwt`` — JWK serialization (``key_to_jwk`` / ``key_from_jwk``).
* ``keyutils_py.asn1utils`` — DER encode/decode and a ``BitString`` builder
* ``keyutils_py.oids`` — OID maps + curve registry + sig parameter catalog.
* ``keyutils_py.enums`` — :class:`KeySaveType`, :class:`SigAlgParametersSpec`.
* ``keyutils_py.data_objects`` — pyasn1 ``CHOICE`` structures + SHAKE wrappers.
* ``keyutils_py.types`` — type aliases (``PrivateKey``, ``PublicKey``, …).
* ``keyutils_py.utils`` — internal helpers (PEM, OQS gating, predicates).
* ``keyutils_py.exceptions`` — package-specific error hierarchy.
* ``keyutils_py.factories``, ``.keys``, ``.fips``, ``.data`` — internals.

XMSS / XMSSMT / Falcon / McEliece / SNTRUP761 / FrodoKEM use liboqs; install
the ``pq`` extra. Without it, those entry points raise
:class:`MissingOQSDependencyError`. HSS / LMS work without liboqs via
``pyhsslms``.
"""

from keyutils_py.compute import (
    compute_decaps,
    compute_ecdh,
    compute_encaps,
    decrypt_data_with_public_key_alg_id,
    encrypt_data_with_public_key_alg_id,
    get_rsa_oaep_padding,
    sign_data,
    sign_with_alg_id,
    verify_signature,
    verify_signature_with_alg_id,
)
from keyutils_py.exceptions import MissingOQSDependencyError
from keyutils_py.keyutils import (
    generate_key,
    get_key_name,
    load_private_key_from_file,
    load_public_key_from_file,
    manipulate_sig_based_on_key,
    prepare_spki,
    save_key,
    validate_sig_alg_id,
)
from keyutils_py.jwt import jwk_thumbprint, key_from_jwk, key_to_jwk
from keyutils_py.security import estimate_key_security_strength

__all__ = [
    # Key lifecycle
    "generate_key",
    "save_key",
    "load_private_key_from_file",
    "load_public_key_from_file",
    # Signatures
    "sign_data",
    "verify_signature",
    "sign_with_alg_id",
    "verify_signature_with_alg_id",
    "validate_sig_alg_id",
    # KEMs and ECDH
    "compute_encaps",
    "compute_decaps",
    "compute_ecdh",
    # RSA key transport
    "get_rsa_oaep_padding",
    "encrypt_data_with_public_key_alg_id",
    "decrypt_data_with_public_key_alg_id",
    # SPKI
    "prepare_spki",
    # Inspection
    "get_key_name",
    "estimate_key_security_strength",
    # JWK serialization
    "key_to_jwk",
    "key_from_jwk",
    "jwk_thumbprint",
    # Negative tests
    "manipulate_sig_based_on_key",
    # Exceptions
    "MissingOQSDependencyError",
]
