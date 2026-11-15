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
        prepare_sig_alg_id,  # keyutils
        prepare_hash_alg_id,  # keyutils
        get_sig_alg_info,  # oids: the row of a signature OID or AlgorithmIdentifier
        list_algorithms,  # algorithms: the rows of one kind of algorithm
        make_alg_id,  # mechanisms: the AlgorithmIdentifier of a KDF, MAC, key wrap or content algorithm
        kdf_derive,  # mechanisms
        compute_mac,
        verify_mac,  # mechanisms
        wrap_cek,
        unwrap_cek,  # mechanisms
        encrypt_content,
        decrypt_content,  # mechanisms
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
        manipulate_pq_stateful_signature_bytes,  # keyutils
        modify_pq_stateful_sig_private_key,  # keyutils
        load_private_key_from_one_asym_key,  # keyutils
        load_public_key_from_spki,  # keyutils
        check_consistency_sig_alg_id_and_key,  # keyutils
        prepare_spki,  # keyutils
    )

Submodules (when you need more):

* ``keyutils_py.compute`` — sign / verify / RSA-PSS / encaps / decaps / ECDH.
* ``keyutils_py.mechanisms`` — the operations that an ``AlgorithmIdentifier`` selects: :func:`make_alg_id`,
  :func:`kdf_derive`, :func:`compute_mac`, :func:`verify_mac`, :func:`wrap_cek` and :func:`unwrap_cek`,
  :func:`encrypt_content` and :func:`decrypt_content`.
* ``keyutils_py.primitives`` — the keyless functions below them, by the name of the hash (importable, not public API).
* ``keyutils_py.keyutils`` — generate, save/load, SPKI, alg-id builders, manipulation.
* ``keyutils_py.security`` — security-strength estimation.
* ``keyutils_py.asn1utils`` — DER encode/decode and a ``BitString`` builder
* ``keyutils_py.oids`` — OID maps + curve registry + the signature algorithm table.
* ``keyutils_py.algorithms`` — :func:`list_algorithms`, the algorithms by kind.
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

from keyutils_py.algorithms import AlgInfo, list_algorithms
from keyutils_py.asn1utils import encode_to_der, try_decode_pyasn1
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
from keyutils_py.exceptions import (
    BadAlg,
    BadAlgParams,
    BadAsn1Data,
    BadSigAlgID,
    BadSigAlgIDParams,
    IntegrityError,
    KeyUtilsError,
    MissingOQSDependencyError,
)
from keyutils_py.keyutils import (
    check_consistency_sig_alg_id_and_key,
    generate_key,
    get_key_name,
    load_private_key_from_file,
    load_private_key_from_one_asym_key,
    load_public_key_from_file,
    load_public_key_from_spki,
    manipulate_pq_stateful_signature_bytes,
    manipulate_sig_based_on_key,
    modify_pq_stateful_sig_private_key,
    prepare_hash_alg_id,
    prepare_sig_alg_id,
    prepare_spki,
    save_key,
    validate_sig_alg_id,
)
from keyutils_py.mechanisms import (
    AlgKind,
    Encrypted,
    compute_mac,
    decrypt_content,
    encrypt_content,
    kdf_derive,
    mac_key_length,
    make_alg_id,
    unwrap_cek,
    verify_mac,
    wrap_cek,
    wrap_key_length,
)
from keyutils_py.oids import (
    RSA_OID_2_NAME,
    SIG_ALG_OID_2_INFO,
    SigAlgInfo,
    get_hash_from_oid,
    get_sig_alg_info,
    sha_alg_name_to_oid,
)
from keyutils_py.security import estimate_key_security_strength
from keyutils_py.types import DSAPublicKey, PublicKey, SignKey, TradVerifyKey, VerifyKey

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
    "prepare_sig_alg_id",
    # Signature algorithm table
    "SigAlgInfo",
    "SIG_ALG_OID_2_INFO",
    "get_sig_alg_info",
    "list_algorithms",
    # Mechanisms by AlgorithmIdentifier
    "AlgInfo",
    "AlgKind",
    "Encrypted",
    "make_alg_id",
    "kdf_derive",
    "compute_mac",
    "verify_mac",
    "mac_key_length",
    "wrap_cek",
    "unwrap_cek",
    "wrap_key_length",
    "encrypt_content",
    "decrypt_content",
    # KEMs and ECDH
    "compute_encaps",
    "compute_decaps",
    "compute_ecdh",
    # RSA key transport
    "get_rsa_oaep_padding",
    "encrypt_data_with_public_key_alg_id",
    "decrypt_data_with_public_key_alg_id",
    # AlgorithmIdentifier builders and hashes
    "prepare_hash_alg_id",
    "get_hash_from_oid",
    "sha_alg_name_to_oid",
    "RSA_OID_2_NAME",
    # ASN.1 helpers
    "encode_to_der",
    "try_decode_pyasn1",
    # SPKI
    "prepare_spki",
    # Inspection
    "get_key_name",
    "estimate_key_security_strength",
    # Negative tests
    "manipulate_sig_based_on_key",
    "manipulate_pq_stateful_signature_bytes",
    "modify_pq_stateful_sig_private_key",
    "load_private_key_from_one_asym_key",
    "load_public_key_from_spki",
    "check_consistency_sig_alg_id_and_key",
    # Key types
    "PublicKey",
    "SignKey",
    "VerifyKey",
    "TradVerifyKey",
    "DSAPublicKey",
    # Exceptions
    "KeyUtilsError",
    "BadAlg",
    "BadAlgParams",
    "BadAsn1Data",
    "BadSigAlgID",
    "BadSigAlgIDParams",
    "IntegrityError",
    "MissingOQSDependencyError",
]
