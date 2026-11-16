# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""CMS/CMP algorithm support matrix scaffolding.

This module keeps the ``must_support`` and ``allowed_algs`` information for
signature and KEM algorithms in two separate mappings.

The keys in each mapping are local profile / grouping names rather than single
algorithm names.  Profile-specific "must support" lists are deliberately set to
the full allowed set unless a stricter policy is intended; refine the tuples
below once a particular CMS/CMP profile (RFC 9629, RFC 9481, FrodoKEM CMS, ...)
is targeted.
"""

from typing import Dict, NamedTuple, Optional, Tuple

from pyasn1.type import univ

from keyutils_py.oids import PQ_KEM_OID_2_NAME, PQ_SIG_OID_2_NAME, SIG_ALG_OID_2_INFO
from keyutils_py.security import HASH_ALG_TO_STRENGTH


class CmsAlgorithmMapping(NamedTuple):
    """Algorithm split required by a CMS-style algorithm profile.

    Fields are explicit in the request:
    - must_support: algorithm names that are mandatory.
    - allowed_algs: algorithm names that are otherwise permitted.
    """

    must_support: Tuple[str, ...]
    allowed_algs: Tuple[str, ...]


# OID-to-name maps are bijections; deduplicate defensively.
SIG_ALGORITHM_NAMES = tuple(sorted(set(PQ_SIG_OID_2_NAME.values())))
KEM_ALGORITHM_NAMES = tuple(sorted(set(PQ_KEM_OID_2_NAME.values())))


CMS_SIG_ALG_MAPPING: Dict[str, CmsAlgorithmMapping] = {
    # Broad reference mapping derived from the bundled, supported signature
    # algorithm OIDs.
    "all_supported_signature_algorithms": CmsAlgorithmMapping(
        must_support=SIG_ALGORITHM_NAMES,
        allowed_algs=SIG_ALGORITHM_NAMES,
    ),
}

CMS_KEM_ALG_MAPPING: Dict[str, CmsAlgorithmMapping] = {
    # Broad reference mapping derived from the bundled, supported KEM
    # algorithm OIDs.
    "all_supported_kem_algorithms": CmsAlgorithmMapping(
        must_support=KEM_ALGORITHM_NAMES,
        allowed_algs=KEM_ALGORITHM_NAMES,
    ),
}


def is_cms_sig_hash_alg_allowed(
    name: str,
    profile: str = "all_supported_signature_algorithms",
    ensure_lw: bool = False,
) -> bool:
    """Return True if the signature algorithm name is allowed by a CMS profile.

    ``ensure_lw`` requests a lightweight profile: only the algorithms listed in
    ``must_support`` (rather than the full ``allowed_algs`` set) are accepted.
    """
    mapping = CMS_SIG_ALG_MAPPING.get(profile)
    if mapping is None:
        return False
    return name in (mapping.must_support if ensure_lw else mapping.allowed_algs)


def is_cms_kem_alg_allowed(name: str, profile: str = "all_supported_kem_algorithms") -> bool:
    """Return True if the KEM algorithm name is allowed by a CMS profile."""
    mapping = CMS_KEM_ALG_MAPPING.get(profile)
    return mapping is not None and name in mapping.allowed_algs


# The identifiers of the pure mode of ML-DSA (RFC 9882 Section 2) and SLH-DSA (RFC 9814 Section 3) by the name of the
# key. A CMS SignerInfo carries only these; the identifiers of the pre-hash variants are in the tables of
# ``keyutils_py.oids``.
PURE_PQ_SIG_NAME_2_OID: Dict[str, univ.ObjectIdentifier] = {
    row.key_name: row.oid
    for row in SIG_ALG_OID_2_INFO.values()
    if row.family in ("ml-dsa", "slh-dsa") and not row.pre_hash and row.key_name
}

# The digest that the row of an EdDSA, ML-DSA or SLH-DSA key names for a SignerInfo, by the name of the key.
_DEFAULT_DIGEST: Dict[str, str] = {
    row.key_name: row.cms_digest
    for row in SIG_ALG_OID_2_INFO.values()
    if row.family in ("eddsa", "ml-dsa", "slh-dsa") and not row.pre_hash and row.key_name and row.cms_digest
}


def _security_bits(key_name: str) -> int:
    """Return the security level in bits (128, 192 or 256) of the name of an ML-DSA or SLH-DSA key."""
    if key_name.startswith("ml-dsa-"):
        return {"44": 128, "65": 192, "87": 256}[key_name[-2:]]
    return int(key_name.split("-")[-1][:-1])  # slh-dsa-sha2-128f -> "128f" -> 128


def cms_digest_algs(key_name: str, signed_attrs: bool = True) -> Optional[Tuple[str, ...]]:
    """Return the digests that a SignerInfo of a key may name in ``digestAlgorithm``, the default first.

    ``None`` means that the key leaves the digest to the signer (RSA, ECDSA, ...). The other cases:

    * EdDSA: the one digest of RFC 8419 Section 3.1, SHA-512 for Ed25519 and SHAKE256 for Ed448.
    * ML-DSA and SLH-DSA with signed attributes: the digests of at least twice the bits of the security level, which
      is the strength of the hash being at least that level (Table 1 of RFC 9882 for ML-DSA, Section 4 of RFC 9814
      for SLH-DSA). That includes the SHA-3 digests.
    * ML-DSA without signed attributes: SHA-512 (RFC 9882 Section 3.3).
    * SLH-DSA without signed attributes: the hash of the tree or SHA-256 (RFC 9814 Section 4).

    :param key_name: The ``get_key_name`` value of the key, e.g. ``ml-dsa-65``.
    :param signed_attrs: Whether the SignerInfo has signed attributes.
    """
    default = _DEFAULT_DIGEST.get(key_name)
    if default is None:
        return None
    if key_name not in PURE_PQ_SIG_NAME_2_OID:
        return (default,)
    if not signed_attrs:
        return ("sha512",) if key_name.startswith("ml-dsa") else tuple(dict.fromkeys((default, "sha256")))
    bits = _security_bits(key_name)
    return (default, *(name for name, strength in HASH_ALG_TO_STRENGTH.items() if strength >= bits and name != default))
