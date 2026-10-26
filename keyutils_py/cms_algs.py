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

from typing import Dict, NamedTuple, Tuple

from keyutils_py.oids import PQ_KEM_OID_2_NAME, PQ_SIG_OID_2_NAME


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


def is_sig_alg_allowed(name: str, profile: str = "all_supported_signature_algorithms") -> bool:
    """Return True if the signature algorithm name is allowed by a CMS profile."""
    mapping = CMS_SIG_ALG_MAPPING.get(profile)
    return mapping is not None and name in mapping.allowed_algs


def is_kem_alg_allowed(name: str, profile: str = "all_supported_kem_algorithms") -> bool:
    """Return True if the KEM algorithm name is allowed by a CMS profile."""
    mapping = CMS_KEM_ALG_MAPPING.get(profile)
    return mapping is not None and name in mapping.allowed_algs
