# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""OID maps for PQ keys (signatures + KEM + stateful-hash).

Trimmed copy of ``cmp-test-suite/resources/oidutils.py`` and
``cmp-test-suite/pq_logic/tmp_oids.py``. Only the maps used by
:mod:`keyutils_py.keys` and the dispatch layer are kept; the broader
catalogue (hybrid, composite, chempat, traditional) lives in the source repo.
"""

from typing import Dict, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5990, rfc8017, rfc9480, rfc9481, rfc9688, rfc9708

from keyutils_py.enums import SigAlgParametersSpec

# ---------------------------------------------------------------------------
# Base OID prefixes
# ---------------------------------------------------------------------------

nist_algorithms_oid = rfc5990.nistAlgorithm
sig_algorithms_oid = nist_algorithms_oid + (3,)
kems_oid = nist_algorithms_oid + (4,)

# Test-suite root used by Falcon / FrodoKEM / McEliece / SNTRUP761
id_test_suite_oid = f"{rfc9480.id_it}.9996.9999"
id_kem_test_suite = f"{id_test_suite_oid}.2"


# ---------------------------------------------------------------------------
# ML-KEM
# ---------------------------------------------------------------------------

id_ml_kem_512 = kems_oid + (1,)
id_ml_kem_768 = kems_oid + (2,)
id_ml_kem_1024 = kems_oid + (3,)

ML_KEM_NAME_2_OID = {
    "ml-kem-512": id_ml_kem_512,
    "ml-kem-768": id_ml_kem_768,
    "ml-kem-1024": id_ml_kem_1024,
}
ML_KEM_OID_2_NAME = {y: x for x, y in ML_KEM_NAME_2_OID.items()}


# ---------------------------------------------------------------------------
# ML-DSA
# ---------------------------------------------------------------------------

id_ml_dsa_44_oid = sig_algorithms_oid + (17,)
id_ml_dsa_65_oid = sig_algorithms_oid + (18,)
id_ml_dsa_87_oid = sig_algorithms_oid + (19,)
id_ml_dsa_44_with_sha512 = sig_algorithms_oid + (32,)
id_ml_dsa_65_with_sha512 = sig_algorithms_oid + (33,)
id_ml_dsa_87_with_sha512 = sig_algorithms_oid + (34,)

ML_DSA_OID_2_NAME = {
    id_ml_dsa_44_oid: "ml-dsa-44",
    id_ml_dsa_65_oid: "ml-dsa-65",
    id_ml_dsa_87_oid: "ml-dsa-87",
}
ML_DSA_PRE_HASH_OID_2_NAME = {
    id_ml_dsa_44_with_sha512: "ml-dsa-44-sha512",
    id_ml_dsa_65_with_sha512: "ml-dsa-65-sha512",
    id_ml_dsa_87_with_sha512: "ml-dsa-87-sha512",
}
ML_DSA_OID_2_NAME.update(ML_DSA_PRE_HASH_OID_2_NAME)
ML_DSA_NAME_2_OID = {y: x for x, y in ML_DSA_OID_2_NAME.items()}


# ---------------------------------------------------------------------------
# SLH-DSA
# ---------------------------------------------------------------------------

_SIG_ALGS = "2.16.840.1.101.3.4.3"
SLH_DSA_NAME_2_OID = {
    "slh-dsa-sha2-128s": univ.ObjectIdentifier(f"{_SIG_ALGS}.20"),
    "slh-dsa-sha2-128f": univ.ObjectIdentifier(f"{_SIG_ALGS}.21"),
    "slh-dsa-sha2-192s": univ.ObjectIdentifier(f"{_SIG_ALGS}.22"),
    "slh-dsa-sha2-192f": univ.ObjectIdentifier(f"{_SIG_ALGS}.23"),
    "slh-dsa-sha2-256s": univ.ObjectIdentifier(f"{_SIG_ALGS}.24"),
    "slh-dsa-sha2-256f": univ.ObjectIdentifier(f"{_SIG_ALGS}.25"),
    "slh-dsa-shake-128s": univ.ObjectIdentifier(f"{_SIG_ALGS}.26"),
    "slh-dsa-shake-128f": univ.ObjectIdentifier(f"{_SIG_ALGS}.27"),
    "slh-dsa-shake-192s": univ.ObjectIdentifier(f"{_SIG_ALGS}.28"),
    "slh-dsa-shake-192f": univ.ObjectIdentifier(f"{_SIG_ALGS}.29"),
    "slh-dsa-shake-256s": univ.ObjectIdentifier(f"{_SIG_ALGS}.30"),
    "slh-dsa-shake-256f": univ.ObjectIdentifier(f"{_SIG_ALGS}.31"),
}

SLH_DSA_PRE_HASH_NAME_2_OID = {
    "slh-dsa-sha2-128s-sha256": sig_algorithms_oid + (35,),
    "slh-dsa-sha2-128f-sha256": sig_algorithms_oid + (36,),
    "slh-dsa-sha2-192s-sha512": sig_algorithms_oid + (37,),
    "slh-dsa-sha2-192f-sha512": sig_algorithms_oid + (38,),
    "slh-dsa-sha2-256s-sha512": sig_algorithms_oid + (39,),
    "slh-dsa-sha2-256f-sha512": sig_algorithms_oid + (40,),
    "slh-dsa-shake-128s-shake128": sig_algorithms_oid + (41,),
    "slh-dsa-shake-128f-shake128": sig_algorithms_oid + (42,),
    "slh-dsa-shake-192s-shake256": sig_algorithms_oid + (43,),
    "slh-dsa-shake-192f-shake256": sig_algorithms_oid + (44,),
    "slh-dsa-shake-256s-shake256": sig_algorithms_oid + (45,),
    "slh-dsa-shake-256f-shake256": sig_algorithms_oid + (46,),
}

SLH_DSA_HASH_MAPPING = {
    "slh-dsa-sha2-128s": "sha256",
    "slh-dsa-sha2-128f": "sha256",
    "slh-dsa-sha2-192s": "sha512",
    "slh-dsa-sha2-192f": "sha512",
    "slh-dsa-sha2-256s": "sha512",
    "slh-dsa-sha2-256f": "sha512",
    "slh-dsa-shake-128s": "shake128",
    "slh-dsa-shake-128f": "shake128",
    "slh-dsa-shake-192s": "shake256",
    "slh-dsa-shake-192f": "shake256",
    "slh-dsa-shake-256s": "shake256",
    "slh-dsa-shake-256f": "shake256",
}

SLH_DSA_PRE_HASH_OID_2_NAME = {y: x for x, y in SLH_DSA_PRE_HASH_NAME_2_OID.items()}
SLH_DSA_NAME_2_OID.update(SLH_DSA_PRE_HASH_NAME_2_OID)
SLH_DSA_OID_2_NAME = {y: x for x, y in SLH_DSA_NAME_2_OID.items()}


# ---------------------------------------------------------------------------
# Falcon (oqs-only)
# ---------------------------------------------------------------------------

id_falcon_512 = univ.ObjectIdentifier("1.3.9999.3.6")
id_falcon_1024 = univ.ObjectIdentifier("1.3.9999.3.9")
id_falcon_padded_512 = univ.ObjectIdentifier("1.3.9999.3.16")
id_falcon_padded_1024 = univ.ObjectIdentifier("1.3.9999.3.19")

FALCON_NAME_2_OID = {
    "falcon-512": id_falcon_512,
    "falcon-padded-512": id_falcon_padded_512,
    "falcon-1024": id_falcon_1024,
    "falcon-padded-1024": id_falcon_padded_1024,
}
FALCON_OID_2_NAME = {y: x for x, y in FALCON_NAME_2_OID.items()}


# ---------------------------------------------------------------------------
# SNTRUP761 / McEliece / FrodoKEM (oqs-only test-suite OIDs)
# ---------------------------------------------------------------------------

id_ntru = f"{id_kem_test_suite}.1"
id_sntrup761 = univ.ObjectIdentifier(f"{id_ntru}.1")

id_mceliece = f"{id_kem_test_suite}.2"
MCELIECE_NAME_2_OID = {
    "mceliece-348864": univ.ObjectIdentifier(f"{id_mceliece}.1"),
    "mceliece-460896": univ.ObjectIdentifier(f"{id_mceliece}.2"),
    "mceliece-6688128": univ.ObjectIdentifier(f"{id_mceliece}.3"),
    "mceliece-6960119": univ.ObjectIdentifier(f"{id_mceliece}.4"),
    "mceliece-8192128": univ.ObjectIdentifier(f"{id_mceliece}.5"),
}
MCELIECE_OID_2_NAME = {y: x for x, y in MCELIECE_NAME_2_OID.items()}

id_frodokem = f"{id_kem_test_suite}.3"
FRODOKEM_NAME_2_OID = {
    "frodokem-640-aes": univ.ObjectIdentifier(f"{id_frodokem}.1"),
    "frodokem-640-shake": univ.ObjectIdentifier(f"{id_frodokem}.2"),
    "frodokem-976-aes": univ.ObjectIdentifier(f"{id_frodokem}.3"),
    "frodokem-976-shake": univ.ObjectIdentifier(f"{id_frodokem}.4"),
    "frodokem-1344-aes": univ.ObjectIdentifier(f"{id_frodokem}.5"),
    "frodokem-1344-shake": univ.ObjectIdentifier(f"{id_frodokem}.6"),
}
FRODOKEM_OID_2_NAME = {y: x for x, y in FRODOKEM_NAME_2_OID.items()}


# ---------------------------------------------------------------------------
# Stateful-hash (HSS / XMSS / XMSSMT)
# ---------------------------------------------------------------------------

PQ_STATEFUL_HASH_SIG_NAME_2_OID = {
    "xmss": univ.ObjectIdentifier("1.3.6.1.5.5.7.6.34"),
    "xmssmt": univ.ObjectIdentifier("1.3.6.1.5.5.7.6.35"),
    "hss": rfc9708.id_alg_hss_lms_hashsig,
}
PQ_STATEFUL_HASH_SIG_OID_2_NAME = {y: x for x, y in PQ_STATEFUL_HASH_SIG_NAME_2_OID.items()}


# ---------------------------------------------------------------------------
# Aggregated PQ catalogues
# ---------------------------------------------------------------------------

PQ_KEM_NAME_2_OID = {}
PQ_KEM_NAME_2_OID.update(ML_KEM_NAME_2_OID)
PQ_KEM_NAME_2_OID.update({"sntrup761": id_sntrup761})
PQ_KEM_NAME_2_OID.update(MCELIECE_NAME_2_OID)
PQ_KEM_NAME_2_OID.update(FRODOKEM_NAME_2_OID)
PQ_KEM_OID_2_NAME = {y: x for x, y in PQ_KEM_NAME_2_OID.items()}

PQ_SIG_NAME_2_OID = {}
PQ_SIG_NAME_2_OID.update(ML_DSA_NAME_2_OID)
PQ_SIG_NAME_2_OID.update(SLH_DSA_NAME_2_OID)
PQ_SIG_NAME_2_OID.update(FALCON_NAME_2_OID)
PQ_SIG_OID_2_NAME = {y: x for x, y in PQ_SIG_NAME_2_OID.items()}

PQ_SIG_PRE_HASH_OID_2_NAME = {}
PQ_SIG_PRE_HASH_OID_2_NAME.update(ML_DSA_PRE_HASH_OID_2_NAME)
PQ_SIG_PRE_HASH_OID_2_NAME.update(SLH_DSA_PRE_HASH_OID_2_NAME)
PQ_SIG_PRE_HASH_NAME_2_OID = {y: x for x, y in PQ_SIG_PRE_HASH_OID_2_NAME.items()}

PQ_NAME_2_OID = {}
PQ_NAME_2_OID.update(PQ_SIG_NAME_2_OID)
PQ_NAME_2_OID.update(PQ_KEM_NAME_2_OID)
PQ_NAME_2_OID.update(PQ_STATEFUL_HASH_SIG_NAME_2_OID)
PQ_OID_2_NAME = {y: x for x, y in PQ_NAME_2_OID.items()}

KEM_OID_2_NAME = {y: x for x, y in PQ_KEM_NAME_2_OID.items()}


# ---------------------------------------------------------------------------
# Hash helpers (subset of resources/oid_mapping.py used by sig_keys.py)
# ---------------------------------------------------------------------------

_HASH_NAME_2_OID = {
    "sha1": univ.ObjectIdentifier("1.3.14.3.2.26"),
    "sha224": univ.ObjectIdentifier("2.16.840.1.101.3.4.2.4"),
    "sha256": univ.ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
    "sha384": univ.ObjectIdentifier("2.16.840.1.101.3.4.2.2"),
    "sha512": univ.ObjectIdentifier("2.16.840.1.101.3.4.2.3"),
    "shake128": univ.ObjectIdentifier("2.16.840.1.101.3.4.2.11"),
    "shake256": univ.ObjectIdentifier("2.16.840.1.101.3.4.2.12"),
}

_HASH_OID_2_NAME = {oid: name for name, oid in _HASH_NAME_2_OID.items()}


def sha_alg_name_to_oid(name: str) -> univ.ObjectIdentifier:
    """Return the SHA-family OID for ``name`` (e.g. ``"sha256"``)."""
    key = name.lower()
    if key not in _HASH_NAME_2_OID:
        raise ValueError(f"Unsupported hash algorithm: {name}")
    return _HASH_NAME_2_OID[key]


def compute_hash(alg_name: str, data: bytes) -> bytes:
    """Compute a digest using ``cryptography`` primitives. Mirrors source helper."""
    name = alg_name.lower()
    if name == "sha224":
        digest = hashes.Hash(hashes.SHA224())
    elif name == "sha256":
        digest = hashes.Hash(hashes.SHA256())
    elif name == "sha384":
        digest = hashes.Hash(hashes.SHA384())
    elif name == "sha512":
        digest = hashes.Hash(hashes.SHA512())
    elif name == "shake128":
        digest = hashes.Hash(hashes.SHAKE128(32))
    elif name == "shake256":
        digest = hashes.Hash(hashes.SHAKE256(64))
    else:
        raise ValueError(f"Unsupported hash algorithm: {alg_name}")
    digest.update(data)
    return digest.finalize()


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


# Populated at the bottom of this module once all hybrid OID maps are defined.
_HYBRID_OID_2_NAME: Dict[univ.ObjectIdentifier, str] = {}


def may_return_oid_to_name(oid: Union[str, univ.ObjectIdentifier]) -> str:
    """Return the registered name for ``oid`` or its dotted string form."""
    if isinstance(oid, str):
        return oid
    name = PQ_OID_2_NAME.get(oid)
    if name is not None:
        return name
    name = _HYBRID_OID_2_NAME.get(oid)
    if name is not None:
        return name
    return str(oid)


def get_hash_from_oid(oid: univ.ObjectIdentifier) -> Optional[str]:
    """Return the hash-algorithm name for ``oid``, or ``None``.

    Recognises plain SHA / SHA-3 / SHAKE OIDs, as well as the embedded
    pre-hash hint in ML-DSA / SLH-DSA pre-hash OIDs.
    """
    if oid in _HASH_OID_2_NAME:
        return _HASH_OID_2_NAME[oid]
    if oid in ML_DSA_PRE_HASH_OID_2_NAME:
        return "sha512"
    if oid in SLH_DSA_PRE_HASH_OID_2_NAME:
        name = SLH_DSA_PRE_HASH_OID_2_NAME[oid]
        return name.rsplit("-", 1)[-1]
    if oid in SLH_DSA_OID_2_NAME:
        return SLH_DSA_HASH_MAPPING.get(SLH_DSA_OID_2_NAME[oid])
    return None


# ---------------------------------------------------------------------------
# Hybrid / Composite OIDs
# (Copy of pq_logic/tmp_oids.py hybrid sections, with same OID values)
# ---------------------------------------------------------------------------

id_hybrid_kems_test_suite = f"{id_test_suite_oid}.3"
id_hybrid_sig_test_suite = f"{id_test_suite_oid}.4"
id_composite_sig_test_suite = f"{id_hybrid_sig_test_suite}.1"
id_Chempat = f"{id_hybrid_kems_test_suite}.2"
id_composite_kem_test_suite = f"{id_hybrid_kems_test_suite}.1"

# RSA-KEM SPKI OID (RFC 9690)
id_rsa_kem_spki = univ.ObjectIdentifier("1.2.840.113549.1.9.16.3")

# XWing
XWING_OID_STR = "1.3.6.1.4.1.62253.25722"

# ---------------------------------------------------------------------------
# Composite Signature OIDs (draft-ietf-lamps-pq-composite-sigs)
# ---------------------------------------------------------------------------

id_compSig_base = univ.ObjectIdentifier("1.3.6.1.5.5.7.6")

# Single source of truth: (name, arc_suffix, label, inner_hash, prehash_hash)
# inner_hash: hash used for RSA/ECDSA inner operation (None for EdDSA)
# prehash:    hash used to compute M' in the composite sig construction
_COMPOSITE_SIG_TABLE = [
    # fmt: off
    ("composite-sig-ml-dsa-44-rsa2048-pss", 37, b"COMPSIG-MLDSA44-RSA2048-PSS-SHA256", "sha256", "sha256"),
    ("composite-sig-ml-dsa-44-rsa2048", 38, b"COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", "sha256", "sha256"),
    ("composite-sig-ml-dsa-44-ed25519", 39, b"COMPSIG-MLDSA44-Ed25519-SHA512", None, "sha512"),
    ("composite-sig-ml-dsa-44-ecdsa-secp256r1", 40, b"COMPSIG-MLDSA44-ECDSA-P256-SHA256", "sha256", "sha256"),
    ("composite-sig-ml-dsa-65-rsa3072-pss", 41, b"COMPSIG-MLDSA65-RSA3072-PSS-SHA512", "sha256", "sha512"),
    ("composite-sig-ml-dsa-65-rsa3072", 42, b"COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", "sha256", "sha512"),
    ("composite-sig-ml-dsa-65-rsa4096-pss", 43, b"COMPSIG-MLDSA65-RSA4096-PSS-SHA512", "sha384", "sha512"),
    ("composite-sig-ml-dsa-65-rsa4096", 44, b"COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", "sha384", "sha512"),
    ("composite-sig-ml-dsa-65-ecdsa-secp256r1", 45, b"COMPSIG-MLDSA65-ECDSA-P256-SHA512", "sha256", "sha512"),
    ("composite-sig-ml-dsa-65-ecdsa-secp384r1", 46, b"COMPSIG-MLDSA65-ECDSA-P384-SHA512", "sha384", "sha512"),
    ("composite-sig-ml-dsa-65-ecdsa-brainpoolP256r1", 47, b"COMPSIG-MLDSA65-ECDSA-BP256-SHA512", "sha256", "sha512"),
    ("composite-sig-ml-dsa-65-ed25519", 48, b"COMPSIG-MLDSA65-Ed25519-SHA512", None, "sha512"),
    ("composite-sig-ml-dsa-87-ecdsa-secp384r1", 49, b"COMPSIG-MLDSA87-ECDSA-P384-SHA512", "sha384", "sha512"),
    ("composite-sig-ml-dsa-87-ecdsa-brainpoolP384r1", 50, b"COMPSIG-MLDSA87-ECDSA-BP384-SHA512", "sha384", "sha512"),
    ("composite-sig-ml-dsa-87-ed448", 51, b"COMPSIG-MLDSA87-Ed448-SHAKE256", None, "shake256"),
    ("composite-sig-ml-dsa-87-rsa3072-pss", 52, b"COMPSIG-MLDSA87-RSA3072-PSS-SHA512", "sha256", "sha512"),
    ("composite-sig-ml-dsa-87-rsa4096-pss", 53, b"COMPSIG-MLDSA87-RSA4096-PSS-SHA512", "sha384", "sha512"),
    ("composite-sig-ml-dsa-87-ecdsa-secp521r1", 54, b"COMPSIG-MLDSA87-ECDSA-P521-SHA512", "sha512", "sha512"),
    # fmt: on
]

COMPOSITE_SIG_NAME_TO_OID = {name: id_compSig_base + (arc,) for name, arc, *_ in _COMPOSITE_SIG_TABLE}
COMPOSITE_SIG_OID_TO_NAME = {v: k for k, v in COMPOSITE_SIG_NAME_TO_OID.items()}
COMPOSITE_SIG_LABELS = {id_compSig_base + (arc,): label for _, arc, label, *_ in _COMPOSITE_SIG_TABLE}
COMPOSITE_SIG_INNER_HASH_OID_2_NAME = {id_compSig_base + (row[1],): row[3] for row in _COMPOSITE_SIG_TABLE}
COMPOSITE_SIG_PREHASH_OID_2_HASH = {id_compSig_base + (row[1],): row[4] for row in _COMPOSITE_SIG_TABLE}

# ---------------------------------------------------------------------------
# Composite KEM OIDs (draft-ietf-lamps-pq-composite-kem-14, arc: 1.3.6.1.5.5.7.6.55-66)
# ---------------------------------------------------------------------------

_COMPOSITE_KEM_MLKEM_NAMES = [
    "composite-kem-ml-kem-768-rsa2048",
    "composite-kem-ml-kem-768-rsa3072",
    "composite-kem-ml-kem-768-rsa4096",
    "composite-kem-ml-kem-768-x25519",
    "composite-kem-ml-kem-768-ecdh-secp256r1",
    "composite-kem-ml-kem-768-ecdh-secp384r1",
    "composite-kem-ml-kem-768-ecdh-brainpoolP256r1",
    "composite-kem-ml-kem-1024-rsa3072",
    "composite-kem-ml-kem-1024-ecdh-secp384r1",
    "composite-kem-ml-kem-1024-ecdh-brainpoolP384r1",
    "composite-kem-ml-kem-1024-x448",
    "composite-kem-ml-kem-1024-ecdh-secp521r1",
]

COMPOSITE_KEM_NAME_2_OID = {name: id_compSig_base + (i,) for i, name in enumerate(_COMPOSITE_KEM_MLKEM_NAMES, start=55)}
COMPOSITE_KEM_OID_2_NAME = {oid: name for name, oid in COMPOSITE_KEM_NAME_2_OID.items()}

# ---------------------------------------------------------------------------
# Chempat OIDs (draft-josefsson-chempat)
# ---------------------------------------------------------------------------

_CHEMPAT_NAMES = [
    # fmt: off
    "chempat-sntrup761-x25519",  # .1
    "chempat-mceliece-348864-x25519",  # .2
    "chempat-mceliece-460896-x25519",  # .3
    "chempat-mceliece-6688128-x25519",  # .4
    "chempat-mceliece-6960119-x25519",  # .5
    "chempat-mceliece-8192128-x25519",  # .6
    "chempat-mceliece-348864-x448",  # .7
    "chempat-mceliece-460896-x448",  # .8
    "chempat-mceliece-6688128-x448",  # .9
    "chempat-mceliece-6960119-x448",  # .10
    "chempat-mceliece-8192128-x448",  # .11
    "chempat-ml-kem-768-x25519",  # .12
    "chempat-ml-kem-1024-x448",  # .13
    "chempat-ml-kem-768-ecdh-secp256r1",  # .14
    "chempat-ml-kem-1024-ecdh-secp384r1",  # .15
    "chempat-ml-kem-768-ecdh-brainpoolP256r1",  # .16
    "chempat-ml-kem-1024-ecdh-brainpoolP384r1",  # .17
    "chempat-frodokem-976-aes-x25519",  # .18
    "chempat-frodokem-976-shake-x25519",  # .19
    "chempat-frodokem-640-aes-ecdh-brainpoolP256r1",  # .20
    "chempat-frodokem-640-shake-ecdh-brainpoolP256r1",  # .21
    "chempat-frodokem-976-aes-ecdh-brainpoolP384r1",  # .22
    "chempat-frodokem-976-shake-ecdh-brainpoolP384r1",  # .23
    "chempat-frodokem-1344-aes-ecdh-brainpoolP512r1",  # .24
    "chempat-frodokem-1344-shake-ecdh-brainpoolP512r1",  # .25
    "chempat-frodokem-1344-aes-x448",  # .26
    "chempat-frodokem-1344-shake-x448",  # .27
    # fmt: on
]

CHEMPAT_OID_2_NAME = {
    univ.ObjectIdentifier(f"{id_Chempat}.{i}"): name for i, name in enumerate(_CHEMPAT_NAMES, start=1)
}
CHEMPAT_NAME_2_OID = {v: k for k, v in CHEMPAT_OID_2_NAME.items()}

# ---------------------------------------------------------------------------
# ALL_COMPOSITE_SIG_COMBINATIONS  (from resources/oidutils.py)
# ---------------------------------------------------------------------------

ALL_COMPOSITE_SIG_COMBINATIONS = [
    {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
    {"pq_name": "ml-dsa-44", "trad_name": "ed25519", "curve": None},
    {"pq_name": "ml-dsa-44", "trad_name": "ecdsa", "curve": "secp256r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "ml-dsa-65", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "ml-dsa-65", "trad_name": "ecdsa", "curve": "secp256r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "ecdsa", "curve": "secp384r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "ecdsa", "curve": "brainpoolP256r1"},
    {"pq_name": "ml-dsa-65", "trad_name": "ed25519", "curve": None},
    {"pq_name": "ml-dsa-87", "trad_name": "ecdsa", "curve": "secp384r1"},
    {"pq_name": "ml-dsa-87", "trad_name": "ecdsa", "curve": "brainpoolP384r1"},
    {"pq_name": "ml-dsa-87", "trad_name": "ed448", "curve": None},
    {"pq_name": "ml-dsa-87", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "ml-dsa-87", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "ml-dsa-87", "trad_name": "ecdsa", "curve": "secp512r1"},
]

# Update aggregated KEM map with hybrid entries
KEM_OID_2_NAME.update(CHEMPAT_OID_2_NAME)
KEM_OID_2_NAME.update({univ.ObjectIdentifier(XWING_OID_STR): "xwing"})
KEM_OID_2_NAME.update(COMPOSITE_KEM_OID_2_NAME)

# Populate the lookup table used by may_return_oid_to_name (defined earlier).
_HYBRID_OID_2_NAME.update(COMPOSITE_SIG_OID_TO_NAME)
_HYBRID_OID_2_NAME.update(CHEMPAT_OID_2_NAME)
_HYBRID_OID_2_NAME.update(COMPOSITE_KEM_OID_2_NAME)
_HYBRID_OID_2_NAME.update({univ.ObjectIdentifier(XWING_OID_STR): "xwing"})


# ---------------------------------------------------------------------------
# Traditional signature OIDs (RSA, RSASSA-PSS, ECDSA, EdDSA)
# Subset of resources/oidutils.py needed by validate_sig_alg_id.
# ---------------------------------------------------------------------------

RSA_SHA2_OID_2_NAME = {
    rfc9481.sha224WithRSAEncryption: "rsa-sha224",
    rfc9481.sha256WithRSAEncryption: "rsa-sha256",
    rfc9481.sha384WithRSAEncryption: "rsa-sha384",
    rfc9481.sha512WithRSAEncryption: "rsa-sha512",
}

RSA_SHA3_OID_2_NAME = {
    rfc9688.id_rsassa_pkcs1_v1_5_with_sha3_224: "rsa-sha3_224",
    rfc9688.id_rsassa_pkcs1_v1_5_with_sha3_256: "rsa-sha3_256",
    rfc9688.id_rsassa_pkcs1_v1_5_with_sha3_384: "rsa-sha3_384",
    rfc9688.id_rsassa_pkcs1_v1_5_with_sha3_512: "rsa-sha3_512",
}

RSA_OID_2_NAME = {rfc8017.sha1WithRSAEncryption: "rsa-sha1"}
RSA_OID_2_NAME.update(RSA_SHA2_OID_2_NAME)
RSA_OID_2_NAME.update(RSA_SHA3_OID_2_NAME)

RSASSA_PSS_OID_2_NAME = {
    rfc9481.id_RSASSA_PSS: "rsassa_pss-sha256",
    rfc9481.id_RSASSA_PSS_SHAKE128: "rsassa_pss-shake128",
    rfc9481.id_RSASSA_PSS_SHAKE256: "rsassa_pss-shake256",
}

ECDSA_SHA_OID_2_NAME = {
    rfc9481.ecdsa_with_SHA224: "ecdsa-sha224",
    rfc9481.ecdsa_with_SHA256: "ecdsa-sha256",
    rfc9481.ecdsa_with_SHA384: "ecdsa-sha384",
    rfc9481.ecdsa_with_SHA512: "ecdsa-sha512",
    rfc9481.id_ecdsa_with_shake128: "ecdsa-shake128",
    rfc9481.id_ecdsa_with_shake256: "ecdsa-shake256",
}

ECDSA_SHA3_OID_2_NAME = {
    rfc9688.id_ecdsa_with_sha3_224: "ecdsa-sha3_224",
    rfc9688.id_ecdsa_with_sha3_256: "ecdsa-sha3_256",
    rfc9688.id_ecdsa_with_sha3_384: "ecdsa-sha3_384",
    rfc9688.id_ecdsa_with_sha3_512: "ecdsa-sha3_512",
}

ECDSA_OID_2_NAME: Dict[univ.ObjectIdentifier, str] = {}
ECDSA_OID_2_NAME.update(ECDSA_SHA_OID_2_NAME)
ECDSA_OID_2_NAME.update(ECDSA_SHA3_OID_2_NAME)

# Pure EdDSA
ED_OID_2_NAME = {
    rfc9481.id_Ed25519: "ed25519",
    rfc9481.id_Ed448: "ed448",
}

TRAD_SIG_OID_2_NAME: Dict[univ.ObjectIdentifier, str] = {}
TRAD_SIG_OID_2_NAME.update(ED_OID_2_NAME)
TRAD_SIG_OID_2_NAME.update(RSA_OID_2_NAME)
TRAD_SIG_OID_2_NAME.update(RSASSA_PSS_OID_2_NAME)
TRAD_SIG_OID_2_NAME.update(ECDSA_OID_2_NAME)

TRAD_SIG_NAME_2_OID = {v: k for k, v in TRAD_SIG_OID_2_NAME.items()}


# ---------------------------------------------------------------------------
# Curve cofactors (used by compute_ecdh when use_cofactor=True).
# Copy of resources/oidutils.py:CURVE_2_COFACTORS.
# ---------------------------------------------------------------------------

CURVE_2_COFACTORS: Dict[str, int] = {
    # Curves over prime fields (Fp)
    "secp112r1": 1,
    "secp112r2": 4,
    "secp128r1": 1,
    "secp128r2": 4,
    "secp160k1": 1,
    "secp160r1": 1,
    "secp160r2": 1,
    "secp192k1": 1,
    "secp192r1": 1,
    "secp224k1": 1,
    "secp224r1": 1,
    "secp256k1": 1,
    "secp256r1": 1,
    "secp384r1": 1,
    "secp521r1": 1,
    # Curves over binary fields (F2m)
    "sect113r1": 2,
    "sect113r2": 2,
    "sect131r1": 2,
    "sect131r2": 2,
    "sect163k1": 2,
    "sect163r1": 2,
    "sect163r2": 2,
    "sect193r1": 2,
    "sect193r2": 2,
    "sect233k1": 4,
    "sect233r1": 2,
    "sect239k1": 4,
    "sect283k1": 4,
    "sect283r1": 2,
    "sect409k1": 4,
    "sect409r1": 2,
    "sect571k1": 4,
    "sect571r1": 2,
    # Brainpool curves RFC 5639
    "brainpoolP160r1": 1,
    "brainpoolP192r1": 1,
    "brainpoolP224r1": 1,
    "brainpoolP256r1": 1,
    "brainpoolP320r1": 1,
    "brainpoolP384r1": 1,
    "brainpoolP512r1": 1,
    "brainpoolP160t1": 1,
    "brainpoolP192t1": 1,
    "brainpoolP224t1": 1,
    "brainpoolP256t1": 1,
    "brainpoolP320t1": 1,
    "brainpoolP384t1": 1,
    "brainpoolP512t1": 1,
    # Montgomery and Edwards curves
    "curve25519": 8,
    "curve448": 4,
    "edwards25519": 8,
    "edwards448": 4,
}


# ---------------------------------------------------------------------------
# Curve registry + key-class naming (from cmp-test-suite/resources/oid_mapping.py)
# ---------------------------------------------------------------------------


CURVE_NAMES_TO_INSTANCES: Dict[str, ec.EllipticCurve] = {
    "secp192r1": ec.SECP192R1(),
    "prime192v1": ec.SECP192R1(),
    "secp224r1": ec.SECP224R1(),
    "prime224v1": ec.SECP224R1(),
    "secp256r1": ec.SECP256R1(),
    "prime256v1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
    "secp256k1": ec.SECP256K1(),
    "brainpoolP256r1": ec.BrainpoolP256R1(),
    "brainpoolP384r1": ec.BrainpoolP384R1(),
    "brainpoolP512r1": ec.BrainpoolP512R1(),
    "brainpoolp256r1": ec.BrainpoolP256R1(),
    "brainpoolp384r1": ec.BrainpoolP384R1(),
    "brainpoolp512r1": ec.BrainpoolP512R1(),
}


CURVE_NAME_2_OID: Dict[str, univ.ObjectIdentifier] = {}
for _curve in CURVE_NAMES_TO_INSTANCES.values():
    _tmp_oid = getattr(ec.EllipticCurveOID(), _curve.name.upper())
    CURVE_NAME_2_OID[_curve.name] = univ.ObjectIdentifier(_tmp_oid.dotted_string)
    CURVE_NAME_2_OID[_curve.name.lower()] = univ.ObjectIdentifier(_tmp_oid.dotted_string)


_ALLOWED_HASH_TYPES: Dict[str, hashes.HashAlgorithm] = {
    "sha1": hashes.SHA1(),
    "sha224": hashes.SHA224(),
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
    "shake128": hashes.SHAKE128(32),
    "shake256": hashes.SHAKE256(64),
    "sha3_224": hashes.SHA3_224(),
    "sha3_256": hashes.SHA3_256(),
    "sha3_384": hashes.SHA3_384(),
    "sha3_512": hashes.SHA3_512(),
}


KEY_CLASS_MAPPING = {
    "RSAPrivateKey": "rsa",
    "RSAPublicKey": "rsa",
    "EllipticCurvePrivateKey": "ecdsa",
    "EllipticCurvePublicKey": "ecdsa",
    "ECPrivateKey": "ecdsa",
    "ECPublicKey": "ecdsa",
    "DSAPrivateKey": "dsa",
    "DSAPublicKey": "dsa",
    "Ed25519PrivateKey": "ed25519",
    "Ed25519PublicKey": "ed25519",
    "Ed448PrivateKey": "ed448",
    "Ed448PublicKey": "ed448",
    "X25519PrivateKey": "x25519",
    "X25519PublicKey": "x25519",
    "X448PrivateKey": "x448",
    "X448PublicKey": "x448",
}


def get_curve_instance(curve_name: str) -> ec.EllipticCurve:
    """Return the :mod:`cryptography` curve instance for *curve_name*."""
    if curve_name not in CURVE_NAMES_TO_INSTANCES:
        raise ValueError(f"The Curve: {curve_name} is not Supported!")
    return CURVE_NAMES_TO_INSTANCES[curve_name]


def hash_name_to_instance(alg: str) -> hashes.HashAlgorithm:
    """Return the :mod:`cryptography` hash instance for *alg* (e.g. ``"sha256"``)."""
    try:
        if "-" in alg:
            return _ALLOWED_HASH_TYPES[alg.split("-")[1]]
        return _ALLOWED_HASH_TYPES[alg]
    except KeyError as err:
        raise ValueError(f"Unsupported hash algorithm: {alg}") from err


# ---------------------------------------------------------------------------
# AlgorithmIdentifier parameter-shape catalog (drives validate_sig_alg_id)
# ---------------------------------------------------------------------------


# id_xmss / id_xmssmt are not exported by every pyasn1-alt-modules version.
_PKIX_CMP_ALG_ROOT = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 6))
id_xmss = _PKIX_CMP_ALG_ROOT + (34,)
id_xmssmt = _PKIX_CMP_ALG_ROOT + (35,)


_SIG_ALG_OID_2_PARAMETERS_SPEC: Dict[univ.ObjectIdentifier, SigAlgParametersSpec] = {}

# RSA PKCS#1 v1.5 — parameters MUST be NULL.
for _oid in RSA_OID_2_NAME:
    _SIG_ALG_OID_2_PARAMETERS_SPEC[_oid] = SigAlgParametersSpec.MUST_BE_NULL

# RSASSA-PSS: id-RSASSA-PSS carries RSASSA-PSS-params; SHAKE variants must be absent.
_SIG_ALG_OID_2_PARAMETERS_SPEC[rfc9481.id_RSASSA_PSS] = SigAlgParametersSpec.MUST_BE_RSASSA_PSS_PARAMS
_SIG_ALG_OID_2_PARAMETERS_SPEC[rfc9481.id_RSASSA_PSS_SHAKE128] = SigAlgParametersSpec.MUST_BE_ABSENT
_SIG_ALG_OID_2_PARAMETERS_SPEC[rfc9481.id_RSASSA_PSS_SHAKE256] = SigAlgParametersSpec.MUST_BE_ABSENT

# ECDSA + EdDSA — parameters absent.
for _oid in ECDSA_OID_2_NAME:
    _SIG_ALG_OID_2_PARAMETERS_SPEC[_oid] = SigAlgParametersSpec.MUST_BE_ABSENT
for _oid in ED_OID_2_NAME:
    _SIG_ALG_OID_2_PARAMETERS_SPEC[_oid] = SigAlgParametersSpec.MUST_BE_ABSENT

# PQ signatures (ML-DSA, SLH-DSA, Falcon, with and without pre-hash) — absent.
for _oid in PQ_SIG_OID_2_NAME:
    _SIG_ALG_OID_2_PARAMETERS_SPEC[_oid] = SigAlgParametersSpec.MUST_BE_ABSENT
for _oid in PQ_SIG_PRE_HASH_OID_2_NAME:
    _SIG_ALG_OID_2_PARAMETERS_SPEC[_oid] = SigAlgParametersSpec.MUST_BE_ABSENT

# Stateful-hash — absent.
for _oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
    _SIG_ALG_OID_2_PARAMETERS_SPEC[_oid] = SigAlgParametersSpec.MUST_BE_ABSENT
_SIG_ALG_OID_2_PARAMETERS_SPEC.setdefault(rfc9708.id_alg_hss_lms_hashsig, SigAlgParametersSpec.MUST_BE_ABSENT)
_SIG_ALG_OID_2_PARAMETERS_SPEC.setdefault(id_xmss, SigAlgParametersSpec.MUST_BE_ABSENT)
_SIG_ALG_OID_2_PARAMETERS_SPEC.setdefault(id_xmssmt, SigAlgParametersSpec.MUST_BE_ABSENT)

# Composite-sig — absent.
for _oid in COMPOSITE_SIG_OID_TO_NAME:
    _SIG_ALG_OID_2_PARAMETERS_SPEC[_oid] = SigAlgParametersSpec.MUST_BE_ABSENT


SIG_ALG_OID_2_PARAMETERS_SPEC: Dict[univ.ObjectIdentifier, SigAlgParametersSpec] = dict(_SIG_ALG_OID_2_PARAMETERS_SPEC)


# OID → ASN.1 spec class for parameter decoding.
ALG_ID_PARAMETERS_OID_2_SPEC: Dict[univ.ObjectIdentifier, type] = {
    rfc9481.id_RSASSA_PSS: rfc4055.RSASSA_PSS_params,
}
