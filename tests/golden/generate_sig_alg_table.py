# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Write ``sig_alg_table.tsv``, the golden table of the signature algorithms.

The file is NOT derived from ``keyutils_py``: the table in ``keyutils_py.oids`` is checked against it. The facts
(family, hash, pre-hash mode, padding, parameter shape, CMS digest) are written down below by hand, one literal
entry per algorithm, with the RFC that states them. Two independent witnesses check the literals:

* the OIDs of ``pyasn1_alt_modules`` (which are generated from the RFC ASN.1 modules) must equal the cmp-test-suite
  OID of the same name, and
* the set of names must equal the set of names of the cmp-test-suite signature tables (nothing missing, nothing extra),
  so a new algorithm in cmp-test-suite makes this script fail until its facts are added here.

Run it by hand from a cmp-test-suite checkout with that checkout's virtual environment, then review the diff of the
TSV file. The tests never run it and never import cmp-test-suite; they only read the file it writes:

    cd <cmp-test-suite>
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. .venv/bin/python <keyutils-py>/tests/golden/generate_sig_alg_table.py

Columns: ``oid``, ``name``, ``family``, ``key_name``, ``hash_alg``, ``pre_hash``, ``pss``, ``params``,
``cms_digest``. An empty cell is "none"; ``pre_hash`` and ``pss`` are ``true`` or ``false``. ``params`` is one of
``absent``, ``null`` and ``rsassa_pss_params``.

Sources of the facts:

* RFC 8017 / RFC 3279 (sha1WithRSAEncryption), RFC 4055 Section 5 and RFC 5754 Section 3.2
  (sha*WithRSAEncryption: parameters NULL on generation), RFC 9688 Section 3 (SHA-3 with RSA, NULL).
* RFC 4055 Section 3.1 (id-RSASSA-PSS: hash, MGF1 and salt are in the parameters, so no fixed hash here) and
  RFC 8702 Section 3 (RSASSA-PSS-SHAKE128/256: parameters absent, hash SHAKE128/SHAKE256).
* RFC 5758 Section 3.2 (ECDSA with SHA-2, parameters absent), RFC 8702 (ECDSA with SHAKE), RFC 9688 (ECDSA with
  SHA-3), RFC 5758 Section 3.1 (id-dsa-with-sha256, parameters absent).
* RFC 8410 Section 3 (EdDSA, parameters absent) and RFC 8419 Section 3.1 (CMS digest: Ed25519 SHA-512,
  Ed448 SHAKE256).
* RFC 9881 Section 3 and RFC 9882 Section 4 (ML-DSA, parameters absent, CMS digest SHA-512). The HashML-DSA OIDs
  (2.16.840.1.101.3.4.3.32 to 34, "ML-DSA with SHA-512") are in no RFC module; they come from the NIST OID registry
  and are described in RFC 9881 Section 8.3.
* RFC 9814 Section 3 and 4 (SLH-DSA, parameters absent, CMS digest per parameter set) and RFC 9909 (HashSLH-DSA
  OIDs, one hash per parameter set).
* Falcon: the OIDs are test OIDs of cmp-test-suite and no RFC names a CMS digest for them; the value is the
  convention of cmp-test-suite (SHA-512, as for ML-DSA), kept so that the table gives what the test suite uses today.
* RFC 8708 / RFC 9708 (HSS/LMS) and RFC 9802 (XMSS, XMSS^MT): parameters absent; no CMS digest is registered here.
* draft-ietf-lamps-pq-composite-sigs: the arc (37 to 54) names the combination, the last label component is the
  hash of the pre-hashed message M'; ``-pss`` combinations use RSASSA-PSS.
* rsaEncryption as signature algorithm identifier: RFC 3370 Section 3.2 (parameters NULL, hash is not named).
"""

import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pyasn1_alt_modules.rfc4055 as rfc4055
import pyasn1_alt_modules.rfc5480 as rfc5480
import pyasn1_alt_modules.rfc8017 as rfc8017
import pyasn1_alt_modules.rfc8410 as rfc8410
import pyasn1_alt_modules.rfc8692 as rfc8692
import pyasn1_alt_modules.rfc9688 as rfc9688
import pyasn1_alt_modules.rfc9814 as rfc9814
import pyasn1_alt_modules.rfc9881 as rfc9881
import pyasn1_alt_modules.rfc9909 as rfc9909
import resources.oidutils as oidutils
from pyasn1.type import univ

OUTPUT = Path(__file__).with_name("sig_alg_table.tsv")

# One row per algorithm: name -> (RFC module attribute or None, hash_alg, pre_hash, params, cms_digest).
Facts = Tuple[Optional[Tuple[object, str]], Optional[str], bool, str, Optional[str]]

# ---- RSA PKCS#1 v1.5: key "rsa", parameters NULL, CMS digest = the named hash -------------------------------------
PKCS1_V15: Dict[str, Tuple[object, str, str]] = {
    "rsa-sha1": (rfc8017, "sha1WithRSAEncryption", "sha1"),
    "rsa-sha224": (rfc4055, "sha224WithRSAEncryption", "sha224"),
    "rsa-sha256": (rfc4055, "sha256WithRSAEncryption", "sha256"),
    "rsa-sha384": (rfc4055, "sha384WithRSAEncryption", "sha384"),
    "rsa-sha512": (rfc4055, "sha512WithRSAEncryption", "sha512"),
    "rsa-sha3_224": (rfc9688, "id_rsassa_pkcs1_v1_5_with_sha3_224", "sha3_224"),
    "rsa-sha3_256": (rfc9688, "id_rsassa_pkcs1_v1_5_with_sha3_256", "sha3_256"),
    "rsa-sha3_384": (rfc9688, "id_rsassa_pkcs1_v1_5_with_sha3_384", "sha3_384"),
    "rsa-sha3_512": (rfc9688, "id_rsassa_pkcs1_v1_5_with_sha3_512", "sha3_512"),
}

# ---- ECDSA: key "ecdsa", parameters absent, CMS digest = the named hash ------------------------------------------
ECDSA: Dict[str, Tuple[object, str, str]] = {
    "ecdsa-sha224": (rfc5480, "ecdsa_with_SHA224", "sha224"),
    "ecdsa-sha256": (rfc5480, "ecdsa_with_SHA256", "sha256"),
    "ecdsa-sha384": (rfc5480, "ecdsa_with_SHA384", "sha384"),
    "ecdsa-sha512": (rfc5480, "ecdsa_with_SHA512", "sha512"),
    "ecdsa-shake128": (rfc8692, "id_ecdsa_with_shake128", "shake128"),
    "ecdsa-shake256": (rfc8692, "id_ecdsa_with_shake256", "shake256"),
    "ecdsa-sha3_224": (rfc9688, "id_ecdsa_with_sha3_224", "sha3_224"),
    "ecdsa-sha3_256": (rfc9688, "id_ecdsa_with_sha3_256", "sha3_256"),
    "ecdsa-sha3_384": (rfc9688, "id_ecdsa_with_sha3_384", "sha3_384"),
    "ecdsa-sha3_512": (rfc9688, "id_ecdsa_with_sha3_512", "sha3_512"),
}

# ---- ML-DSA (pure) and HashML-DSA with SHA-512; CMS digest SHA-512 (RFC 9882 Section 4) --------------------------
ML_DSA_PURE = {
    "ml-dsa-44": (rfc9881, "id_ml_dsa_44"),
    "ml-dsa-65": (rfc9881, "id_ml_dsa_65"),
    "ml-dsa-87": (rfc9881, "id_ml_dsa_87"),
}
ML_DSA_PRE_HASH = ("ml-dsa-44-sha512", "ml-dsa-65-sha512", "ml-dsa-87-sha512")

# ---- SLH-DSA: parameter set -> (pure OID attribute, hash of the CMS digest and of the pre-hash OID,
# ---- pre-hash OID attribute)
SLH_DSA: Dict[str, Tuple[str, str, str]] = {
    "slh-dsa-sha2-128s": ("id_slh_dsa_sha2_128s", "sha256", "id_hash_slh_dsa_sha2_128s_with_sha256"),
    "slh-dsa-sha2-128f": ("id_slh_dsa_sha2_128f", "sha256", "id_hash_slh_dsa_sha2_128f_with_sha256"),
    "slh-dsa-sha2-192s": ("id_slh_dsa_sha2_192s", "sha512", "id_hash_slh_dsa_sha2_192s_with_sha512"),
    "slh-dsa-sha2-192f": ("id_slh_dsa_sha2_192f", "sha512", "id_hash_slh_dsa_sha2_192f_with_sha512"),
    "slh-dsa-sha2-256s": ("id_slh_dsa_sha2_256s", "sha512", "id_hash_slh_dsa_sha2_256s_with_sha512"),
    "slh-dsa-sha2-256f": ("id_slh_dsa_sha2_256f", "sha512", "id_hash_slh_dsa_sha2_256f_with_sha512"),
    "slh-dsa-shake-128s": ("id_slh_dsa_shake_128s", "shake128", "id_hash_slh_dsa_shake_128s_with_shake128"),
    "slh-dsa-shake-128f": ("id_slh_dsa_shake_128f", "shake128", "id_hash_slh_dsa_shake_128f_with_shake128"),
    "slh-dsa-shake-192s": ("id_slh_dsa_shake_192s", "shake256", "id_hash_slh_dsa_shake_192s_with_shake256"),
    "slh-dsa-shake-192f": ("id_slh_dsa_shake_192f", "shake256", "id_hash_slh_dsa_shake_192f_with_shake256"),
    "slh-dsa-shake-256s": ("id_slh_dsa_shake_256s", "shake256", "id_hash_slh_dsa_shake_256s_with_shake256"),
    "slh-dsa-shake-256f": ("id_slh_dsa_shake_256f", "shake256", "id_hash_slh_dsa_shake_256f_with_shake256"),
}

# ---- Composite signatures: arc -> (name, hash of M'); the hash is the last component of the draft's label --------
COMPOSITE_BASE = "1.3.6.1.5.5.7.6."
COMPOSITE: Dict[int, Tuple[str, str]] = {
    37: ("composite-sig-ml-dsa-44-rsa2048-pss", "sha256"),
    38: ("composite-sig-ml-dsa-44-rsa2048", "sha256"),
    39: ("composite-sig-ml-dsa-44-ed25519", "sha512"),
    40: ("composite-sig-ml-dsa-44-ecdsa-secp256r1", "sha256"),
    41: ("composite-sig-ml-dsa-65-rsa3072-pss", "sha512"),
    42: ("composite-sig-ml-dsa-65-rsa3072", "sha512"),
    43: ("composite-sig-ml-dsa-65-rsa4096-pss", "sha512"),
    44: ("composite-sig-ml-dsa-65-rsa4096", "sha512"),
    45: ("composite-sig-ml-dsa-65-ecdsa-secp256r1", "sha512"),
    46: ("composite-sig-ml-dsa-65-ecdsa-secp384r1", "sha512"),
    47: ("composite-sig-ml-dsa-65-ecdsa-brainpoolP256r1", "sha512"),
    48: ("composite-sig-ml-dsa-65-ed25519", "sha512"),
    49: ("composite-sig-ml-dsa-87-ecdsa-secp384r1", "sha512"),
    50: ("composite-sig-ml-dsa-87-ecdsa-brainpoolP384r1", "sha512"),
    51: ("composite-sig-ml-dsa-87-ed448", "shake256"),
    52: ("composite-sig-ml-dsa-87-rsa3072-pss", "sha512"),
    53: ("composite-sig-ml-dsa-87-rsa4096-pss", "sha512"),
    54: ("composite-sig-ml-dsa-87-ecdsa-secp521r1", "sha512"),
}

# Row: oid, name, family, key_name, hash_alg, pre_hash, pss, params, cms_digest
Row = Tuple[str, str, str, str, str, str, str, str, str]


def _cell(value: object) -> str:
    """Return the TSV cell for ``value``."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _row(oid, name, family, key_name, hash_alg, pre_hash, pss, params, cms_digest) -> Row:
    """Return one table row as strings."""
    return (str(oid), name, family, *(_cell(v) for v in (key_name, hash_alg, pre_hash, pss, params, cms_digest)))  # type: ignore[return-value]


def _rfc_oid(module: object, attribute: str) -> univ.ObjectIdentifier:
    """Return the OID the RFC module ``module`` defines as ``attribute``."""
    return getattr(module, attribute)


def _host_names() -> Dict[str, univ.ObjectIdentifier]:
    """Return every signature name of cmp-test-suite with its OID."""
    names: Dict[str, univ.ObjectIdentifier] = {}
    for table in (
        oidutils.TRAD_SIG_OID_2_NAME,
        oidutils.PQ_SIG_OID_2_NAME,
        oidutils.PQ_STATEFUL_HASH_SIG_OID_2_NAME,
        oidutils.COMPOSITE_SIG_OID_TO_NAME,
    ):
        for oid, name in table.items():
            if name in names:
                raise SystemExit(f"the name {name} is in two cmp-test-suite tables")
            names[name] = oid
    return names


def _build() -> List[Row]:
    """Return the rows, checked against the RFC modules and the cmp-test-suite names."""
    host = _host_names()
    rows: List[Row] = []
    used: Dict[str, univ.ObjectIdentifier] = {}

    def add(oid: univ.ObjectIdentifier, name: str, *facts: object, from_host: bool = True) -> None:
        if from_host:
            if host.get(name) != oid:
                raise SystemExit(f"{name}: RFC OID {oid} differs from cmp-test-suite {host.get(name)}")
            used[name] = oid
        rows.append(_row(oid, name, *facts))  # type: ignore[arg-type]

    for name, (module, attribute, hash_alg) in PKCS1_V15.items():
        add(_rfc_oid(module, attribute), name, "rsa", "rsa", hash_alg, False, False, "null", hash_alg)
    # RFC 3370 Section 3.2: rsaEncryption names no hash; the digest comes from the caller.
    add(rfc8017.rsaEncryption, "rsa-encryption", "rsa", "rsa", None, False, False, "null", None, from_host=False)

    # RFC 4055 Section 3.1: hash, MGF1 and salt length are in the parameters.
    add(rfc4055.id_RSASSA_PSS, "rsassa_pss-sha256", "rsa-pss", "rsa", None, False, True, "rsassa_pss_params", None)
    for suffix in ("shake128", "shake256"):  # RFC 8702 Section 3: parameters absent.
        oid = _rfc_oid(rfc8692, f"id_RSASSA_PSS_{suffix.upper()}")
        add(oid, f"rsassa_pss-{suffix}", "rsa-pss", "rsa", suffix, False, True, "absent", suffix)

    for name, (module, attribute, hash_alg) in ECDSA.items():
        add(_rfc_oid(module, attribute), name, "ecdsa", "ecdsa", hash_alg, False, False, "absent", hash_alg)

    # DSA is not in cmp-test-suite's tables (RFC 5758 Section 3.1 defines the OID, parameters absent).
    add(
        rfc5480.id_dsa_with_sha256,
        "dsa-sha256",
        "dsa",
        "dsa",
        "sha256",
        False,
        False,
        "absent",
        "sha256",
        from_host=False,
    )

    # RFC 8419 Section 3.1: the CMS digest of Ed25519 is SHA-512, the one of Ed448 is SHAKE256.
    add(rfc8410.id_Ed25519, "ed25519", "eddsa", "ed25519", None, False, False, "absent", "sha512")
    add(rfc8410.id_Ed448, "ed448", "eddsa", "ed448", None, False, False, "absent", "shake256")

    for name, (module, attribute) in ML_DSA_PURE.items():
        add(_rfc_oid(module, attribute), name, "ml-dsa", name, None, False, False, "absent", "sha512")
    # Falcon: test OIDs of cmp-test-suite (no RFC); the CMS digest is the cmp-test-suite convention.
    falcon_oids = {name: oid for oid, name in oidutils.PQ_SIG_OID_2_NAME.items() if name.startswith("falcon-")}
    for name, oid in falcon_oids.items():
        add(oid, name, "falcon", name, None, False, False, "absent", "sha512")

    pre_hash_by_name = {name: oid for oid, name in oidutils.PQ_SIG_PRE_HASH_OID_2_NAME.items()}
    for name in ML_DSA_PRE_HASH:
        base = name.removesuffix("-sha512")
        add(pre_hash_by_name[name], name, "ml-dsa", base, "sha512", True, False, "absent", "sha512")
    for base, (pure_attribute, hash_alg, pre_attribute) in SLH_DSA.items():
        add(_rfc_oid(rfc9814, pure_attribute), base, "slh-dsa", base, None, False, False, "absent", hash_alg)
        add(
            _rfc_oid(rfc9909, pre_attribute),
            f"{base}-{hash_alg}",
            "slh-dsa",
            base,
            hash_alg,
            True,
            False,
            "absent",
            hash_alg,
        )

    # RFC 8708 / RFC 9708 (HSS) and RFC 9802 (XMSS, XMSS^MT); the OID of HSS is also in the RFC module.
    stateful = {name: oid for oid, name in oidutils.PQ_STATEFUL_HASH_SIG_OID_2_NAME.items()}
    for name in ("hss", "xmss", "xmssmt"):
        add(stateful[name], name, name, name, None, False, False, "absent", None)

    for arc, (name, hash_alg) in COMPOSITE.items():
        add(
            univ.ObjectIdentifier(COMPOSITE_BASE + str(arc)),
            name,
            "composite",
            None,
            hash_alg,
            False,
            name.endswith("-pss"),
            "absent",
            hash_alg,
        )

    missing = sorted(set(host) - set(used))
    extra = sorted(set(used) - set(host))
    if missing or extra:
        raise SystemExit(f"names of cmp-test-suite without facts here: {missing}; facts here without a name: {extra}")
    return rows


def main() -> None:
    """Write the golden file."""
    rows = sorted(_build(), key=lambda row: tuple(int(part) for part in row[0].split(".")))
    with open(OUTPUT, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(("oid", "name", "family", "key_name", "hash_alg", "pre_hash", "pss", "params", "cms_digest"))
        writer.writerows(rows)
    sys.stderr.write(f"wrote {len(rows)} rows to {OUTPUT}\n")


if __name__ == "__main__":
    main()
