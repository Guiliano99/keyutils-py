# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Write ``oid_tables.tsv``, the golden copy of the cmp-test-suite OID tables.

Run it by hand from a cmp-test-suite checkout with that checkout's virtual environment. The tests never run it and
never import cmp-test-suite; they only read the file it writes. Rerun it when the cmp-test-suite tables change and
review the diff of the TSV file:

    cd <cmp-test-suite>
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. .venv/bin/python <keyutils-py>/tests/golden/generate_oid_tables.py

Every line is ``table``, ``name``, ``oid`` (tab separated, the OID dotted). A table that maps OID to name and one that
maps name to OID give the same kind of line, so the direction of the table does not matter. The table ``constants``
holds single OID values by variable name. The table ``may_return_oid_to_name`` holds the result of the cmp-test-suite
function ``may_return_oid_to_name`` for every OID that its table ``ALL_KNOWN_OIDS_2_NAME`` knows.
"""

import csv
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pq_logic.tmp_oids as tmp_oids
import resources.oid_mapping as oid_mapping
import resources.oidutils as oidutils
from pyasn1.type import univ

OUTPUT = Path(__file__).with_name("oid_tables.tsv")

# Tables the package defines with the same name and the same content as cmp-test-suite.
TABLES = (
    # Hash, MAC, KDF, key wrap and content encryption.
    "SHA2_OID_2_NAME",
    "SHA2_NAME_2_OID",
    "SHA_OID_2_NAME",
    "HMAC_SHA_OID_2_NAME",
    "HMAC_SHA3_OID_2_NAME",
    "HMAC_OID_2_NAME",
    "KMAC_OID_2_NAME",
    "AES_GMAC_NAME_2_OID",
    "AES_GMAC_OID_2_NAME",
    "HKDF_NAME_2_OID",
    "HKDF_OID_2_NAME",
    "AES_CBC_NAME_2_OID",
    "AES_CBC_OID_2_NAME",
    "AES_GCM_NAME_2_OID",
    "AES_GCM_OID_2_NAME",
    "SYMMETRIC_ENCR_ALG_OID_2_NAME",
    "SYMMETRIC_ENCR_ALG_NAME_2_OID",
    "KEY_WRAP_NAME_2_OID",
    "KEY_WRAP_OID_2_NAME",
    "KM_KW_ALG",
    # CMP protection algorithms.
    "LWCMP_MAC_OID_2_NAME",
    "SYMMETRIC_PROT_ALGO",
    "MSG_SIG_ALG",
    "SUPPORTED_MAC_OID_2_NAME",
    # Tables the package already had; they have to stay equal while cmp-test-suite keeps its own copy.
    "RSA_OID_2_NAME",
    "RSASSA_PSS_OID_2_NAME",
    "ECDSA_OID_2_NAME",
    "PQ_OID_2_NAME",
    "PQ_NAME_2_OID",
    "PQ_SIG_OID_2_NAME",
    "PQ_SIG_PRE_HASH_OID_2_NAME",
    "PQ_STATEFUL_HASH_SIG_OID_2_NAME",
    "COMPOSITE_SIG_OID_TO_NAME",
)

# Single OID values.
CONSTANTS = (
    "id_alg",
    "id_KemBasedMac",
    "id_it_KemCiphertextInfo",
    "id_ce_subjectAltPublicKeyInfo",
    "id_ce_altSignatureAlgorithm",
    "id_ce_altSignatureValue",
)

# Not an OID table of the package: the host lookup that ``may_return_oid_to_name`` has to agree with.
NAME_LOOKUP_TABLE = "may_return_oid_to_name"


def _lookup(name: str) -> object:
    """Return the cmp-test-suite object ``name`` from ``resources.oidutils`` or ``pq_logic.tmp_oids``."""
    for module in (oidutils, tmp_oids):
        if hasattr(module, name):
            return getattr(module, name)
    raise SystemExit(f"{name} is neither in resources.oidutils nor in pq_logic.tmp_oids")


def _pairs(table: Dict) -> List[Tuple[str, str]]:
    """Return ``(name, dotted OID)`` for every entry, whichever way the table maps."""
    pairs = []
    for key, value in table.items():
        if isinstance(key, univ.ObjectIdentifier):
            pairs.append((value, str(key)))
        elif isinstance(value, univ.ObjectIdentifier):
            pairs.append((key, str(value)))
        else:
            raise SystemExit(f"entry {key!r}: {value!r} has no OID")
    return pairs


def _known_oids() -> List[univ.ObjectIdentifier]:
    """Return the OIDs of the host table ``ALL_KNOWN_OIDS_2_NAME``, as a key or as a dotted string key."""
    known = []
    for key in oidutils.ALL_KNOWN_OIDS_2_NAME:
        if isinstance(key, univ.ObjectIdentifier):
            known.append(key)
        elif key.replace(".", "").isdigit():
            known.append(univ.ObjectIdentifier(key))
    return known


def main() -> None:
    """Write the golden file."""
    rows = []
    for table in TABLES:
        rows.extend((table, name, oid) for name, oid in sorted(_pairs(_lookup(table))))
    rows.extend(("constants", name, str(_lookup(name))) for name in CONSTANTS)
    lookups = {(NAME_LOOKUP_TABLE, oid_mapping.may_return_oid_to_name(oid), str(oid)) for oid in _known_oids()}
    rows.extend(sorted(lookups, key=lambda row: (row[2], row[1])))

    with open(OUTPUT, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(("table", "name", "oid"))
        writer.writerows(rows)
    sys.stderr.write(f"wrote {len(rows)} rows to {OUTPUT}\n")


if __name__ == "__main__":
    main()
