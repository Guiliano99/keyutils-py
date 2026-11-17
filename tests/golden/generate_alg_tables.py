# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Write ``alg_tables.tsv``, the golden table of the KDF, MAC, key wrap, content, key agreement and key transport OIDs.

The file is NOT derived from ``keyutils_py``: ``keyutils_py._algs`` is checked against it. The facts (family, hash,
size, mode) are written down below by hand, one literal entry per OID, with the RFC that states them. The dotted OID
of each entry is written next to the name of the ``pyasn1_alt_modules`` constant (which is generated from the ASN.1
modules of the RFCs), and the script fails if the two differ, so an OID is confirmed by two independent witnesses.

Run it by hand, then review the diff of the TSV file. The tests never run it; they only read the file it writes:

    PYTHONDONTWRITEBYTECODE=1 python tests/golden/generate_alg_tables.py

Columns: ``table``, ``oid``, ``name``, ``family``, ``variant``, ``hash``, ``bits``, ``size``, ``prf``. An empty cell is
"none". ``variant`` is the wrap mode (``kw``, ``kwp``), the content mode (``cbc``, ``gcm``), the key agreement scheme
(``stdDH``, ``cofactorDH``, ``mqv``, ``legacy``) or the key transport padding (``pkcs1v15``, ``oaep``). ``size`` is
the KEK or CEK size in octets, ``bits`` the AES key size of AES-GMAC, ``prf`` is ``true`` for an HMAC OID that RFC 8018
Appendix B.1 names as a PBKDF2 pseudorandom function and ``false`` for the other HMAC OIDs.

Sources of the facts:

* RFC 8619 (HKDF with SHA-256/384/512) and RFC 9688 Section 5.1 (HKDF with SHA3-224/256/384/512, the OIDs ``id-alg
  32`` to ``35``): the hash is part of the OID, the parameters are absent.
* RFC 9690 Appendix B.1 and RFC 9688 Section 5.3 (``id-kdf-kdf2``, ``id-kdf-kdf3``: the hash is the AlgorithmIdentifier
  in the parameters, from the X9 hash functions SHA-1, SHA-2 and SHA-3, never SHAKE).
* RFC 8018 Appendix A.2 (``id-PBKDF2``: the pseudorandom function is in the parameters, DEFAULT HMAC-SHA-1).
* RFC 8018 Appendix B.1.1 and B.1.2 (``id-hmacWithSHA1`` to ``id-hmacWithSHA512``, pseudorandom functions of PBKDF2),
  RFC 9481 Section 6.2.1 (the SHA-2 OIDs as MAC), RFC 3370 (``hMAC-SHA1``, 1.3.6.1.5.5.8.1.2, the SHA-1 OID of a MAC),
  RFC 9688 Section 4 (HMAC with SHA-3).
* RFC 8702 Section 3.4 and RFC 9481 Section 6.2.3 (KMAC with SHAKE128/256: the SHAKE function), RFC 9044 Section 3.1 and
  RFC 9481 Section 6.2.2 (AES-GMAC with 128, 192 and 256 bit keys), RFC 8018 Section 7.1 (PBMAC1).
* RFC 3565 Section 2.3.2 and RFC 9481 Section 4.3.1 (AES key wrap with 128, 192, 256 bit KEK), RFC 5649 (AES key wrap
  with padding, the same KEK sizes).
* RFC 9481 Section 5.1 and RFC 3565 (AES-CBC), RFC 5084 (AES-GCM).
* RFC 9481 Section 4.1.2 and RFC 5753 (``dhSinglePass-stdDH``, ``dhSinglePass-cofactorDH`` and ``mqvSinglePass`` with
  SHA-224/256/384/512): the hash of the KDF is part of the OID. ``id-X25519`` and ``id-X448`` (RFC 9481 Section 4.1.2,
  RFC 8418) and ``id-alg-ESDH`` (RFC 3370) name no hash; the rows keep the SHA-256 X9.63 KDF of the callers of this
  package.
* RFC 9481 Section 4.2.1 and RFC 8017 (``rsaEncryption``, ``id-RSAES-OAEP``), RFC 4055.
"""

import csv
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import pyasn1_alt_modules.rfc3370 as rfc3370
import pyasn1_alt_modules.rfc3565 as rfc3565
import pyasn1_alt_modules.rfc5084 as rfc5084
import pyasn1_alt_modules.rfc5649 as rfc5649
import pyasn1_alt_modules.rfc5753 as rfc5753
import pyasn1_alt_modules.rfc5990 as rfc5990
import pyasn1_alt_modules.rfc8017 as rfc8017
import pyasn1_alt_modules.rfc8018 as rfc8018
import pyasn1_alt_modules.rfc8410 as rfc8410
import pyasn1_alt_modules.rfc8619 as rfc8619
import pyasn1_alt_modules.rfc9481 as rfc9481
import pyasn1_alt_modules.rfc9688 as rfc9688
from pyasn1.type import univ

OUTPUT = Path(__file__).with_name("alg_tables.tsv")

Row = Tuple[str, str, str, str, str, str, str, str, str]
_rows: List[Row] = []


def add(
    table: str,
    module: object,
    attribute: str,
    dotted: str,
    name: str,
    *,
    family: str = "",
    variant: str = "",
    hash_alg: Optional[str] = None,
    bits: Optional[int] = None,
    size: Optional[int] = None,
    prf: Optional[bool] = None,
) -> None:
    """Add one row after checking that the OID written here is the one of the RFC module."""
    constant = getattr(module, attribute)
    if univ.ObjectIdentifier(dotted) != constant:
        raise SystemExit(f"{name}: {dotted} written here, but {module.__name__}.{attribute} is {constant}")
    _rows.append(
        (
            table,
            dotted,
            name,
            family,
            variant,
            hash_alg or "",
            "" if bits is None else str(bits),
            "" if size is None else str(size),
            "" if prf is None else str(prf).lower(),
        )
    )


def _build() -> List[Row]:
    """Return every row."""
    # ---- key derivation functions -----------------------------------------------------------------------------
    for number, hash_alg in ((28, "sha256"), (29, "sha384"), (30, "sha512")):
        add(
            "kdf",
            rfc8619,
            f"id_alg_hkdf_with_{hash_alg}",
            f"1.2.840.113549.1.9.16.3.{number}",
            f"id-alg-hkdf-with-{hash_alg}",
            family="hkdf",
            hash_alg=hash_alg,
        )
    for number, hash_alg in ((32, "sha3_224"), (33, "sha3_256"), (34, "sha3_384"), (35, "sha3_512")):
        add(
            "kdf",
            rfc9688,
            f"id_alg_hkdf_with_{hash_alg}",
            f"1.2.840.113549.1.9.16.3.{number}",
            f"id-alg-hkdf-with-{hash_alg.replace('_', '-')}",
            family="hkdf",
            hash_alg=hash_alg,
        )
    add("kdf", rfc5990, "id_kdf_kdf2", "1.3.133.16.840.9.44.1.1", "id-kdf-kdf2", family="kdf2")
    add("kdf", rfc5990, "id_kdf_kdf3", "1.3.133.16.840.9.44.1.2", "id-kdf-kdf3", family="kdf3")
    add("kdf", rfc8018, "id_PBKDF2", "1.2.840.113549.1.5.12", "id-PBKDF2", family="pbkdf2")

    # ---- message authentication codes ---------------------------------------------------------------------------
    add("mac", rfc3370, "hMAC_SHA1", "1.3.6.1.5.5.8.1.2", "hMAC-SHA1", family="hmac", hash_alg="sha1", prf=False)
    add(
        "mac",
        rfc8018,
        "id_hmacWithSHA1",
        "1.2.840.113549.2.7",
        "id-hmacWithSHA1",
        family="hmac",
        hash_alg="sha1",
        prf=True,
    )
    for number, hash_alg in ((8, "sha224"), (9, "sha256"), (10, "sha384"), (11, "sha512")):
        add(
            "mac",
            rfc8018,
            f"id_hmacWithSHA{hash_alg[3:]}",
            f"1.2.840.113549.2.{number}",
            f"id-hmacWithSHA{hash_alg[3:]}",
            family="hmac",
            hash_alg=hash_alg,
            prf=True,
        )
    for number, hash_alg in ((13, "sha3_224"), (14, "sha3_256"), (15, "sha3_384"), (16, "sha3_512")):
        add(
            "mac",
            rfc9688,
            f"id_hmacWithSHA3_{hash_alg[5:]}",
            f"2.16.840.1.101.3.4.2.{number}",
            f"id-hmacWithSHA3-{hash_alg[5:]}",
            family="hmac",
            hash_alg=hash_alg,
            prf=False,
        )
    add(
        "mac",
        rfc9481,
        "id_KMACWithSHAKE128",
        "2.16.840.1.101.3.4.2.19",
        "id-KMACWithSHAKE128",
        family="kmac",
        hash_alg="shake128",
    )
    add(
        "mac",
        rfc9481,
        "id_KMACWithSHAKE256",
        "2.16.840.1.101.3.4.2.20",
        "id-KMACWithSHAKE256",
        family="kmac",
        hash_alg="shake256",
    )
    for number, bits in ((9, 128), (29, 192), (49, 256)):
        add(
            "mac",
            rfc9481,
            f"id_aes{bits}_GMAC",
            f"2.16.840.1.101.3.4.1.{number}",
            f"id-aes{bits}-GMAC",
            family="gmac",
            bits=bits,
        )
    add("mac", rfc8018, "id_PBMAC1", "1.2.840.113549.1.5.14", "id-PBMAC1", family="pbmac1")

    # ---- AES key wrap ---------------------------------------------------------------------------------------------
    for number, bits in ((5, 128), (25, 192), (45, 256)):
        add(
            "wrap",
            rfc3565,
            f"id_aes{bits}_wrap",
            f"2.16.840.1.101.3.4.1.{number}",
            f"id-aes{bits}-wrap",
            family="aes",
            variant="kw",
            size=bits // 8,
        )
    for number, bits in ((8, 128), (28, 192), (48, 256)):
        add(
            "wrap",
            rfc5649,
            f"id_aes{bits}_wrap_pad",
            f"2.16.840.1.101.3.4.1.{number}",
            f"id-aes{bits}-wrap-pad",
            family="aes",
            variant="kwp",
            size=bits // 8,
        )

    # ---- content encryption ----------------------------------------------------------------------------------------
    for number, bits in ((2, 128), (22, 192), (42, 256)):
        add(
            "content",
            rfc3565,
            f"id_aes{bits}_CBC",
            f"2.16.840.1.101.3.4.1.{number}",
            f"id-aes{bits}-CBC",
            family="aes",
            variant="cbc",
            size=bits // 8,
        )
    for number, bits in ((6, 128), (26, 192), (46, 256)):
        add(
            "content",
            rfc5084,
            f"id_aes{bits}_GCM",
            f"2.16.840.1.101.3.4.1.{number}",
            f"id-aes{bits}-GCM",
            family="aes",
            variant="gcm",
            size=bits // 8,
        )

    # ---- key agreement schemes -----------------------------------------------------------------------------------
    schemes = (
        ("stdDH", "dhSinglePass_stdDH_{}kdf_scheme", "dhSinglePass-stdDH-{}kdf-scheme", "1.3.132.1.11."),
        ("cofactorDH", "dhSinglePass_cofactorDH_{}kdf_scheme", "dhSinglePass-cofactorDH-{}kdf-scheme", "1.3.132.1.14."),
        ("mqv", "mqvSinglePass_{}kdf_scheme", "mqvSinglePass-{}kdf-scheme", "1.3.132.1.15."),
    )
    for variant, attribute, name, arc in schemes:
        for index, hash_alg in enumerate(("sha224", "sha256", "sha384", "sha512")):
            add(
                "kari",
                rfc5753,
                attribute.format(hash_alg),
                f"{arc}{index}",
                name.format(hash_alg),
                variant=variant,
                hash_alg=hash_alg,
            )
    add("kari", rfc8410, "id_X25519", "1.3.101.110", "id-X25519", variant="legacy", hash_alg="sha256")
    add("kari", rfc8410, "id_X448", "1.3.101.111", "id-X448", variant="legacy", hash_alg="sha256")
    add("kari", rfc3370, "id_alg_ESDH", "1.2.840.113549.1.9.16.3.5", "id-alg-ESDH", variant="legacy", hash_alg="sha256")

    # ---- key transport ----------------------------------------------------------------------------------------------
    add("key_transport", rfc8017, "rsaEncryption", "1.2.840.113549.1.1.1", "rsaEncryption", variant="pkcs1v15")
    add("key_transport", rfc8017, "id_RSAES_OAEP", "1.2.840.113549.1.1.7", "id-RSAES-OAEP", variant="oaep")
    return _rows


def main() -> None:
    """Write the golden file."""
    rows = _build()
    with open(OUTPUT, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(("table", "oid", "name", "family", "variant", "hash", "bits", "size", "prf"))
        writer.writerows(rows)
    sys.stderr.write(f"wrote {len(rows)} rows to {OUTPUT}\n")


if __name__ == "__main__":
    main()
