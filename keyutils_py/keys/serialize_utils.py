# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Utility functions for serializing traditional keys."""

from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5915, rfc8017

from keyutils_py.oids import CURVE_NAME_2_OID
from keyutils_py.utils import encode_to_der


def prepare_rsa_private_key(rsa_key: rsa.RSAPrivateKey, add_to_n: bool = False) -> bytes:
    """Prepare an RSA private key for DER encoding as RSAPrivateKey."""
    private_nums = rsa_key.private_numbers()
    n = private_nums.public_numbers.n
    if add_to_n:
        n += 1

    rsa_asn1_key = rfc8017.RSAPrivateKey()
    rsa_asn1_key["version"] = 0
    rsa_asn1_key["modulus"] = n
    rsa_asn1_key["publicExponent"] = private_nums.public_numbers.e
    rsa_asn1_key["privateExponent"] = private_nums.d
    rsa_asn1_key["prime1"] = private_nums.p
    rsa_asn1_key["prime2"] = private_nums.q
    rsa_asn1_key["exponent1"] = private_nums.dmp1
    rsa_asn1_key["exponent2"] = private_nums.dmq1
    rsa_asn1_key["coefficient"] = private_nums.iqmp
    return encode_to_der(rsa_asn1_key)


def ecc_private_key_to_bytes(ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Convert an EC private key to big-endian bytes."""
    private_nums = ec_key.private_numbers()
    return private_nums.private_value.to_bytes((private_nums.private_value.bit_length() + 7) // 8, "big")


def prepare_ec_private_key(
    ec_key: ec.EllipticCurvePrivateKey, private_key_bytes: Optional[bytes] = None
) -> rfc5915.ECPrivateKey:
    """Prepare an EC private key for ASN.1 encoding."""
    ec_private_key = rfc5915.ECPrivateKey()
    ec_private_key["version"] = 1

    private_key_bytes = private_key_bytes or ecc_private_key_to_bytes(ec_key)
    ec_private_key["privateKey"] = private_key_bytes
    curve_oid = CURVE_NAME_2_OID[ec_key.curve.name.lower()]
    ec_private_key["parameters"]["namedCurve"] = curve_oid

    public_key = ec_key.public_key()
    public_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    ec_private_key["publicKey"] = univ.BitString(hexValue=public_bytes.hex()).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
    )
    return ec_private_key
