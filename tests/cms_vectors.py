# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Helpers of the tests that read CMS ``EnvelopedData`` vectors from ``tests/vectors``."""

from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5652

VECTORS = Path(__file__).with_name("vectors")


def load_enveloped_data(name: str) -> rfc5652.EnvelopedData:
    """Return the ``EnvelopedData`` of the DER ``ContentInfo`` file ``tests/vectors/<name>``."""
    content_info, rest = decoder.decode((VECTORS / name).read_bytes(), asn1Spec=rfc5652.ContentInfo())
    assert not rest
    enveloped, rest = decoder.decode(content_info["content"].asOctets(), asn1Spec=rfc5652.EnvelopedData())
    assert not rest
    return enveloped


def load_private_key(name: str) -> rsa.RSAPrivateKey:
    """Return the RSA private key of the PEM file ``tests/vectors/<name>``."""
    key = serialization.load_pem_private_key((VECTORS / name).read_bytes(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key


def key_transport_recipient(name: str) -> Tuple[object, bytes, object]:
    """Return ``(keyEncryptionAlgorithm, encryptedKey, EncryptedContentInfo)`` of the first KTRI of a vector file."""
    enveloped = load_enveloped_data(name)
    ktri = enveloped["recipientInfos"][0]["ktri"]
    return ktri["keyEncryptionAlgorithm"], ktri["encryptedKey"].asOctets(), enveloped["encryptedContentInfo"]
