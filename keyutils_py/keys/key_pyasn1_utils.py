# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Encrypt / decrypt PKCS#8 private keys (PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA256).

Trimmed copy of ``cmp-test-suite/pq_logic/keys/key_pyasn1_utils.py``: the
Robot Framework decorators are dropped, and the dependency on
``resources.prepare_alg_ids`` is replaced by inline AlgorithmIdentifier
construction.
"""

import base64
import os
import textwrap

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3565, rfc5208, rfc8018, rfc9480

from keyutils_py.utils import encode_to_der, try_decode_pyasn1

CUSTOM_KEY_TYPES = [
    b"BASE",
    b"PQ",
    b"XMSS",
    b"XMSSMT",
    b"HSS",
]


def _compute_aes_cbc(key: bytes, data: bytes, iv: bytes, decrypt: bool = True) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long for AES-CBC.")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    block_size: int = algorithms.AES.block_size  # type: ignore[assignment]

    if decrypt:
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        unpadder = aes_padding.PKCS7(block_size).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()

    padder = aes_padding.PKCS7(block_size).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _build_pbkdf2_alg_id(salt: bytes, iterations: int, key_length: int) -> rfc9480.AlgorithmIdentifier:
    hmac_alg_id = rfc9480.AlgorithmIdentifier()
    hmac_alg_id["algorithm"] = rfc8018.id_hmacWithSHA256
    hmac_alg_id["parameters"] = univ.Any(encode_to_der(univ.Null("")))

    pbkdf2_params = rfc8018.PBKDF2_params()
    pbkdf2_params["salt"]["specified"] = univ.OctetString(salt)
    pbkdf2_params["iterationCount"] = iterations
    pbkdf2_params["keyLength"] = key_length
    pbkdf2_params["prf"] = hmac_alg_id

    alg_id = rfc9480.AlgorithmIdentifier()
    alg_id["algorithm"] = rfc8018.id_PBKDF2
    alg_id["parameters"] = univ.Any(encode_to_der(pbkdf2_params))
    return alg_id


def encrypt_private_key_pkcs8(
    private_key_der: bytes,
    password: str | bytes,
    iterations: int = 600000,
    salt_length: int = 16,
    iv_length: int = 16,
) -> bytes:
    """Encrypt ``private_key_der`` using PKCS#8 PBES2 with AES-256-CBC and PBKDF2-HMAC-SHA256."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not password:
        raise ValueError("Password must not be empty.")
    if iv_length != 16:
        raise ValueError("IV length must be 16 bytes for AES-CBC.")

    salt = os.urandom(salt_length)
    iv = os.urandom(iv_length)

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    encryption_key = kdf.derive(password)

    encrypted = _compute_aes_cbc(key=encryption_key, data=private_key_der, iv=iv, decrypt=False)

    enc_scheme = rfc9480.AlgorithmIdentifier()
    enc_scheme["algorithm"] = rfc3565.id_aes256_CBC
    enc_scheme["parameters"] = univ.Any(encode_to_der(univ.OctetString(iv)))

    pbes2_params = rfc8018.PBES2_params()
    pbes2_params["keyDerivationFunc"] = _build_pbkdf2_alg_id(salt, iterations, 32)
    pbes2_params["encryptionScheme"] = enc_scheme

    pbes2_alg_id = rfc9480.AlgorithmIdentifier()
    pbes2_alg_id["algorithm"] = rfc8018.id_PBES2
    pbes2_alg_id["parameters"] = univ.Any(encode_to_der(pbes2_params))

    enc_pki = rfc5208.EncryptedPrivateKeyInfo()
    enc_pki["encryptionAlgorithm"] = pbes2_alg_id
    enc_pki["encryptedData"] = univ.OctetString(encrypted)
    return encode_to_der(enc_pki)


def encrypt_private_key_pkcs8_pem(
    private_key_der: bytes,
    password: str | bytes,
    iterations: int = 600000,
    salt_length: int = 16,
    iv_length: int = 16,
) -> bytes:
    """Encrypt and PEM-armor the result of :func:`encrypt_private_key_pkcs8`."""
    encrypted_der = encrypt_private_key_pkcs8(
        private_key_der=private_key_der,
        password=password,
        iterations=iterations,
        salt_length=salt_length,
        iv_length=iv_length,
    )
    body = "\n".join(textwrap.wrap(base64.b64encode(encrypted_der).decode("ascii"), 64))
    pem = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{body}\n-----END ENCRYPTED PRIVATE KEY-----\n"
    return pem.encode("ascii")


def decrypt_private_key_pkcs8(encrypted_der: bytes, password: str | bytes) -> bytes:
    """Decrypt a DER-encoded EncryptedPrivateKeyInfo (PBES2 / AES-256-CBC / PBKDF2-HMAC-SHA256)."""
    if isinstance(password, str):
        password = password.encode("utf-8")

    enc_pki, rest = try_decode_pyasn1(encrypted_der, rfc5208.EncryptedPrivateKeyInfo())
    if rest:
        raise ValueError("Trailing data after EncryptedPrivateKeyInfo.")

    enc_alg = enc_pki["encryptionAlgorithm"]
    if enc_alg["algorithm"] != rfc8018.id_PBES2:
        raise ValueError(f"Unsupported encryption algorithm: {enc_alg['algorithm']}. Expected PBES2.")

    pbes2_params, _ = try_decode_pyasn1(enc_alg["parameters"], rfc8018.PBES2_params())

    kdf_alg = pbes2_params["keyDerivationFunc"]
    if kdf_alg["algorithm"] != rfc8018.id_PBKDF2:
        raise ValueError(f"Unsupported KDF: {kdf_alg['algorithm']}. Expected PBKDF2.")

    pbkdf2_params, _ = try_decode_pyasn1(kdf_alg["parameters"], rfc8018.PBKDF2_params())
    salt = bytes(pbkdf2_params["salt"]["specified"])
    iterations = int(pbkdf2_params["iterationCount"])
    key_length = int(pbkdf2_params["keyLength"]) if pbkdf2_params["keyLength"].isValue else 32

    enc_scheme = pbes2_params["encryptionScheme"]
    if enc_scheme["algorithm"] != rfc3565.id_aes256_CBC:
        raise ValueError(f"Unsupported encryption scheme: {enc_scheme['algorithm']}. Expected AES-256-CBC.")
    iv_asn1, _ = try_decode_pyasn1(enc_scheme["parameters"], univ.OctetString())
    iv = bytes(iv_asn1)

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_length, salt=salt, iterations=iterations)
    decryption_key = kdf.derive(password)

    encrypted_data = bytes(enc_pki["encryptedData"])
    return _compute_aes_cbc(key=decryption_key, data=encrypted_data, iv=iv, decrypt=True)


def decrypt_private_key_pkcs8_pem(pem_data: bytes, password: str | bytes) -> bytes:
    """Decrypt a PEM-armoured ``ENCRYPTED PRIVATE KEY`` block."""
    lines = pem_data.splitlines()
    b64_lines = []
    in_block = False
    for line in lines:
        if line.strip() == b"-----BEGIN ENCRYPTED PRIVATE KEY-----":
            in_block = True
            continue
        if line.strip() == b"-----END ENCRYPTED PRIVATE KEY-----":
            break
        if in_block:
            b64_lines.append(line.strip())

    encrypted_der = base64.b64decode(b"".join(b64_lines))
    return decrypt_private_key_pkcs8(encrypted_der, password)


def load_enc_key(password: str | bytes, data: bytes) -> bytes:
    """Decrypt a PEM-armoured PKCS#8 ``ENCRYPTED PRIVATE KEY`` and return DER bytes.

    Only the modern PKCS#8 EncryptedPrivateKeyInfo format is supported in this
    slim copy. The legacy ``Proc-Type/DEK-Info`` format used by older
    cmp-test-suite keys is not supported here — write a fresh PEM with the
    new format if you encounter one.
    """
    lines = data.splitlines()
    if not lines:
        raise ValueError("Empty PEM data.")
    if lines[0].rstrip() != b"-----BEGIN ENCRYPTED PRIVATE KEY-----":
        raise ValueError(
            "Only PKCS#8 EncryptedPrivateKeyInfo PEM is supported (expected `-----BEGIN ENCRYPTED PRIVATE KEY-----`)."
        )
    return decrypt_private_key_pkcs8_pem(data, password)
