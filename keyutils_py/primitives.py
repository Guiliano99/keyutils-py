# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""The lower layer: keyless, by-name cryptographic functions.

Every function takes the names of its hash (``"sha256"``, ``"sha3_256"``; the names of the hash registry of
:mod:`keyutils_py.oids`, SHAKE excluded) and plain byte strings. Nothing here reads an ``AlgorithmIdentifier``, an OID
or a table, and nothing checks that a key size fits an algorithm identifier: that is the work of
:mod:`keyutils_py.mechanisms`, which resolves an identifier to a call of this module. A function of this module is
therefore the way to produce what a mechanism refuses on purpose, for example a key wrap whose KEK does not match the
identifier that is written next to it, and the way to check a mechanism against an independent computation.

The module imports ``cryptography``, ``pycryptodome`` (for KMAC) and :mod:`keyutils_py.exceptions` only, which a test
checks. It is importable but not part of the public API (:data:`keyutils_py.__all__`).

Errors: a hash name that is no fixed-output hash is :class:`~keyutils_py.exceptions.BadAlg`; an unwrap, a CBC padding or
a GCM tag that does not verify is :class:`~keyutils_py.exceptions.IntegrityError`, with a message that does not say
why. A wrong size of a key, nonce or output is the ``ValueError`` of the library underneath.
"""

from typing import Callable, Dict, Optional, Tuple

from Crypto.Hash import KMAC128, KMAC256
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap,
    aes_key_wrap_with_padding,
)

from keyutils_py.exceptions import BadAlg, IntegrityError

# The fixed-output hashes that HMAC, HKDF, KDF2, KDF3 and PBKDF2 can use, by the names of the hash registry.
_HASHES: Dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha3_224": hashes.SHA3_224,
    "sha3_256": hashes.SHA3_256,
    "sha3_384": hashes.SHA3_384,
    "sha3_512": hashes.SHA3_512,
}

_KMAC = {"shake128": KMAC128, "shake256": KMAC256}

_BLOCK_BITS = 128  # the AES block size, for the PKCS#7 padding


def _hash(hash_alg: str) -> hashes.HashAlgorithm:
    """Return a ``cryptography`` hash for a registry name.

    :raises BadAlg: If the name is unknown or names a SHAKE function.
    """
    try:
        return _HASHES[hash_alg]()
    except (KeyError, TypeError):
        raise BadAlg(f"{hash_alg!r} is not a fixed-output hash that this function can use.") from None


def _check_length(length: int) -> None:
    """Raise ``ValueError`` for a negative output length, which the libraries underneath report as an overflow."""
    if length < 0:
        raise ValueError("The output length must not be negative.")


def hkdf(hash_alg: str, ikm: bytes, length: int, info: bytes = b"", salt: Optional[bytes] = None) -> bytes:
    """Derive ``length`` octets with HKDF (RFC 5869); without ``salt`` the extract step uses a zero salt."""
    _check_length(length)
    return HKDF(algorithm=_hash(hash_alg), length=length, salt=salt, info=info).derive(ikm)


def kdf2(hash_alg: str, z: bytes, length: int, info: bytes = b"") -> bytes:
    """Derive ``length`` octets with KDF2, the X9.63 KDF: ``Hash(Z || counter || info)``, counter from 1."""
    _check_length(length)
    return X963KDF(algorithm=_hash(hash_alg), length=length, sharedinfo=info).derive(z)


def kdf3(hash_alg: str, z: bytes, length: int, info: bytes = b"") -> bytes:
    """Derive ``length`` octets with KDF3 (RFC 9690 Appendix B.1): ``Hash(counter || Z || info)``, counter from 1.

    :raises ValueError: If ``length`` is negative or needs more than ``2**32 - 1`` blocks.
    """
    algorithm = _hash(hash_alg)
    _check_length(length)
    blocks = -(-length // algorithm.digest_size)
    if blocks >= 2**32:
        raise ValueError("The length needs more than 2**32 - 1 blocks.")
    out = b""
    for counter in range(1, blocks + 1):
        digest = hashes.Hash(algorithm)
        digest.update(counter.to_bytes(4, "big") + z + info)
        out += digest.finalize()
    return out[:length]


def pbkdf2(hash_alg: str, password: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    """Derive ``length`` octets with PBKDF2-HMAC (RFC 8018 Section 5.2)."""
    _check_length(length)
    return PBKDF2HMAC(algorithm=_hash(hash_alg), length=length, salt=salt, iterations=iterations).derive(password)


def hmac_digest(hash_alg: str, key: bytes, data: bytes) -> bytes:
    """Return the HMAC of ``data`` under ``key`` (RFC 2104), with the full output of the hash."""
    mac = hmac.HMAC(key, _hash(hash_alg))
    mac.update(data)
    return mac.finalize()


def kmac(shake: str, key: bytes, data: bytes, *, mac_len: int, custom: bytes = b"") -> bytes:
    """Return KMAC128 (``shake="shake128"``) or KMAC256 (``"shake256"``) of NIST SP 800-185 with ``mac_len`` octets.

    :raises BadAlg: If ``shake`` is neither of the two names.
    :raises ValueError: If the key is shorter than the security strength (16 octets for KMAC128, 32 for KMAC256) or
        ``mac_len`` is below 8 octets, the limits of ``pycryptodome``. The package adds none.
    """
    if shake not in _KMAC:
        raise BadAlg(f"KMAC is defined over shake128 and shake256, not {shake!r}.")
    return _KMAC[shake].new(key=key, data=data, mac_len=mac_len, custom=custom).digest()


def gmac(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Return the 16 octet AES-GMAC tag of ``data`` (AES-GCM over no plaintext, RFC 9044 Section 4).

    :raises ValueError: If the key is no AES key or the nonce is not 8 to 128 octets (the limit of ``cryptography``).
    """
    return AESGCM(key).encrypt(nonce, b"", data)


def aes_kw_wrap(kek: bytes, key: bytes) -> bytes:
    """Wrap ``key`` with AES key wrap (RFC 3394); ``key`` must be a multiple of 8 octets, at least 16."""
    return aes_key_wrap(kek, key)


def aes_kw_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """Unwrap with AES key wrap (RFC 3394).

    :raises IntegrityError: If the check value does not verify or the wrapped key has an impossible size.
    """
    try:
        return aes_key_unwrap(kek, wrapped)
    except InvalidUnwrap:
        raise IntegrityError("AES key unwrap failed.") from None


def aes_kwp_wrap(kek: bytes, key: bytes) -> bytes:
    """Wrap ``key`` with AES key wrap with padding (RFC 5649); ``key`` may have any size from 1 octet."""
    return aes_key_wrap_with_padding(kek, key)


def aes_kwp_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """Unwrap with AES key wrap with padding (RFC 5649).

    :raises IntegrityError: If the check value or the padding does not verify or the wrapped key has an impossible size.
    """
    try:
        return aes_key_unwrap_with_padding(kek, wrapped)
    except InvalidUnwrap:
        raise IntegrityError("AES key unwrap failed.") from None


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-CBC and PKCS#7 padding; the IV must have 16 octets."""
    padder = padding.PKCS7(_BLOCK_BITS).padder()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padder.update(plaintext) + padder.finalize()) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-CBC and remove the PKCS#7 padding.

    :raises IntegrityError: If the length is no multiple of the block size or the padding is wrong; both give the
        same message.
    """
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(_BLOCK_BITS).unpadder()
    try:
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise IntegrityError("AES-CBC decryption failed.") from None


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Encrypt with AES-GCM and return ``(ciphertext, 16 octet tag)``."""
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return sealed[: len(plaintext)], sealed[len(plaintext) :]


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: Optional[bytes] = None) -> bytes:
    """Decrypt AES-GCM; ``tag`` may be truncated (4 to 16 octets) and is then compared at its own length.

    :raises IntegrityError: If the tag does not verify.
    """
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag, min_tag_length=len(tag))).decryptor()
    if aad is not None:
        decryptor.authenticate_additional_data(aad)
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise IntegrityError("AES-GCM decryption failed.") from None
