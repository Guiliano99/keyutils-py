# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=redefined-builtin  # ``format`` is cryptography's parameter name

"""Traditional signature keys that ``cryptography`` no longer provides.

``cryptography`` has deprecated DSA and will remove it in a future release. This
module keeps DSA usable by wrapping pycryptodome (already a dependency) behind
the attribute surface the ``cryptography`` key classes expose, so the rest of
the package dispatches on :class:`DSAPrivateKey` / :class:`DSAPublicKey` exactly
as it did on ``dsa.DSAPrivateKey`` / ``dsa.DSAPublicKey``:

* ``sign(data, hash_alg)`` / ``verify(signature, data, hash_alg)`` keep
  ``cryptography``'s positional order and produce / consume DER-encoded
  ``Dss-Sig-Value`` signatures (byte-compatible with ``cryptography``);
* ``private_bytes`` / ``public_bytes`` take ``cryptography``'s ``Encoding`` /
  ``PrivateFormat`` / ``PublicFormat`` enums;
* a failed verification raises :class:`cryptography.exceptions.InvalidSignature`.

Hash algorithms are named by string (``"sha256"``) like everywhere else in the
package; a ``cryptography`` :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
instance is also accepted so callers written against the old class keep working.
"""

from __future__ import annotations

from typing import Any, Union

from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    KeySerializationEncryption,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from keyutils_py.keys.key_pyasn1_utils import encrypt_private_key_pkcs8_pem

__all__ = ["DSAPrivateKey", "DSAPublicKey", "to_pycryptodome_hash"]

HashAlg = Union[str, hashes.HashAlgorithm]

# The hashes FIPS 186-4 approves for DSA.
_PYCRYPTODOME_HASHES = {
    "sha1": SHA1,
    "sha224": SHA224,
    "sha256": SHA256,
    "sha384": SHA384,
    "sha512": SHA512,
}


def to_pycryptodome_hash(hash_alg: HashAlg, data: bytes) -> Any:
    """Return a pycryptodome hash object over ``data`` for ``hash_alg``.

    :param hash_alg: Hash name (``"sha256"``) or a ``cryptography`` hash instance
        (``hashes.SHA256()``); an instance is reduced to its ``name``.
    :param data: The bytes to hash.
    :raises ValueError: If the hash is not one DSA may use (SHA-1 / SHA-2 family).
    """
    name = hash_alg.name if isinstance(hash_alg, hashes.HashAlgorithm) else hash_alg
    try:
        return _PYCRYPTODOME_HASHES[name.lower()].new(data)
    except KeyError as err:
        raise ValueError(f"Unsupported hash algorithm for DSA: {name!r}") from err


def _pem_with_newline(pem: bytes) -> bytes:
    # pycryptodome omits the trailing newline that ``cryptography`` always emits.
    return pem if pem.endswith(b"\n") else pem + b"\n"


class DSAPublicKey:
    """DSA public key backed by pycryptodome, mirroring ``dsa.DSAPublicKey``."""

    def __init__(self, key: DSA.DsaKey) -> None:
        """Wrap a pycryptodome public ``DsaKey``.

        :raises ValueError: If ``key`` carries a private component.
        """
        if key.has_private():
            raise ValueError("DSAPublicKey requires a public pycryptodome key; use DSAPrivateKey.")
        self._key = key

    @classmethod
    def load(cls, data: bytes) -> DSAPublicKey:
        """Load a public key from PEM or DER ``SubjectPublicKeyInfo`` bytes."""
        return cls(DSA.import_key(data))

    @property
    def key_size(self) -> int:
        """Bit length of the prime modulus ``p`` (as ``cryptography`` reports it)."""
        return int(self._key.p).bit_length()

    # ponytail: the integers are exposed directly instead of cryptography's
    # DSAPublicNumbers / DSAParameterNumbers; nothing in the package reads those.
    @property
    def p(self) -> int:
        """Prime modulus."""
        return int(self._key.p)

    @property
    def q(self) -> int:
        """Sub-group order."""
        return int(self._key.q)

    @property
    def g(self) -> int:
        """Generator."""
        return int(self._key.g)

    @property
    def y(self) -> int:
        """Public value ``g^x mod p``."""
        return int(self._key.y)

    def verify(self, signature: bytes, data: bytes, hash_alg: HashAlg = "sha256") -> None:
        """Verify a DER-encoded ``Dss-Sig-Value`` ``signature`` over ``data``.

        :raises InvalidSignature: If the signature does not verify.
        :raises ValueError: If ``hash_alg`` is not usable with DSA.
        """
        digest = to_pycryptodome_hash(hash_alg, data)
        try:
            DSS.new(self._key, "fips-186-3", encoding="der").verify(digest, signature)
        except ValueError as err:
            raise InvalidSignature(str(err)) from err

    def public_bytes(
        self,
        encoding: Encoding = Encoding.PEM,
        format: PublicFormat = PublicFormat.SubjectPublicKeyInfo,
    ) -> bytes:
        """Serialise as ``SubjectPublicKeyInfo`` (DER or PEM).

        :raises ValueError: For unsupported encoding / format combinations.
        """
        if format != PublicFormat.SubjectPublicKeyInfo:
            raise ValueError(f"Unsupported format for DSA public key: {format}")
        if encoding == Encoding.DER:
            return self._key.export_key(format="DER")
        if encoding == Encoding.PEM:
            return _pem_with_newline(self._key.export_key(format="PEM"))
        raise ValueError(f"Unsupported encoding: {encoding}")

    def __eq__(self, other: object) -> bool:
        """Return True if ``other`` is a DSA public key with the same numbers."""
        if not isinstance(other, DSAPublicKey):
            return NotImplemented
        return (self.p, self.q, self.g, self.y) == (other.p, other.q, other.g, other.y)

    def __hash__(self) -> int:
        """Hash on the public numbers."""
        return hash((self.p, self.q, self.g, self.y))


class DSAPrivateKey:
    """DSA private key backed by pycryptodome, mirroring ``dsa.DSAPrivateKey``."""

    def __init__(self, key: DSA.DsaKey) -> None:
        """Wrap a pycryptodome private ``DsaKey``.

        :raises ValueError: If ``key`` has no private component.
        """
        if not key.has_private():
            raise ValueError("DSAPrivateKey requires a private pycryptodome key; use DSAPublicKey.")
        self._key = key

    @classmethod
    def generate(cls, key_size: int = 2048) -> DSAPrivateKey:
        """Generate a fresh key.

        :param key_size: Modulus length in bits; pycryptodome accepts the FIPS 186-4
            sizes 1024, 2048 and 3072 only and pairs them with N = 160 / 224 / 256
            (``cryptography`` generated 2048-bit keys with N = 256).
        :raises ValueError: For any other size.
        """
        return cls(DSA.generate(key_size))

    @classmethod
    def load(cls, data: bytes, password: str | bytes | None = None) -> DSAPrivateKey:
        """Load a private key from PEM or DER (PKCS#8 or ``DSA PRIVATE KEY``) bytes.

        :param data: The serialised key.
        :param password: Passphrase for an ``ENCRYPTED PRIVATE KEY`` (PBES2) block.
        """
        return cls(DSA.import_key(data, passphrase=password))

    @property
    def key_size(self) -> int:
        """Bit length of the prime modulus ``p`` (as ``cryptography`` reports it)."""
        return int(self._key.p).bit_length()

    @property
    def x(self) -> int:
        """Private value."""
        return int(self._key.x)

    def public_key(self) -> DSAPublicKey:
        """Return the matching public key."""
        return DSAPublicKey(self._key.public_key())

    def sign(self, data: bytes, hash_alg: HashAlg = "sha256") -> bytes:
        """Sign ``data`` and return a DER-encoded ``Dss-Sig-Value``.

        :raises ValueError: If ``hash_alg`` is not usable with DSA.
        """
        digest = to_pycryptodome_hash(hash_alg, data)
        return DSS.new(self._key, "fips-186-3", encoding="der").sign(digest)

    def private_bytes(
        self,
        encoding: Encoding = Encoding.PEM,
        format: PrivateFormat = PrivateFormat.PKCS8,
        encryption_algorithm: KeySerializationEncryption = NoEncryption(),
    ) -> bytes:
        """Serialise the private key (PKCS#8 or ``TraditionalOpenSSL``, DER or PEM).

        Encryption (``BestAvailableEncryption``) is supported for PKCS#8 PEM only
        and uses the package's PBES2 writer, matching every other key type.

        :raises ValueError: For unsupported format / encoding / encryption combinations.
        """
        if format not in (PrivateFormat.PKCS8, PrivateFormat.TraditionalOpenSSL):
            raise ValueError(f"Unsupported format for DSA private key: {format}")
        pkcs8 = format == PrivateFormat.PKCS8
        # Fail closed: an unknown encryption type must never fall through to plaintext output.
        if not isinstance(encryption_algorithm, (NoEncryption, BestAvailableEncryption)):
            raise ValueError(f"Unsupported encryption for DSA private key: {encryption_algorithm!r}")
        encrypted = not isinstance(encryption_algorithm, NoEncryption)
        if encrypted and not (encoding == Encoding.PEM and pkcs8):
            raise ValueError("Encryption is only supported for PKCS8 PEM encoding.")

        if encoding == Encoding.DER:
            return self._key.export_key(format="DER", pkcs8=pkcs8)
        if encoding == Encoding.PEM:
            if isinstance(encryption_algorithm, BestAvailableEncryption):
                return encrypt_private_key_pkcs8_pem(
                    private_key_der=self._key.export_key(format="DER", pkcs8=True),
                    password=encryption_algorithm.password,
                )
            return _pem_with_newline(self._key.export_key(format="PEM", pkcs8=pkcs8))
        raise ValueError(f"Unsupported encoding: {encoding}")
