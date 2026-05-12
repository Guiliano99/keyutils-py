# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# Originally written for the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
# Ported from branch:
#   https://github.com/Guiliano99/cmp-test-suite-update-code/tree/AddKeySecStrengthCheck

"""Security-related utilities (key bit-strength estimation).

Estimates security strength in bits for traditional, PQ, stateful-hash, and
hybrid keys. Mappings follow NIST SP 800-57 Part 1 Rev. 5 Tables 2 and 4.
"""

from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric import dsa, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from keyutils_py.keys.abstract_pq import PQKEMPublicKey, PQSignaturePublicKey
from keyutils_py.keys.abstract_stateful_hash_sig import PQHashStatefulSigPublicKey
from keyutils_py.keys.abstract_wrapper_keys import HybridPublicKey, TradKEMPublicKey
from keyutils_py.keys.stateful_sig_keys import HSSPublicKey, XMSSMTPublicKey, XMSSPublicKey
from keyutils_py.types import PrivateKey, PublicKey

# Security strength values follow NIST SP 800-57 Part 1 Revision 5, Tables 2 and 4.
# Table 2 provides the traditional key equivalence for RSA/DSA and ECC key sizes,
# while Table 4 lists the target security strengths for the NIST PQC levels.
_NIST_LEVEL_TO_STRENGTH = {
    1: 128,
    2: 192,
    3: 192,
    4: 256,
    5: 256,
}

HASH_ALG_TO_STRENGTH = {
    "sha1": 80,
    "sha224": 112,
    "sha256": 128,
    "sha384": 192,
    "sha512": 256,
    "sha3_224": 112,
    "sha3_256": 128,
    "sha3_384": 192,
    "sha3_512": 256,
    "shake128": 128,  # 32-byte output in CMP per RFC 9481.
    "shake256": 256,  # 64-byte output in CMP per RFC 9481.
}


# Concrete private-key classes that own a ``.public_key()`` method.
# Used in place of ``isinstance(key, PrivateKey)`` because ``PrivateKey`` is a
# ``typing.Union`` alias and unions can't be used with ``isinstance``.
_TRAD_PRIVATE_KEY_TYPES = (
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
)


def _rsa_security_strength(key_size: int) -> int:
    """Return an approximate security strength (in bits) for an RSA / DSA key size.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 2.
    """
    if key_size < 1024:
        return 64
    if key_size <= 1024:
        return 80
    if key_size <= 2048:
        return 112
    if key_size <= 3072:
        return 128
    if key_size <= 7680:
        return 192
    if key_size <= 15360:
        return 256
    return 256


def _ecc_security_strength(key_size: int) -> int:
    """Return the security strength (in bits) for an ECC curve size.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 2.

    ``f`` is the field size in bits:

    * f = 160–223 → 80
    * f = 224–255 → 112
    * f = 256–383 → 128
    * f = 384–511 → 192
    * f ≥ 512 → 256
    """
    if key_size <= 223:
        return 80
    if key_size <= 255:
        return 112
    if key_size <= 383:
        return 128
    if key_size <= 511:
        return 192
    return 256


def _get_pq_stfl_nist_security_strength(key: PQHashStatefulSigPublicKey) -> int:
    """Return the PQ security strength (in bits) for a stateful-hash signature key.

    XMSS / XMSS^MT security strength is determined by the hash output size
    (RFC 8391 §5; halved for Grover). HSS strength is set by the LMS
    parameter set.
    """
    if isinstance(key, (XMSSPublicKey, XMSSMTPublicKey, HSSPublicKey)):
        return key.key_bit_security
    raise NotImplementedError(
        f"Security strength estimation is only implemented for XMSS, XMSSMT and HSS stateful-hash keys. "
        f"Got: {type(key).__name__}"
    )


def _nist_level_strength(level: Optional[int]) -> int:
    """Convert a claimed NIST PQC level into an approximate security strength.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 4. Returns ``0`` for
    ``None`` / unknown levels.
    """
    if level is None:
        return 0
    return _NIST_LEVEL_TO_STRENGTH.get(int(level), 0)


def estimate_key_security_strength(key: Union[PrivateKey, PublicKey]) -> int:
    """Estimate the security strength of ``key`` in bits.

    Public-key derivation: if ``key`` is a private key, its public side is
    used. Supports traditional (RSA / DSA / ECC / Ed25519 / Ed448 /
    X25519 / X448), PQ (ML-DSA / ML-KEM / SLH-DSA / Falcon / FrodoKEM /
    McEliece / SNTRUP761), stateful-hash (HSS / XMSS / XMSSMT), and hybrid
    keys (composite-sig / composite-kem / chempat / xwing).

    For hybrid keys, the strength is the minimum of the PQ and traditional
    components — the conservative "Grover-aware" estimate.

    :raises NotImplementedError: for unsupported key types.
    """
    # If it's a private key we can extract the public key from, do so first.
    if isinstance(key, _TRAD_PRIVATE_KEY_TYPES) or hasattr(key, "public_key"):
        try:
            key = key.public_key()  # type: ignore[union-attr]
        except (AttributeError, TypeError):
            pass

    if isinstance(key, PQHashStatefulSigPublicKey):
        return _get_pq_stfl_nist_security_strength(key)

    if isinstance(key, (PQKEMPublicKey, PQSignaturePublicKey)):
        return _nist_level_strength(key.nist_level)

    if hasattr(key, "nist_level"):
        return _nist_level_strength(getattr(key, "nist_level"))

    if isinstance(key, rsa.RSAPublicKey):
        return _rsa_security_strength(key.key_size)
    if isinstance(key, dsa.DSAPublicKey):
        return _rsa_security_strength(key.key_size)
    if isinstance(key, EllipticCurvePublicKey):
        return _ecc_security_strength(key.curve.key_size)

    if isinstance(key, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey)):
        return 128
    if isinstance(key, (ed448.Ed448PublicKey, x448.X448PublicKey)):
        return 224

    if isinstance(key, TradKEMPublicKey):
        # TradKEMPublicKey wraps a cryptography traditional public key.
        return estimate_key_security_strength(key._public_key)  # pylint: disable=protected-access

    if isinstance(key, HybridPublicKey):
        pq_strength = estimate_key_security_strength(getattr(key, "pq_key"))
        trad_strength = estimate_key_security_strength(getattr(key, "trad_key"))
        return min(pq_strength, trad_strength)

    raise NotImplementedError(f"Security strength estimation not implemented for key type: {type(key).__name__}")


__all__ = [
    "estimate_key_security_strength",
    "HASH_ALG_TO_STRENGTH",
]
