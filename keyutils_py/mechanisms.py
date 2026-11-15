# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Mechanisms: the operations that an ``AlgorithmIdentifier`` selects.

A function here takes the identifier as it is, or will be, written in the structure under test (``AlgId`` is
``rfc5280.AlgorithmIdentifier``), looks its OID up in the tables of :mod:`keyutils_py._algs`, reads and checks the
parameters, and calls the keyless function of :mod:`keyutils_py.primitives` that the row names. The identifier that is
passed in and the identifier that a caller writes next to the result are two separate statements, so a test makes a
mismatch on purpose by passing the one and writing the other; no function has a flag for it.

A mechanism validates what it applies, and is strict about it as a receiver:

* an OID that is in no table is :class:`~keyutils_py.exceptions.BadAlg`,
* parameters that are absent, present where they must be absent, or inconsistent with the OID or the other arguments
  are :class:`~keyutils_py.exceptions.BadAlgParams` (trailing data after the parameters included),
* parameters that cannot be decoded are :class:`~keyutils_py.exceptions.BadAsn1Data`,
* a value that does not verify (an unwrap, a MAC) is :class:`~keyutils_py.exceptions.IntegrityError`,
* an argument of the wrong type is a ``TypeError``.

Parameters are read once, against the specification of the algorithm, from DER bytes (``univ.Any``) or from an
already decoded object of that specification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from pyasn1.codec.der import encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc8018, rfc9480

from keyutils_py import primitives
from keyutils_py._algs import KDF_BY_OID, MAC_BY_OID, KdfRow
from keyutils_py.asn1utils import try_decode_pyasn1
from keyutils_py.exceptions import BadAlg, BadAlgParams, BadAsn1Data
from keyutils_py.keys.key_pyasn1_utils import MAX_PBKDF2_ITERATIONS
from keyutils_py.oids import _HASH_OID_2_NAME, _is_parameters_null

__all__ = ["kdf_derive"]

AlgId = rfc9480.AlgorithmIdentifier

# The hashes whose AlgorithmIdentifier carries NULL or no parameters (RFC 5754 Section 2); SHA-3 must have none
# (RFC 9688 Section 2).
_HASHES_WITH_NULL = ("sha1", "sha224", "sha256", "sha384", "sha512")
# The hash functions of the X9 KDFs: SHA-1, SHA-2 and SHA-3, never SHAKE (RFC 9688 Section 5.3, RFC 9690 Appendix B).
_X9_HASHES = (*_HASHES_WITH_NULL, "sha3_224", "sha3_256", "sha3_384", "sha3_512")


# ---------------------------------------------------------------------------------------------------------------
# Reading an AlgorithmIdentifier
# ---------------------------------------------------------------------------------------------------------------


def _check_alg_id(alg_id: Any, what: str) -> None:
    """Raise ``TypeError`` unless ``alg_id`` is an ``AlgorithmIdentifier``, ``BadAlg`` if it names no OID."""
    if not isinstance(alg_id, univ.Sequence):
        raise TypeError(f"The {what} must be an AlgorithmIdentifier, not {type(alg_id).__name__}.")
    if not alg_id["algorithm"].isValue:
        raise BadAlg(f"The AlgorithmIdentifier of the {what} has no OID.")


def _row(index: Any, alg_id: Any, what: str) -> Any:
    """Return the table row of the OID of ``alg_id``.

    :raises TypeError: If ``alg_id`` is no AlgorithmIdentifier.
    :raises BadAlg: If it has no OID or the OID is in no table.
    """
    _check_alg_id(alg_id, what)
    try:
        return index[alg_id["algorithm"]]
    except KeyError:
        raise BadAlg(f"{alg_id['algorithm']} is not a known {what}.") from None


def _require_absent(alg_id: Any, what: str) -> None:
    """Raise ``BadAlgParams`` if the identifier has parameters, NULL included."""
    if alg_id["parameters"].isValue:
        raise BadAlgParams(f"The parameters of {what} must be absent.")


def _require_absent_or_null(alg_id: Any, what: str) -> None:
    """Raise ``BadAlgParams`` unless the parameters are absent or NULL."""
    parameters = alg_id["parameters"]
    if parameters.isValue and not _is_parameters_null(parameters):
        raise BadAlgParams(f"The parameters of {what} must be absent or NULL.")


def _parameters(alg_id: Any, spec: type, what: str, *, required: bool = True) -> Any:
    """Return the parameters of ``alg_id`` as an object of ``spec``, or ``None`` if they are absent and optional.

    :raises BadAlgParams: If they are absent and required, or have data after the structure.
    :raises BadAsn1Data: If they do not decode as ``spec``.
    """
    parameters = alg_id["parameters"]
    if not parameters.isValue:
        if required:
            raise BadAlgParams(f"The parameters of {what} are required.")
        return None
    if isinstance(parameters, spec):
        return parameters
    try:
        der = parameters.asOctets() if isinstance(parameters, univ.Any) else encoder.encode(parameters)
    except PyAsn1Error as exc:
        raise BadAsn1Data(f"The parameters of {what} cannot be encoded: {exc}", overwrite=True) from exc
    decoded, rest = try_decode_pyasn1(der, spec())
    if rest:
        raise BadAlgParams(f"The parameters of {what} have trailing data.")
    return decoded


def _check_hmac_parameters(alg_id: Any, hash_name: str, what: str) -> None:
    """Raise ``BadAlgParams`` unless the parameters of an HMAC identifier are as the hash allows.

    SHA-1 and SHA-2: absent or NULL (NULL is the form of the PBKDF2 pseudorandom functions, RFC 8018 Appendix B.1).
    SHA-3: absent, "not NULL but absent" (RFC 9688 Section 4).
    """
    if hash_name in _HASHES_WITH_NULL:
        _require_absent_or_null(alg_id, what)
    else:
        _require_absent(alg_id, what)


def _hash_of(hash_alg_id: Any, what: str) -> str:
    """Return the name of the hash of an ``AlgorithmIdentifier`` of the X9 hash functions (SHA-1, SHA-2, SHA-3).

    :raises BadAlg: If the OID is no hash or a SHAKE function.
    :raises BadAlgParams: If the parameters are not absent (SHA-3) or absent or NULL (SHA-1, SHA-2).
    """
    _check_alg_id(hash_alg_id, what)
    name = _HASH_OID_2_NAME.get(hash_alg_id["algorithm"])
    if name not in _X9_HASHES:
        raise BadAlg(f"{hash_alg_id['algorithm']} is not a hash that {what} can use.")
    _check_hmac_parameters(hash_alg_id, name, f"the hash of {what}")
    return name


# ---------------------------------------------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pbkdf2:
    """The fields of ``PBKDF2-params`` (RFC 8018 Appendix A.2) after the checks."""

    salt: bytes
    iterations: int
    key_length: Optional[int]
    prf_hash: str


def _read_pbkdf2(kdf: Any) -> _Pbkdf2:
    """Read ``PBKDF2-params`` of an ``id-PBKDF2`` identifier.

    :raises BadAlg: If the salt comes from ``otherSource`` or the pseudorandom function is no HMAC.
    :raises BadAlgParams: If the parameters are absent, have data after them, the iteration count is above
        ``MAX_PBKDF2_ITERATIONS``, or the parameters of the pseudorandom function are not absent or NULL.
    """
    params = _parameters(kdf, rfc8018.PBKDF2_params, "PBKDF2")
    salt = params["salt"]
    if not salt.isValue:
        raise BadAlgParams("PBKDF2 `salt` is not set.")
    if salt.getName() != "specified":
        raise BadAlg("PBKDF2 `salt` from `otherSource` is not supported.")
    iterations = int(params["iterationCount"])
    if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise BadAlgParams(f"PBKDF2 iteration count {iterations} is outside 1..{MAX_PBKDF2_ITERATIONS}.")
    key_length = int(params["keyLength"]) if params["keyLength"].isValue else None
    prf = params["prf"]  # DEFAULT algid-hmacWithSHA1 (RFC 8018 Appendix A.2): the default object if it is absent
    row = _row(MAC_BY_OID, prf, "pseudorandom function of PBKDF2")
    if row.family != "hmac" or row.hash is None:
        raise BadAlg(f"{prf['algorithm']} is not an HMAC, the pseudorandom function of PBKDF2 must be one.")
    _check_hmac_parameters(prf, row.hash, "the pseudorandom function of PBKDF2")
    return _Pbkdf2(salt["specified"].asOctets(), iterations, key_length, row.hash)


def _derive_hkdf(row: KdfRow, kdf: Any, secret: bytes, length: int, info: bytes) -> bytes:
    """HKDF (RFC 5869) with the hash of the OID, no salt; the parameters must be absent (RFC 8619, RFC 9688)."""
    _require_absent(kdf, "HKDF")
    assert row.hash is not None
    return primitives.hkdf(row.hash, secret, length, info)


def _derive_x9(row: KdfRow, kdf: Any, secret: bytes, length: int, info: bytes) -> bytes:
    """KDF2 or KDF3 with the hash that the parameters name (RFC 9690 Appendix B)."""
    hash_alg_id = _parameters(kdf, rfc5280.AlgorithmIdentifier, row.family.upper())
    function = primitives.kdf2 if row.family == "kdf2" else primitives.kdf3
    return function(_hash_of(hash_alg_id, row.family.upper()), secret, length, info)


def _derive_pbkdf2(row: KdfRow, kdf: Any, secret: bytes, length: int, info: bytes) -> bytes:
    """PBKDF2 over the password ``secret``; it has no ``info`` input, and ``keyLength``, if present, is ``length``."""
    del row
    if info:
        raise BadAlgParams("PBKDF2 has no info input; `info` must be empty.")
    params = _read_pbkdf2(kdf)
    if params.key_length is not None and params.key_length != length:
        raise BadAlgParams(f"PBKDF2 keyLength {params.key_length} differs from the requested length {length}.")
    return primitives.pbkdf2(params.prf_hash, secret, params.salt, params.iterations, length)


_KDF_IMPL: Dict[str, Callable[[KdfRow, Any, bytes, int, bytes], bytes]] = {
    "hkdf": _derive_hkdf,
    "kdf2": _derive_x9,
    "kdf3": _derive_x9,
    "pbkdf2": _derive_pbkdf2,
}


def kdf_derive(kdf: AlgId, secret: bytes, length: int, info: bytes = b"") -> bytes:
    """Derive ``length`` octets with the key derivation function that ``kdf`` names.

    ``secret`` is the input keying material of HKDF, the shared secret ``Z`` of KDF2 (X9.63) and KDF3, and the
    password of PBKDF2. ``info`` is the HKDF ``info`` and the ``otherInfo`` of KDF2 and KDF3 (RFC 9629 Section 5 puts
    the ``CMSORIforKEMOtherInfo`` there). HKDF is used without salt.

    * HKDF (RFC 8619, RFC 9688 Section 5.1): the hash is in the OID, the parameters must be absent. SHAKE has no OID,
      and HKDF over SHAKE is :class:`BadAlg` (HKDF is HMAC based).
    * KDF2, KDF3 (RFC 9690 Appendix B): the parameters are the ``AlgorithmIdentifier`` of the hash, SHA-1, SHA-2 or
      SHA-3 (SHA-1 and SHA-2 with NULL or no parameters, SHA-3 with none); SHAKE is :class:`BadAlg`.
    * PBKDF2 (RFC 8018 Appendix A.2): ``PBKDF2-params``, decoded as that structure also after a DER round trip. The salt
      must be ``specified`` (``otherSource`` is :class:`BadAlg`); ``keyLength``, if present, must equal ``length``;
      an absent ``prf`` is HMAC-SHA-1, the DEFAULT; the iteration count is capped at ``MAX_PBKDF2_ITERATIONS``.
      PBKDF2 takes no ``info``: a non-empty one is :class:`BadAlgParams`.

    :param kdf: The identifier of the key derivation function, with its parameters.
    :param secret: The input keying material or password.
    :param length: The number of octets to derive, at least 1.
    :param info: The ``info`` or ``otherInfo``.
    :raises TypeError: If ``kdf`` is no ``AlgorithmIdentifier``.
    :raises BadAlg: If the OID is no key derivation function, or names a hash or pseudorandom function that the
        function cannot use.
    :raises BadAlgParams: If the parameters are absent, present wrongly or inconsistent with ``length`` and ``info``.
    :raises BadAsn1Data: If the parameters cannot be decoded.
    :raises ValueError: If ``length`` is below 1 or more than the function can derive.
    """
    row = _row(KDF_BY_OID, kdf, "key derivation function")
    if length < 1:
        raise ValueError(f"The length must be at least 1, not {length}.")
    return _KDF_IMPL[row.family](row, kdf, secret, length, info)
