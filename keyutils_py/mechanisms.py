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

The parameters of a received structure also decide how strong or how expensive a check is, so the mechanisms refuse
values outside four limits, named below, before any computation: a PBMAC1 ``keyLength`` outside 16 to 4096 octets, a
KMAC ``kMACOutputLength`` below 128 bits, and a PBKDF2 work above 25 000 000 blocks (besides the cap of
``MAX_PBKDF2_ITERATIONS`` on the iterations). They are fail-closed defaults for received parameters. The functions of
:mod:`keyutils_py.primitives` have none of them, which is how a test makes a short key or tag on purpose.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Callable, Dict, Literal, Optional, Tuple

from pyasn1.codec.der import encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import tag, univ
from pyasn1_alt_modules import (
    rfc3565,
    rfc4055,
    rfc5084,
    rfc5280,
    rfc8018,
    rfc8702,
    rfc9044,
    rfc9480,
)

from keyutils_py import primitives
from keyutils_py._algs import (
    CONTENT_BY_OID,
    CONTENT_OID,
    KDF_BY_OID,
    KDF_OID,
    KT_OID,
    MAC_BY_OID,
    MAC_OID,
    PRF_OID,
    WRAP_BY_OID,
    WRAP_OID,
    AlgInfo,
    ContentRow,
    KdfRow,
    MacRow,
    WrapRow,
)
from keyutils_py.asn1utils import try_decode_pyasn1
from keyutils_py.exceptions import BadAlg, BadAlgParams, BadAsn1Data, IntegrityError
from keyutils_py.keys.key_pyasn1_utils import MAX_PBKDF2_ITERATIONS
from keyutils_py.oids import _HASH_OID_2_NAME, _HASH_REGISTRY, _is_parameters_null

__all__ = [
    "AlgInfo",
    "AlgKind",
    "Encrypted",
    "compute_mac",
    "decrypt_content",
    "encrypt_content",
    "kdf_derive",
    "mac_key_length",
    "make_alg_id",
    "unwrap_cek",
    "verify_mac",
    "wrap_cek",
    "wrap_key_length",
]

AlgId = rfc9480.AlgorithmIdentifier

# Limits on received parameters (fail-closed defaults; see the module docstring). Every one is checked before the
# derivation or the MAC is computed.
MIN_PBMAC1_KEY_LENGTH = 16
"""The least ``keyLength`` of PBMAC1 in octets: the MAC key has that length, and a 1 octet key falls in 256 tries."""
MAX_PBMAC1_KEY_LENGTH = 4096
"""The greatest ``keyLength`` of PBMAC1 in octets (a known peer, CmpRaComponent 4.3.0, defaults to 4096)."""
MIN_KMAC_OUTPUT_BITS = 128
"""The least ``kMACOutputLength`` of KMAC in bits; an 8 bit output is a 1 in 256 forgery. There is no upper cap."""
MAX_PBKDF2_WORK = 25_000_000
"""The most PBKDF2 work, ``iterations * ceil(keyLength / digest size of the prf hash)``, that a mechanism starts."""

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


def _check_pbkdf2_work(prf_hash: str, iterations: int, key_length: int) -> None:
    """Raise ``BadAlgParams`` if PBKDF2 would need more than ``MAX_PBKDF2_WORK`` blocks (RFC 8018 Section 5.2).

    One block is one run of ``iterations`` HMAC calls, and ``ceil(key_length / digest size)`` blocks are needed.
    """
    blocks = -(-key_length // _HASH_REGISTRY[prf_hash][1].digest_size)
    if iterations * blocks > MAX_PBKDF2_WORK:
        raise BadAlgParams(
            f"PBKDF2 with {iterations} iterations over {blocks} blocks needs {iterations * blocks} rounds, "
            f"more than the limit of {MAX_PBKDF2_WORK}."
        )


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
    _check_pbkdf2_work(params.prf_hash, params.iterations, length)
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
      an absent ``prf`` is HMAC-SHA-1, the DEFAULT; the iteration count is capped at ``MAX_PBKDF2_ITERATIONS``, and
      the work ``iterations * ceil(length / digest size of the prf hash)`` at ``MAX_PBKDF2_WORK`` (25 000 000), both
      refused with :class:`BadAlgParams` before anything is derived. PBKDF2 takes no ``info``: a non-empty one is
      :class:`BadAlgParams`.

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


# ---------------------------------------------------------------------------------------------------------------
# Message authentication codes
# ---------------------------------------------------------------------------------------------------------------

_KMAC_PARAMS = {"shake128": rfc8702.KMACwithSHAKE128_params, "shake256": rfc8702.KMACwithSHAKE256_params}


def _refuse_sha1(hash_name: Optional[str], allow_sha1: bool) -> None:
    """Raise ``BadAlg`` for SHA-1 unless the caller allows it."""
    if hash_name == "sha1" and not allow_sha1:
        raise BadAlg("A MAC over SHA-1 is refused unless the caller passes `allow_sha1=True`.")


def _mac_hmac(row: MacRow, mac: Any, key: bytes, data: bytes, allow_sha1: bool) -> bytes:
    """HMAC with the hash of the OID; the parameters are absent, or NULL for SHA-1 and SHA-2."""
    assert row.hash is not None
    _check_hmac_parameters(mac, row.hash, "HMAC")
    _refuse_sha1(row.hash, allow_sha1)
    return primitives.hmac_digest(row.hash, key, data)


def _mac_kmac(row: MacRow, mac: Any, key: bytes, data: bytes, allow_sha1: bool) -> bytes:
    """KMAC128 or KMAC256 (RFC 8702 Section 3.4): absent parameters mean 256 or 512 bits and no customization."""
    del allow_sha1
    assert row.hash is not None
    params = _parameters(mac, _KMAC_PARAMS[row.hash], "KMAC", required=False)
    if params is None:
        bits, custom = _HASH_REGISTRY[row.hash][1].digest_size * 8, b""
    else:
        bits, custom = int(params["kMACOutputLength"]), params["customizationString"].asOctets()
    if bits % 8:
        raise BadAlgParams(f"KMAC kMACOutputLength must be a multiple of 8 bits, not {bits}.")
    if bits < MIN_KMAC_OUTPUT_BITS:
        raise BadAlgParams(f"KMAC kMACOutputLength {bits} is below the limit of {MIN_KMAC_OUTPUT_BITS} bits.")
    return primitives.kmac(row.hash, key, data, mac_len=bits // 8, custom=custom)


def _mac_gmac(row: MacRow, mac: Any, key: bytes, data: bytes, allow_sha1: bool) -> bytes:
    """AES-GMAC (RFC 9044 Section 3.1): the tag truncated to ``length`` (DEFAULT 12) octets of the parameters."""
    del allow_sha1
    assert row.bits is not None
    params = _parameters(mac, rfc9044.GCMParameters, "AES-GMAC")
    if len(key) * 8 != row.bits:
        raise BadAlgParams(f"AES-GMAC with a {row.bits} bit key needs {row.bits // 8} octets of key, not {len(key)}.")
    nonce = params["nonce"].asOctets()
    if not 8 <= len(nonce) <= 128:
        raise BadAlgParams(f"The AES-GMAC nonce must have 8 to 128 octets, not {len(nonce)}.")
    return primitives.gmac(key, nonce, data)[: int(params["length"])]


def _mac_pbmac1(row: MacRow, mac: Any, key: bytes, data: bytes, allow_sha1: bool) -> bytes:
    """PBMAC1 (RFC 8018 Section 7.1): PBKDF2 over the password ``key``, then HMAC under the derived key."""
    del row
    params = _parameters(mac, rfc8018.PBMAC1_params, "PBMAC1")
    kdf = params["keyDerivationFunc"]
    if kdf["algorithm"] != rfc8018.id_PBKDF2:
        raise BadAlg(f"The key derivation function of PBMAC1 must be PBKDF2, not {kdf['algorithm']}.")
    pbkdf2 = _read_pbkdf2(kdf)
    if pbkdf2.key_length is None:
        raise BadAlgParams("PBMAC1 needs the keyLength of PBKDF2-params: it is the length of the key of the MAC.")
    if not MIN_PBMAC1_KEY_LENGTH <= pbkdf2.key_length <= MAX_PBMAC1_KEY_LENGTH:
        raise BadAlgParams(
            f"PBMAC1 keyLength {pbkdf2.key_length} is outside {MIN_PBMAC1_KEY_LENGTH} to {MAX_PBMAC1_KEY_LENGTH}."
        )
    _check_pbkdf2_work(pbkdf2.prf_hash, pbkdf2.iterations, pbkdf2.key_length)
    scheme = params["messageAuthScheme"]
    scheme_row = _row(MAC_BY_OID, scheme, "message authentication scheme of PBMAC1")
    if scheme_row.family != "hmac" or scheme_row.hash is None:
        raise BadAlg(f"PBMAC1 over {scheme_row.family} is not supported, only over HMAC.")
    _check_hmac_parameters(scheme, scheme_row.hash, "the message authentication scheme of PBMAC1")
    _refuse_sha1(pbkdf2.prf_hash, allow_sha1)
    _refuse_sha1(scheme_row.hash, allow_sha1)
    derived = primitives.pbkdf2(pbkdf2.prf_hash, key, pbkdf2.salt, pbkdf2.iterations, pbkdf2.key_length)
    return primitives.hmac_digest(scheme_row.hash, derived, data)


_MAC_IMPL: Dict[str, Callable[[MacRow, Any, bytes, bytes, bool], bytes]] = {
    "hmac": _mac_hmac,
    "kmac": _mac_kmac,
    "gmac": _mac_gmac,
    "pbmac1": _mac_pbmac1,
}


def _mac(mac: Any, key: bytes, data: bytes, allow_sha1: bool) -> bytes:
    """Compute the MAC that ``mac`` names."""
    row = _row(MAC_BY_OID, mac, "message authentication code")
    return _MAC_IMPL[row.family](row, mac, key, data, allow_sha1)


def compute_mac(mac: AlgId, key: bytes, data: bytes) -> bytes:
    """Compute the MAC of ``data`` that the identifier ``mac`` names.

    * HMAC with SHA-1 (``hMAC-SHA1`` and ``id-hmacWithSHA1``), SHA-2 and SHA-3: the parameters are absent, or NULL for
      SHA-1 and SHA-2 (RFC 8018 Appendix B.1, RFC 9688 Section 4).
    * KMAC128 and KMAC256 (RFC 8702 Section 3.4): absent parameters mean 256 or 512 bits of output and no customization
      string; ``KMACwithSHAKE128-params`` and ``KMACwithSHAKE256-params`` change both. An output length that is no
      multiple of 8 bits, or below ``MIN_KMAC_OUTPUT_BITS`` (128), is :class:`BadAlgParams`; there is no upper cap.
      ``pycryptodome`` takes a key of at least 16 (KMAC128) or 32 (KMAC256) octets, a shorter one is a ``ValueError``.
    * AES-GMAC (RFC 9044): ``key`` has the size of the OID, the parameters are required; the nonce has 8 to 128 octets
      and the MAC is the GCM tag cut to ``length`` octets of the parameters (DEFAULT 12).
    * PBMAC1 (RFC 8018 Section 7.1, RFC 9481 Section 6.1.2): ``key`` is the password; the key derivation function must
      be PBKDF2 with a ``keyLength``, the message authentication scheme an HMAC. The MAC key is the PBKDF2 output.
      A ``keyLength`` outside ``MIN_PBMAC1_KEY_LENGTH`` to ``MAX_PBMAC1_KEY_LENGTH`` (16 to 4096 octets) or a PBKDF2
      work above ``MAX_PBKDF2_WORK`` is :class:`BadAlgParams`, refused before PBKDF2 runs.

    SHA-1 is not refused here, a test suite has to produce it; :func:`verify_mac` refuses it unless it is allowed.

    :param mac: The identifier of the MAC, with its parameters.
    :param key: The MAC key, or the password for PBMAC1.
    :param data: The data to authenticate.
    :raises TypeError: If ``mac`` is no ``AlgorithmIdentifier``.
    :raises BadAlg: If the OID is no MAC, or PBMAC1 names another KDF than PBKDF2 or another scheme than HMAC.
    :raises BadAlgParams: If the parameters or the key size do not fit the OID.
    :raises BadAsn1Data: If the parameters cannot be decoded.
    """
    return _mac(mac, key, data, allow_sha1=True)


def verify_mac(mac: AlgId, key: bytes, data: bytes, expected: bytes, *, allow_sha1: bool = False) -> None:
    """Verify that ``expected`` is the MAC of ``data`` under ``mac`` and ``key``, in constant time.

    Verification is a trust decision, so SHA-1 is refused unless the caller allows it: HMAC with SHA-1, and PBMAC1 with
    SHA-1 as the pseudorandom function or as the HMAC, raise :class:`BadAlg` unless ``allow_sha1`` is true. Everything
    else is as in :func:`compute_mac`.

    :param expected: The MAC value that was received.
    :param allow_sha1: Accept a MAC over SHA-1.
    :raises IntegrityError: If the MAC does not match, also if ``expected`` has another length than the MAC (a prefix
        of a MAC does not verify). The message does not say how it differs.
    :raises BadAlg: As :func:`compute_mac`, and for SHA-1 without ``allow_sha1``.
    """
    if not hmac.compare_digest(_mac(mac, key, data, allow_sha1), expected):
        raise IntegrityError("MAC verification failed.")


def mac_key_length(mac: AlgId) -> Optional[int]:
    """Return the octets of key that the MAC needs (AES-GMAC: 16, 24 or 32), or ``None`` if its key has any size.

    :raises BadAlg: If the OID is no MAC.
    """
    row = _row(MAC_BY_OID, mac, "message authentication code")
    return row.bits // 8 if row.bits is not None else None


# ---------------------------------------------------------------------------------------------------------------
# Key wrap
# ---------------------------------------------------------------------------------------------------------------

_WRAP_IMPL: Dict[str, Tuple[Callable[[bytes, bytes], bytes], Callable[[bytes, bytes], bytes]]] = {
    "kw": (primitives.aes_kw_wrap, primitives.aes_kw_unwrap),
    "kwp": (primitives.aes_kwp_wrap, primitives.aes_kwp_unwrap),
}


def _wrap_row(wrap: Any) -> WrapRow:
    """Return the row of an AES key wrap identifier, whose parameters must be absent (RFC 3565 Section 2.3.2)."""
    row = _row(WRAP_BY_OID, wrap, "AES key wrap algorithm")
    _require_absent(wrap, "an AES key wrap algorithm")
    return row


def _check_kek(row: WrapRow, kek: bytes) -> None:
    """Raise ``BadAlgParams`` if the KEK has not the size that the OID names."""
    if len(kek) != row.kek_len:
        raise BadAlgParams(f"The key wrap OID names an AES key of {row.kek_len} octets, the KEK has {len(kek)}.")


def wrap_key_length(wrap: AlgId) -> int:
    """Return the octets of KEK that the key wrap OID names (16, 24 or 32).

    :raises TypeError: If ``wrap`` is no ``AlgorithmIdentifier``.
    :raises BadAlg: If the OID is no AES key wrap.
    :raises BadAlgParams: If the identifier has parameters.
    """
    return _wrap_row(wrap).kek_len


def wrap_cek(wrap: AlgId, kek: bytes, cek: bytes) -> bytes:
    """Wrap ``cek`` under ``kek`` with the AES key wrap that ``wrap`` names.

    AES key wrap (RFC 3394) takes a ``cek`` of a multiple of 8 octets, at least 16 (a ``ValueError`` otherwise); AES key
    wrap with padding (RFC 5649) takes any size from 1 octet. The KEK must have the size that the OID names.

    :raises TypeError: If ``wrap`` is no ``AlgorithmIdentifier``.
    :raises BadAlg: If the OID is no AES key wrap.
    :raises BadAlgParams: If the identifier has parameters, or the KEK has not the size of the OID.
    :raises ValueError: If ``cek`` has a size that the algorithm cannot wrap.
    """
    row = _wrap_row(wrap)
    _check_kek(row, kek)
    return _WRAP_IMPL[row.mode][0](kek, cek)


def unwrap_cek(wrap: AlgId, kek: bytes, wrapped: bytes) -> bytes:
    """Unwrap ``wrapped`` under ``kek`` with the AES key wrap that ``wrap`` names.

    :raises IntegrityError: If the check value does not verify (a wrong KEK, a changed or truncated value, or a value
        that was wrapped with the other mode), and for a ``wrapped`` of an impossible size. The message says no more.
    :raises BadAlg: As :func:`wrap_cek`.
    :raises BadAlgParams: As :func:`wrap_cek`.
    """
    row = _wrap_row(wrap)
    _check_kek(row, kek)
    return _WRAP_IMPL[row.mode][1](kek, wrapped)


# ---------------------------------------------------------------------------------------------------------------
# Content encryption
# ---------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Encrypted:
    """The result of :func:`encrypt_content`: the ciphertext, and for AES-GCM the authentication tag."""

    ciphertext: bytes
    tag: Optional[bytes] = None


def _content_row(enc: Any) -> ContentRow:
    """Return the row of a content encryption identifier."""
    return _row(CONTENT_BY_OID, enc, "content encryption algorithm")


def _check_cek(row: ContentRow, cek: bytes) -> None:
    """Raise ``BadAlgParams`` if the key has not the size that the OID names."""
    if len(cek) != row.key_len:
        raise BadAlgParams(f"The content encryption OID names a key of {row.key_len} octets, the key has {len(cek)}.")


def _cbc_iv(enc: Any) -> bytes:
    """Return the IV of AES-CBC, the parameters (RFC 3565 Section 4.1): an OCTET STRING of 16 octets."""
    return _parameters(enc, rfc3565.AES_IV, "AES-CBC").asOctets()


def _gcm_parameters(enc: Any) -> Tuple[bytes, int]:
    """Return ``(nonce, tag length)`` of ``GCMParameters`` (RFC 5084 Section 3.2); the length DEFAULT is 12."""
    params = _parameters(enc, rfc5084.GCMParameters, "AES-GCM")
    nonce = params["aes-nonce"].asOctets()
    if not 8 <= len(nonce) <= 128:
        raise BadAlgParams(f"The AES-GCM nonce must have 8 to 128 octets, not {len(nonce)}.")
    return nonce, int(params["aes-ICVlen"])


def encrypt_content(enc: AlgId, cek: bytes, plaintext: bytes, *, aad: Optional[bytes] = None) -> Encrypted:
    """Encrypt ``plaintext`` with the AES mode that ``enc`` names, with the IV or nonce of its parameters.

    * AES-CBC (RFC 3565, RFC 9481 Section 5.1) with PKCS#7 padding: the parameters are the IV, an OCTET STRING of 16
      octets. ``aad`` is a ``TypeError``.
    * AES-GCM (RFC 5084): the parameters are ``GCMParameters``, a nonce of 8 to 128 octets (the range of the
      implementation) and ``aes-ICVlen`` (DEFAULT 12, 12 to 16). The result carries the tag cut to that length.

    The key must have the size that the OID names.

    :raises TypeError: If ``enc`` is no ``AlgorithmIdentifier``, or ``aad`` is given for AES-CBC.
    :raises BadAlg: If the OID is no content encryption algorithm.
    :raises BadAlgParams: If the parameters are absent or inconsistent, or the key has not the size of the OID.
    :raises BadAsn1Data: If the parameters do not decode (a wrong IV size, a tag length outside 12 to 16).
    """
    row = _content_row(enc)
    _check_cek(row, cek)
    if row.mode == "cbc":
        if aad is not None:
            raise TypeError("`aad` is only for AES-GCM.")
        return Encrypted(primitives.aes_cbc_encrypt(cek, _cbc_iv(enc), plaintext))
    nonce, tag_length = _gcm_parameters(enc)
    ciphertext, tag = primitives.aes_gcm_encrypt(cek, nonce, plaintext, aad)
    return Encrypted(ciphertext, tag[:tag_length])


def decrypt_content(
    enc: AlgId, cek: bytes, ciphertext: bytes, *, tag: Optional[bytes] = None, aad: Optional[bytes] = None
) -> bytes:
    """Decrypt what :func:`encrypt_content` made, with the same checks.

    ``tag`` is required for AES-GCM and must have the ``aes-ICVlen`` of the parameters; ``tag`` and ``aad`` are a
    ``TypeError`` for AES-CBC.

    :raises IntegrityError: If the AES-GCM tag does not verify, or the AES-CBC padding or length is wrong; the message
        does not say which.
    :raises TypeError: If ``tag`` or ``aad`` do not belong to the mode.
    :raises BadAlgParams: As :func:`encrypt_content`, and if the tag has not the length of the parameters.
    """
    row = _content_row(enc)
    _check_cek(row, cek)
    if row.mode == "cbc":
        if tag is not None or aad is not None:
            raise TypeError("`tag` and `aad` are only for AES-GCM.")
        return primitives.aes_cbc_decrypt(cek, _cbc_iv(enc), ciphertext)
    if tag is None:
        raise TypeError("AES-GCM needs the `tag`.")
    nonce, tag_length = _gcm_parameters(enc)
    if len(tag) != tag_length:
        raise BadAlgParams(f"The tag has {len(tag)} octets, `aes-ICVlen` of the parameters says {tag_length}.")
    return primitives.aes_gcm_decrypt(cek, nonce, ciphertext, tag, aad)


# ---------------------------------------------------------------------------------------------------------------
# Building an AlgorithmIdentifier
# ---------------------------------------------------------------------------------------------------------------

AlgKind = Literal["kdf", "mac", "wrap", "content", "kari", "key_transport"]
"""The kinds of algorithm of :func:`make_alg_id`; ``"kari"`` has no builder yet."""


def _make(oid: univ.ObjectIdentifier, parameters: Any = None) -> AlgId:
    """Return an ``AlgorithmIdentifier`` whose parameters are the DER of ``parameters``, or absent."""
    alg_id = AlgId()
    alg_id["algorithm"] = oid
    if parameters is not None:
        alg_id["parameters"] = univ.Any(encoder.encode(parameters))
    return alg_id


def _oid_of(index: Any, key: Any, what: str) -> univ.ObjectIdentifier:
    """Return the OID of a table fact, or raise ``BadAlg``."""
    try:
        return index[key]
    except KeyError:
        raise BadAlg(f"No OID for {what} in the algorithm tables.") from None


def _hash_alg_id(hash_name: str) -> AlgId:
    """Return the identifier of a hash: NULL parameters for SHA-1 and SHA-2 as RFC 9690 Appendix D writes them."""
    if hash_name not in _HASH_REGISTRY:
        raise BadAlg(f"{hash_name!r} is not a hash of the registry.")
    return _make(_HASH_REGISTRY[hash_name][0], univ.Null("") if hash_name in _HASHES_WITH_NULL else None)


def _prf_alg_id(hash_name: str) -> AlgId:
    """Return the HMAC identifier for the ``prf`` of PBKDF2: the OID of RFC 8018 Appendix B.1 where there is one."""
    oid = PRF_OID.get(hash_name) or _oid_of(MAC_OID, ("hmac", hash_name, None), f"HMAC with {hash_name!r}")
    return _make(oid, univ.Null("") if hash_name in _HASHES_WITH_NULL else None)


def _pbkdf2_parameters(salt: bytes, iterations: int, key_length: Optional[int], prf_hash: str) -> Any:
    """Return ``PBKDF2-params`` (RFC 8018 Appendix A.2) with a specified salt."""
    params = rfc8018.PBKDF2_params()
    prf = _prf_alg_id(prf_hash)
    try:
        params["salt"]["specified"] = salt
        params["iterationCount"] = iterations
        if key_length is not None:
            params["keyLength"] = key_length
        if prf_hash != "sha1":  # HMAC-SHA-1 with NULL is the DEFAULT, which DER leaves out
            params["prf"] = prf
    except (PyAsn1Error, KeyError) as exc:
        raise ValueError(f"Not a valid PBKDF2-params value: {exc}") from exc
    return params


# The keyword is called ``hash``, as the algorithm tables call the fact.
# pylint: disable=redefined-builtin
def _build_hkdf(*, hash: str) -> AlgId:
    """HKDF with ``hash``; the parameters are absent."""
    return _make(_oid_of(KDF_OID, ("hkdf", hash), f"HKDF with {hash!r}"))


def _build_kdf2(*, hash: str) -> AlgId:
    """KDF2 (X9.63); the parameters are the identifier of ``hash``."""
    return _make(KDF_OID[("kdf2", None)], _hash_alg_id(hash))


def _build_kdf3(*, hash: str) -> AlgId:
    """KDF3; the parameters are the identifier of ``hash``."""
    return _make(KDF_OID[("kdf3", None)], _hash_alg_id(hash))


def _build_pbkdf2(*, salt: bytes, iterations: int, prf_hash: str, key_length: Optional[int] = None) -> AlgId:
    """PBKDF2 with a specified ``salt``; an absent ``key_length`` leaves ``keyLength`` out."""
    return _make(KDF_OID[("pbkdf2", None)], _pbkdf2_parameters(salt, iterations, key_length, prf_hash))


def _build_hmac(*, hash: str) -> AlgId:
    """HMAC with ``hash``; the parameters are absent. SHA-1 gets ``hMAC-SHA1``, the OID of a MAC."""
    return _make(_oid_of(MAC_OID, ("hmac", hash, None), f"HMAC with {hash!r}"))


def _build_kmac(*, hash: str) -> AlgId:
    """KMAC128 (``hash="shake128"``) or KMAC256 (``"shake256"``); the parameters are absent."""
    return _make(_oid_of(MAC_OID, ("kmac", hash, None), f"KMAC with {hash!r}"))


def _build_gmac(*, bits: int, nonce: bytes, tag_length: Optional[int] = None) -> AlgId:
    """AES-GMAC with a ``bits`` key; the parameters carry ``nonce`` and, if given, ``tag_length`` (12 to 16)."""
    params = rfc9044.GCMParameters()
    try:
        params["nonce"] = nonce
        if tag_length is not None:
            params["length"] = tag_length
    except (PyAsn1Error, KeyError) as exc:
        raise ValueError(f"Not a valid GMACParameters value: {exc}") from exc
    return _make(_oid_of(MAC_OID, ("gmac", None, bits), f"AES-GMAC with a {bits} bit key"), params)


def _build_pbmac1(
    *, salt: bytes, iterations: int, key_length: Optional[int], prf_hash: str, mac_hash: Optional[str] = None
) -> AlgId:
    """PBMAC1 over PBKDF2 and HMAC; ``mac_hash`` is ``prf_hash`` if not given. ``key_length`` None leaves it out."""
    params = rfc8018.PBMAC1_params()
    params["keyDerivationFunc"] = _build_pbkdf2(
        salt=salt, iterations=iterations, prf_hash=prf_hash, key_length=key_length
    )
    params["messageAuthScheme"] = _build_hmac(hash=mac_hash or prf_hash)
    return _make(MAC_OID[("pbmac1", None, None)], params)


def _build_aes_wrap(*, bits: int, mode: str) -> AlgId:
    """AES key wrap (``mode="kw"``, RFC 3394) or key wrap with padding (``"kwp"``, RFC 5649) with a ``bits`` KEK."""
    return _make(_oid_of(WRAP_OID, (mode, bits // 8), f"AES key wrap mode {mode!r} with a {bits} bit KEK"))


def _build_aes_cbc(*, bits: int, iv: bytes) -> AlgId:
    """AES-CBC with a ``bits`` key; the parameters are ``iv`` as an OCTET STRING, of any size."""
    return _make(_oid_of(CONTENT_OID, ("cbc", bits // 8), f"AES-CBC with a {bits} bit key"), univ.OctetString(iv))


def _build_aes_gcm(*, bits: int, nonce: bytes, tag_length: Optional[int] = None) -> AlgId:
    """AES-GCM with a ``bits`` key; the parameters carry ``nonce`` and, if given, ``tag_length`` (12 to 16)."""
    params = rfc5084.GCMParameters()
    try:
        params["aes-nonce"] = nonce
        if tag_length is not None:
            params["aes-ICVlen"] = tag_length
    except (PyAsn1Error, KeyError) as exc:
        raise ValueError(f"Not a valid GCMParameters value: {exc}") from exc
    return _make(_oid_of(CONTENT_OID, ("gcm", bits // 8), f"AES-GCM with a {bits} bit key"), params)


def _oaep_field(alg_id: AlgId, number: int) -> Any:
    """Return an identifier in the context tag ``[number]`` that RSAES-OAEP-params gives its three fields."""
    return alg_id.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, number), cloneValueFlag=True
    )


def _build_rsa_oaep(*, hash: str, mgf1_hash: Optional[str] = None, label: bytes = b"") -> AlgId:
    """RSAES-OAEP (RFC 4055 Section 4.1): ``hash``, MGF1 over ``mgf1_hash`` (``hash`` if ``None``) and ``label``.

    The identifiers of the hashes carry NULL, as the ones that RFC 4055 builds do; a field that has its DEFAULT value
    (SHA-1, SHA-1 for MGF1, the empty label) is left out, as DER requires. SHA-1 and SHA-2 only.
    """
    mgf1_hash = hash if mgf1_hash is None else mgf1_hash
    for name in (hash, mgf1_hash):
        if name not in _HASHES_WITH_NULL:
            raise BadAlg(f"RSAES-OAEP is defined over SHA-1 and SHA-2 (RFC 4055 Section 2.1), not {name!r}.")
    params = rfc4055.RSAES_OAEP_params()
    if hash != "sha1":
        params["hashFunc"] = _oaep_field(_hash_alg_id(hash), 0)
    if mgf1_hash != "sha1":
        params["maskGenFunc"] = _oaep_field(_make(rfc4055.id_mgf1, _hash_alg_id(mgf1_hash)), 1)
    if label:
        params["pSourceFunc"] = _oaep_field(_make(rfc4055.id_pSpecified, univ.OctetString(label)), 2)
    return _make(rfc4055.id_RSAES_OAEP, params)


def _build_rsa_pkcs1v15() -> AlgId:
    """RSAES-PKCS1-v1_5: ``rsaEncryption`` with NULL parameters (RFC 3370 Section 4.2.1)."""
    return _make(KT_OID["pkcs1v15"], univ.Null(""))


# pylint: enable=redefined-builtin
_BUILDERS: Dict[str, Dict[str, Callable[..., AlgId]]] = {
    "kdf": {"hkdf": _build_hkdf, "kdf2": _build_kdf2, "kdf3": _build_kdf3, "pbkdf2": _build_pbkdf2},
    "mac": {"hmac": _build_hmac, "kmac": _build_kmac, "gmac": _build_gmac, "pbmac1": _build_pbmac1},
    "wrap": {"aes": _build_aes_wrap},
    "content": {"aes-cbc": _build_aes_cbc, "aes-gcm": _build_aes_gcm},
    "key_transport": {"rsa-oaep": _build_rsa_oaep, "rsa-pkcs1v15": _build_rsa_pkcs1v15},
}


def make_alg_id(kind: AlgKind, family: str, **params: Any) -> AlgId:
    """Build the ``AlgorithmIdentifier`` of one algorithm family, with its parameters as the RFCs write them.

    One builder per family; its keywords are the facts of the family, and a keyword that the builder does not know, or
    a required one that is missing, is a ``TypeError``. The ``params`` of a row of :func:`keyutils_py.list_algorithms`
    are keywords that the builder of its family takes (the rest, like a salt or a nonce, the caller adds).

    * ``("kdf", "hkdf")``: ``hash`` (``"sha256"``, ``"sha384"``, ``"sha512"``, ``"sha3_224"`` to ``"sha3_512"``).
    * ``("kdf", "kdf2")`` and ``("kdf", "kdf3")``: ``hash``, the hash that the parameters name.
    * ``("kdf", "pbkdf2")``: ``salt``, ``iterations``, ``prf_hash``, ``key_length=None`` (then ``keyLength`` is absent).
    * ``("mac", "hmac")``: ``hash``; SHA-1 gives ``hMAC-SHA1``, the OID of a MAC.
    * ``("mac", "kmac")``: ``hash``, ``"shake128"`` or ``"shake256"``.
    * ``("mac", "gmac")``: ``bits`` (the key size), ``nonce``, ``tag_length=None`` (12 to 16; absent means 12).
    * ``("mac", "pbmac1")``: ``salt``, ``iterations``, ``key_length`` (None leaves it out), ``prf_hash``,
      ``mac_hash=None`` (then ``prf_hash``).
    * ``("wrap", "aes")``: ``bits`` (the KEK size), ``mode`` (``"kw"`` or ``"kwp"``).
    * ``("content", "aes-cbc")``: ``bits``, ``iv``.
    * ``("content", "aes-gcm")``: ``bits``, ``nonce``, ``tag_length=None`` (12 to 16; absent means 12).
    * ``("key_transport", "rsa-oaep")``: ``hash``, ``mgf1_hash=None`` (then ``hash``), ``label=b""``; SHA-1 and SHA-2.
      RFC 4055 form: the hash identifiers carry NULL and MGF1 has the identifier of its hash as parameter; the fields
      that equal the DEFAULTs are left out, so SHA-1 with the empty label is an empty SEQUENCE.
    * ``("key_transport", "rsa-pkcs1v15")``: no keyword; ``rsaEncryption`` with NULL.

    A builder writes what it is asked for and does not check sizes, so a test can build an identifier that a receiver
    refuses (a 15 octet IV, a PBKDF2 ``keyLength`` that differs from the length that is derived). SHA-1 and SHA-2
    inside the parameters of KDF2, KDF3 and the PBKDF2 ``prf`` carry NULL (RFC 9690 Appendix D, RFC 8018 Appendix B.1),
    SHA-3 none.

    :param kind: The kind of algorithm. ``"kari"`` has no builder yet.
    :param family: The family within the kind.
    :param params: The keywords of the family.
    :raises BadAlg: If the kind or family is unknown, or the table has no OID for the hash, size or mode.
    :raises TypeError: If a keyword is unknown for the family or a required one is missing.
    :raises ValueError: If a value cannot be written (a PBKDF2 ``iterations`` of 0, a ``tag_length`` of 11).
    """
    try:
        builder = _BUILDERS[kind][family]
    except KeyError:
        raise BadAlg(f"There is no builder for the algorithm family {family!r} of the kind {kind!r}.") from None
    return builder(**params)
