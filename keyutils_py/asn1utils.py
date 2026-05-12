# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""ASN.1 helpers: DER encode/decode, ``BitString`` construction, and randomness.

This module is the single source of truth for ASN.1 utilities used across
the package:

* :func:`encode_to_der` — wrap ``pyasn1.codec.der.encoder.encode``.
* :func:`try_decode_pyasn1` — wrap ``pyasn1.codec.der.decoder.decode`` and
  raise :class:`BadAsn1Data` on failure.
* :func:`prepare_bit_string` — build (or repopulate) a ``univ.BitString``
  from raw bytes while preserving any subtype tagging on the target.
* :func:`get_asn1_bytes_value` — return the raw octets carried by a
  ``BitString``, ``OctetString``, or ``univ.Any`` value.
* :func:`get_random_bytes` — cryptographically random byte string
  (16 bytes by default).
"""

from typing import Any, Optional, Tuple, Union

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import base, univ

from keyutils_py.exceptions import BadAsn1Data


def encode_to_der(asn1_structure: base.Asn1Item) -> bytes:
    """DER-encode a ``pyasn1`` data structure.

    :param asn1_structure: The ``pyasn1`` data structure to be encoded.
    :returns: The DER-encoded bytes of the structure.
    """
    return encoder.encode(asn1_structure)


def try_decode_pyasn1(
    data: Union[bytes, univ.Any, univ.OctetString],
    asn1_spec: Any,
    verbose: bool = False,
) -> Tuple[Any, bytes]:
    """Decode ``data`` against ``asn1_spec``; raise :class:`BadAsn1Data` on failure.

    :param data: DER bytes, or a ``univ.Any`` / ``univ.OctetString`` carrying them.
    :param asn1_spec: The ``pyasn1`` specification to decode against.
    :param verbose: If ``True``, include the input hex in the error message.
    :returns: A ``(decoded, remainder)`` tuple, mirroring ``decoder.decode``.
    :raises BadAsn1Data: If decoding fails.
    :raises TypeError: If ``data`` is not bytes / Any / OctetString.
    """
    if isinstance(data, (univ.Any, univ.OctetString)):
        der_data = data.asOctets()
    elif isinstance(data, bytes):
        der_data = data
    else:
        raise TypeError(f"Expected bytes, got {type(data)}")

    try:
        return decoder.decode(der_data, asn1_spec)
    except Exception as exc:  # noqa: BLE001
        remainder = f" Remainder: {der_data.hex()}" if verbose else ""
        raise BadAsn1Data(
            f"Error decoding data for {type(asn1_spec)}.{remainder}",
            overwrite=True,
        ) from exc


def prepare_bit_string(
    value: Union[bytes, str],
    target: Optional[univ.BitString] = None,
) -> univ.BitString:
    """Build (or repopulate) a ``univ.BitString`` from raw bytes.

    When ``target`` is provided (typically a ``BitString`` already carrying
    subtype tagging from an ASN.1 module), its tag set is preserved via
    ``clone``. When ``target`` is ``None``, a fresh ``BitString`` is returned.

    :param value: Raw bytes (or a hex string) to encode as the bit-string content.
    :param target: Optional pre-tagged ``BitString`` to populate.
    :returns: A ``univ.BitString`` carrying the supplied bits.
    """
    raw = bytes.fromhex(value) if isinstance(value, str) else value
    bits = univ.BitString.fromOctetString(raw) if raw else univ.BitString("")
    if target is None:
        return bits
    return target.clone(value=bits)


def get_asn1_bytes_value(item: Union[univ.BitString, univ.OctetString, univ.Any]) -> bytes:
    """Return the raw octet payload of a ``BitString``, ``OctetString``, or ``univ.Any``.

    :param item: Source value.
    :returns: The underlying octets.
    :raises TypeError: If ``item`` is not one of the supported pyasn1 types.
    """
    if not isinstance(item, (univ.BitString, univ.OctetString, univ.Any)):
        raise TypeError(f"Expected univ.BitString, univ.OctetString, or univ.Any; got {type(item).__name__}.")
    return item.asOctets()


__all__ = [
    "encode_to_der",
    "try_decode_pyasn1",
    "prepare_bit_string",
    "get_asn1_bytes_value",
]
