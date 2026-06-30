# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Custom exceptions for keyutils-py.

Trimmed copy of ``cmp-test-suite/resources/exceptions.py`` plus a new
:class:`MissingOQSDependencyError` raised at the dispatch boundary when
liboqs (``oqs``) is not installed and a XMSS/XMSSMT operation is attempted.
"""

from typing import List, Optional, Union


class KeyUtilsError(Exception):
    """Base class for keyutils-py errors."""

    def __init__(
        self,
        message: str,
        error_details: Optional[Union[List[str], str]] = None,
    ) -> None:
        """Initialise the error.

        :param message: Human-readable error description.
        :param error_details: Optional supplementary detail entries. A single
            string is wrapped into a one-element list.
        """
        self.message = message
        if error_details is None:
            self.error_details: List[str] = []
        elif isinstance(error_details, str):
            self.error_details = [error_details]
        else:
            self.error_details = list(error_details)
        super().__init__(message)


class BadAlg(KeyUtilsError):
    """Raised when an algorithm is not supported or not allowed."""


class BadSigAlgID(KeyUtilsError):
    """Raised when the algorithm identifier and signing key do not match."""


class BadSigAlgIDParams(BadSigAlgID):
    """Raised when the algorithm identifier parameters are invalid."""


class BadDataFormat(KeyUtilsError):
    """Raised when ASN.1 data cannot be decoded."""


class BadAsn1Data(KeyUtilsError):
    """Raised when ASN.1 data has a remainder or is incorrectly populated."""

    def __init__(
        self,
        message: str,
        remainder: Optional[bytes] = None,
        overwrite: bool = False,
        error_details: Optional[Union[List[str], str]] = None,
    ) -> None:
        """Initialise the error.

        :param message: Either a free-form description (when ``overwrite`` is
            true) or the name of the ASN.1 structure being decoded.
        :param remainder: Trailing bytes left over after decoding, used to
            build the default message.
        :param overwrite: When true, ``message`` is used verbatim instead of
            being wrapped in the default "had a remainder" template.
        :param error_details: Optional supplementary detail entries.
        """
        if overwrite:
            super().__init__(message=message, error_details=error_details)
        else:
            r = "" if remainder is None else remainder.hex()
            super().__init__(
                f"Decoding the `{message}` structure had a remainder: {r}.",
                error_details=error_details,
            )


class InvalidKeyData(BadDataFormat):
    """Raised when a key cannot be loaded or decoded."""


class MismatchingKey(InvalidKeyData):
    """Raised when a loaded public key does not match the private key."""


class InvalidJWK(InvalidKeyData):
    """Raised when a JWK is malformed or a key cannot be represented as a JWK."""


class InvalidKeyCombination(KeyUtilsError):
    """Raised when a hybrid key combination is invalid or unsupported."""


class MissingOQSDependencyError(ImportError):
    """Raised when an XMSS/XMSSMT operation is attempted without liboqs.

    Subclasses :class:`ImportError` so existing ``except ImportError`` callers
    continue to work, and so it is unmistakably a missing-dependency error.
    """

    def __init__(self, algorithm: str) -> None:
        """Initialise the error.

        :param algorithm: Name of the algorithm whose backend is missing.
        """
        message = (
            f"liboqs (oqs) is required for {algorithm}. Install the `pq` extra:\n"
            "    pip install 'keyutils-py[pq]'\n"
            "HSS/LMS algorithms work without liboqs."
        )
        self.algorithm = algorithm
        super().__init__(message)
