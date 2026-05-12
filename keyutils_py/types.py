# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Type aliases for keyutils-py.

Copy of ``cmp-test-suite/resources/typingutils.py``, trimmed to the aliases
needed by keyutils-py: PQ, stateful-hash, and hybrid / composite / chempat
key types. CMP-protocol aliases (CertObjOrPath, RecipInfo, etc.) are omitted.
"""

from typing import Union

from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from keyutils_py.keys.abstract_pq import (
    PQSignaturePrivateKey,
    PQSignaturePublicKey,
)
from keyutils_py.keys.abstract_stateful_hash_sig import (
    PQHashStatefulSigPrivateKey,
    PQHashStatefulSigPublicKey,
)
from keyutils_py.keys.abstract_wrapper_keys import (
    ECDHPrivateKey,
    ECDHPublicKey,
    ECSignKey,
    ECVerifyKey,
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    HybridSigPrivateKey,
    HybridSigPublicKey,
    KEMPrivateKey,
    KEMPublicKey,
    WrapperPrivateKey,
    WrapperPublicKey,
)

ECPrivateKey = Union[ECDHPrivateKey, ECSignKey]

TradSignKey = Union[
    RSAPrivateKey,
    ECSignKey,
    DSAPrivateKey,
]
TradVerifyKey = Union[
    RSAPublicKey,
    ECVerifyKey,
    DSAPublicKey,
]
TradPrivateKey = Union[TradSignKey, DHPrivateKey, X25519PrivateKey, X448PrivateKey]
TradPublicKey = Union[TradVerifyKey, DHPublicKey, X25519PublicKey, X448PublicKey]

PrivateKey = Union[TradPrivateKey, WrapperPrivateKey]
PublicKey = Union[TradPublicKey, WrapperPublicKey]

SignKey = Union[
    TradSignKey,
    PQSignaturePrivateKey,
    PQHashStatefulSigPrivateKey,
    HybridSigPrivateKey,
]
VerifyKey = Union[
    TradVerifyKey,
    PQSignaturePublicKey,
    PQHashStatefulSigPublicKey,
    HybridSigPublicKey,
]

Strint = Union[str, int]


__all__ = [
    "ECDHPrivateKey",
    "ECDHPublicKey",
    "ECSignKey",
    "ECVerifyKey",
    "ECPrivateKey",
    "TradPrivateKey",
    "TradPublicKey",
    "TradSignKey",
    "TradVerifyKey",
    "PrivateKey",
    "PublicKey",
    "SignKey",
    "VerifyKey",
    "Strint",
    "KEMPrivateKey",
    "KEMPublicKey",
    "HybridSigPrivateKey",
    "HybridSigPublicKey",
    "HybridKEMPrivateKey",
    "HybridKEMPublicKey",
]
