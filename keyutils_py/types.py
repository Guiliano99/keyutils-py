# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Type aliases and the single access point for the key types of keyutils-py.

Copy of ``cmp-test-suite/resources/typingutils.py``, trimmed to the aliases
needed by keyutils-py: PQ, stateful-hash, and hybrid / composite / chempat
key types. CMP-protocol aliases (CertObjOrPath, RecipInfo, etc.) are omitted.

Consumers import every key class and key alias from here
(``from keyutils_py.types import MLDSAPrivateKey, SignKey``) instead of from
the ``keyutils_py.keys.*`` modules, so those modules stay an internal detail.
"""

import importlib
from typing import TYPE_CHECKING, Any, Union

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
from keyutils_py.keys.trad_keys import DHPrivateKey, DHPublicKey, DSAPrivateKey, DSAPublicKey

if TYPE_CHECKING:
    from keyutils_py.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
    from keyutils_py.keys.abstract_wrapper_keys import (
        AbstractCompositePrivateKey,
        AbstractCompositePublicKey,
        AbstractHybridRawPrivateKey,
        AbstractHybridRawPublicKey,
        HybridPrivateKey,
        HybridPublicKey,
        PQPrivateKey,
        PQPublicKey,
        TradKEMPrivateKey,
        TradKEMPublicKey,
    )
    from keyutils_py.keys.chempat_key import (
        ChempatFrodoKEMPrivateKey,
        ChempatFrodoKEMPublicKey,
        ChempatMcEliecePrivateKey,
        ChempatMcEliecePublicKey,
        ChempatMLKEMPrivateKey,
        ChempatMLKEMPublicKey,
        ChempatPrivateKey,
        ChempatPublicKey,
        ChempatSntrup761PrivateKey,
        ChempatSntrup761PublicKey,
    )
    from keyutils_py.keys.composite_kem import CompositeKEMPrivateKey, CompositeKEMPublicKey
    from keyutils_py.keys.composite_sig import CompositeSigPrivateKey, CompositeSigPublicKey
    from keyutils_py.keys.kem_keys import (
        FrodoKEMPrivateKey,
        FrodoKEMPublicKey,
        McEliecePrivateKey,
        McEliecePublicKey,
        MLKEMPrivateKey,
        MLKEMPublicKey,
        Sntrup761PrivateKey,
        Sntrup761PublicKey,
    )
    from keyutils_py.keys.sig_keys import (
        FalconPrivateKey,
        FalconPublicKey,
        MLDSAPrivateKey,
        MLDSAPublicKey,
        SLHDSAPrivateKey,
        SLHDSAPublicKey,
    )
    from keyutils_py.keys.stateful_sig_keys import (
        HSSPrivateKey,
        HSSPublicKey,
        XMSSMTPrivateKey,
        XMSSMTPublicKey,
        XMSSPrivateKey,
        XMSSPublicKey,
    )
    from keyutils_py.keys.trad_kem_keys import DHKEMPrivateKey, DHKEMPublicKey, RSADecapKey, RSAEncapKey
    from keyutils_py.keys.xwing import XWingPrivateKey, XWingPublicKey

# The concrete key classes are resolved lazily (PEP 562). The key and factory modules import the
# aliases below from this module, so importing the classes eagerly here would be a circular import.
_LAZY_EXPORTS: dict[str, tuple[str, ...]] = {
    "keyutils_py.keys.abstract_pq": ("PQKEMPrivateKey", "PQKEMPublicKey"),
    "keyutils_py.keys.abstract_wrapper_keys": (
        "AbstractCompositePrivateKey",
        "AbstractCompositePublicKey",
        "AbstractHybridRawPrivateKey",
        "AbstractHybridRawPublicKey",
        "HybridPrivateKey",
        "HybridPublicKey",
        "PQPrivateKey",
        "PQPublicKey",
        "TradKEMPrivateKey",
        "TradKEMPublicKey",
    ),
    "keyutils_py.keys.chempat_key": (
        "ChempatFrodoKEMPrivateKey",
        "ChempatFrodoKEMPublicKey",
        "ChempatMcEliecePrivateKey",
        "ChempatMcEliecePublicKey",
        "ChempatMLKEMPrivateKey",
        "ChempatMLKEMPublicKey",
        "ChempatPrivateKey",
        "ChempatPublicKey",
        "ChempatSntrup761PrivateKey",
        "ChempatSntrup761PublicKey",
    ),
    "keyutils_py.keys.composite_kem": ("CompositeKEMPrivateKey", "CompositeKEMPublicKey"),
    "keyutils_py.keys.composite_sig": ("CompositeSigPrivateKey", "CompositeSigPublicKey"),
    "keyutils_py.keys.kem_keys": (
        "FrodoKEMPrivateKey",
        "FrodoKEMPublicKey",
        "McEliecePrivateKey",
        "McEliecePublicKey",
        "MLKEMPrivateKey",
        "MLKEMPublicKey",
        "Sntrup761PrivateKey",
        "Sntrup761PublicKey",
    ),
    "keyutils_py.keys.sig_keys": (
        "FalconPrivateKey",
        "FalconPublicKey",
        "MLDSAPrivateKey",
        "MLDSAPublicKey",
        "SLHDSAPrivateKey",
        "SLHDSAPublicKey",
    ),
    "keyutils_py.keys.stateful_sig_keys": (
        "HSSPrivateKey",
        "HSSPublicKey",
        "XMSSMTPrivateKey",
        "XMSSMTPublicKey",
        "XMSSPrivateKey",
        "XMSSPublicKey",
    ),
    "keyutils_py.keys.trad_kem_keys": ("DHKEMPrivateKey", "DHKEMPublicKey", "RSADecapKey", "RSAEncapKey"),
    "keyutils_py.keys.xwing": ("XWingPrivateKey", "XWingPublicKey"),
}
_LAZY_MODULE_OF = {name: module for module, names in _LAZY_EXPORTS.items() for name in names}


def __getattr__(name: str) -> Any:
    """Resolve a lazily exported key class on first access."""
    module = _LAZY_MODULE_OF.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value


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

# This is a "stringified integer", to make it easier to pass numeric data
# to RobotFramework keywords. Normally, if you want
# to pass an integer, you have to write it as `${45}` - which hinders readability.
# With a stringified integer, we provide
# some syntactic sugar, enabling both notations: `${45}` and `45`.
Strint = Union[str, int]


__all__ = [
    "AbstractCompositePrivateKey",
    "AbstractCompositePublicKey",
    "AbstractHybridRawPrivateKey",
    "AbstractHybridRawPublicKey",
    "ChempatFrodoKEMPrivateKey",
    "ChempatFrodoKEMPublicKey",
    "ChempatMLKEMPrivateKey",
    "ChempatMLKEMPublicKey",
    "ChempatMcEliecePrivateKey",
    "ChempatMcEliecePublicKey",
    "ChempatPrivateKey",
    "ChempatPublicKey",
    "ChempatSntrup761PrivateKey",
    "ChempatSntrup761PublicKey",
    "CompositeKEMPrivateKey",
    "CompositeKEMPublicKey",
    "CompositeSigPrivateKey",
    "CompositeSigPublicKey",
    "DHKEMPrivateKey",
    "DHKEMPublicKey",
    "DHPrivateKey",
    "DHPublicKey",
    "DSAPrivateKey",
    "DSAPublicKey",
    "ECDHPrivateKey",
    "ECDHPublicKey",
    "ECPrivateKey",
    "ECSignKey",
    "ECVerifyKey",
    "FalconPrivateKey",
    "FalconPublicKey",
    "FrodoKEMPrivateKey",
    "FrodoKEMPublicKey",
    "HSSPrivateKey",
    "HSSPublicKey",
    "HybridKEMPrivateKey",
    "HybridKEMPublicKey",
    "HybridPrivateKey",
    "HybridPublicKey",
    "HybridSigPrivateKey",
    "HybridSigPublicKey",
    "KEMPrivateKey",
    "KEMPublicKey",
    "MLDSAPrivateKey",
    "MLDSAPublicKey",
    "MLKEMPrivateKey",
    "MLKEMPublicKey",
    "McEliecePrivateKey",
    "McEliecePublicKey",
    "PQHashStatefulSigPrivateKey",
    "PQHashStatefulSigPublicKey",
    "PQKEMPrivateKey",
    "PQKEMPublicKey",
    "PQPrivateKey",
    "PQPublicKey",
    "PQSignaturePrivateKey",
    "PQSignaturePublicKey",
    "PrivateKey",
    "PublicKey",
    "RSADecapKey",
    "RSAEncapKey",
    "SLHDSAPrivateKey",
    "SLHDSAPublicKey",
    "SignKey",
    "Sntrup761PrivateKey",
    "Sntrup761PublicKey",
    "Strint",
    "TradKEMPrivateKey",
    "TradKEMPublicKey",
    "TradPrivateKey",
    "TradPublicKey",
    "TradSignKey",
    "TradVerifyKey",
    "VerifyKey",
    "WrapperPrivateKey",
    "WrapperPublicKey",
    "XMSSMTPrivateKey",
    "XMSSMTPublicKey",
    "XMSSPrivateKey",
    "XMSSPublicKey",
    "XWingPrivateKey",
    "XWingPublicKey",
]
