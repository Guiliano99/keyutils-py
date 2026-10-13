<!--
SPDX-FileCopyrightText: Copyright 2026

SPDX-License-Identifier: Apache-2.0
-->
# keyutils-py

Key-management utilities for traditional, post-quantum and hybrid cryptographic
keys: generation, naming, serialization and dispatch. Drop-in key layer for the
cmp-test-suite.

## Language

**Hybrid key**:
A key that pairs a PQ half with a traditional half under one algorithm
identifier. The four families are composite signature, composite KEM, Chempat
and X-Wing.
_Avoid_: combined key, dual key

**PQ half**:
The post-quantum component of a hybrid key (e.g. ML-DSA, ML-KEM, FrodoKEM).
_Avoid_: pq part, quantum key

**Traditional key**:
A bare classical asymmetric key (RSA, DSA, EC, Ed25519/Ed448, X25519/X448, DH)
used on its own. Not every traditional key can be a traditional half: DSA is
sign-only and never pairs with a PQ half.
_Avoid_: classical key, conventional key, legacy key

**Traditional half**:
The classical component of a hybrid key (RSA, EC, Ed25519/Ed448, X25519/X448),
whether held bare or inside a KEM adapter.
_Avoid_: classical key, trad part, conventional key

**Trad name fragment**:
The trailing component of a hybrid algorithm name that identifies the
traditional half. Canonical spellings: `rsa2048`/`rsa3072`/`rsa4096` (modulus
rounded to the nearest bucket; `-pss` suffix only for RSA-PSS signature
lookups), `ecdsa-<curve>` for signatures, `ecdh-<curve>` for KEMs (curve names
keep `cryptography`'s casing, e.g. `brainpoolP256r1`), and `ed25519`, `ed448`,
`x25519`, `x448`.
_Avoid_: hyphenated RSA forms (`rsa-2048`), lowercased brainpool curve names

**Raw hybrid**:
A hybrid KEM family (Chempat, X-Wing) whose keys serialize as concatenated raw
halves rather than ASN.1 structures.

**KEM adapter**:
A wrapper that gives a bare traditional key a KEM interface (encaps/decaps,
canonical naming, wire encoding); DHKEM and RSA-KEM adapters exist.
_Avoid_: KEM wrapper class names when the role is meant

**Owning factory**:
The single key factory that claims an algorithm name, OID or key type; the
dispatch layer asks each family's factory in a fixed order and routes to the
first owner.
