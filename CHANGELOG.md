<!-- SPDX-FileCopyrightText: Copyright 2026
SPDX-License-Identifier: Apache-2.0 -->

# Changelog

# Unreleased

## Added

- DSA wrapper classes `DSAPrivateKey` and `DSAPublicKey` in
  `keyutils_py/keys/trad_keys.py`, backed by `pycryptodome`. They replace the
  `cryptography` DSA classes throughout the package.

  Why: `cryptography` has deprecated DSA and announced its removal in an
  upcoming release. Several modules checked keys with the `cryptography` DSA
  classes, so the removal would have broken the package at import time, not
  only DSA signing. `pycryptodome` was already a dependency.

  - The wrappers keep the call shapes of the `cryptography` classes:
    `sign(data, hash_alg)`, `verify(signature, data, hash_alg)`,
    `private_bytes`, `public_bytes` and `public_key()`. Both keys expose
    `key_size`; the public key also exposes `p`, `q`, `g` and `y`, and the
    private key `x`, all as integers.
  - `hash_alg` is a string such as `"sha256"`; a `cryptography` hash instance
    is also accepted.
  - Signing supports only SHA-256 and raises `ValueError` for any other hash.
    Verification also accepts SHA-1, SHA-224, SHA-384 and SHA-512, so
    signatures made by other implementations can still be checked. This is
    stricter than `cryptography`, which signed with any hash.
  - A failed verification raises `cryptography.exceptions.InvalidSignature`.
  - Keys load from PEM or DER in PKCS#8, `DSA PRIVATE KEY` and
    SubjectPublicKeyInfo form, including encrypted PKCS#8. The file loaders
    `load_private_key_from_file` and `load_public_key_from_file` now handle
    DSA, and `generate_trad_key("dsa")` returns the wrapper.
  - Behavior difference: `pycryptodome` generates only 1024, 2048 and 3072
    bit keys, and a 2048-bit key uses a 224-bit subprime `q`, where
    `cryptography` used 256 bits. Keys from other sources verify normally.
  - Signing with an AlgorithmIdentifier is still not supported for DSA, as
    before.

## Changed

- FrodoKEM algorithm identifiers now follow
  [draft-smyslov-lamps-frodokem-certificates-03](https://www.ietf.org/archive/id/draft-smyslov-lamps-frodokem-certificates-03.txt)
  (ISO/IEC 18033-2 KEM arc `1.0.18033.2.2.7`) instead of the former ad-hoc
  test-suite arc. The old FrodoKEM OIDs are no longer recognised.

  | Name                  | OID                   |
  |-----------------------|-----------------------|
  | `frodokem-976-shake`  | `1.0.18033.2.2.7.1`   |
  | `frodokem-1344-shake` | `1.0.18033.2.2.7.2`   |
  | `frodokem-976-aes`    | `1.0.18033.2.2.7.5`   |
  | `frodokem-1344-aes`   | `1.0.18033.2.2.7.6`   |

- The Chempat FrodoKEM composite OIDs were renumbered without gaps after the
  removals below (`chempat-frodokem-976-aes-x25519` and
  `chempat-frodokem-976-shake-x25519` keep their OIDs).

## Removed

These FrodoKEM versions are no longer supported because the draft assigns them
no OID, so they cannot be used in X.509 / PKIX structures:

- `frodokem-640-aes` and `frodokem-640-shake`: key generation, loading and all
  hybrid combinations.
- `chempat-frodokem-640-aes-ecdh-brainpoolP256r1` and
  `chempat-frodokem-640-shake-ecdh-brainpoolP256r1`.

## Not supported

- The eFrodoKEM-976/1344 variants: draft -03 assigns them OIDs (`.3`, `.4`,
  `.7`, `.8`), but they are not relevant for certificates and neither `liboqs`
  nor the bundled implementation provides them.

# 0.0.1

- Created
