<!-- SPDX-FileCopyrightText: Copyright 2026
SPDX-License-Identifier: Apache-2.0 -->

# Changelog

# Unreleased

## Added

- `keyutils_py.types` now exports every concrete key class (`MLDSAPrivateKey`,
  `CompositeSigPrivateKey`, `ChempatPrivateKey`, ...) next to the key aliases, so a
  consumer imports key types from this one module instead of from `keyutils_py.keys.*`.
  The classes are resolved lazily, because the key and factory modules import the aliases
  from `types.py` and an eager import would be circular.
- `KeyUtilsError` and its subclasses carry the RFC 4210 `PKIFailureInfo` name and bit
  (`failinfo`, `bit_num`, `get_failinfo()`, `get_error_details()`), as plain data. A consumer
  that builds protocol responses can use `KeyUtilsError` as the root of its own exception
  hierarchy and get one class identity for the errors raised in this package.
- `CombinedKeyFactory` (`keyutils_py.factories`), the facade that creates, saves and loads every key type
  (traditional, post-quantum, stateful hash-based and hybrid) by dispatching to the other factories.
- `TradKeyFactory` can load and save keys: `load_public_key_from_spki`, `parse_trad_key_from_one_asym_key`,
  `save_private_key_one_asym_key` and `prepare_invalid_trad_private_key`. DSA and DH keys are loaded as the
  `DSAPrivateKey` / `DHPrivateKey` wrappers directly.
- `generate_key`, `save_key`, `load_private_key_from_one_asym_key`, `load_public_key_from_spki` and
  `load_private_key_from_file` in `keyutils_py.keyutils` work for every key type, not only the post-quantum and
  hybrid ones, and `generate_key` accepts a `seed`. Their Robot Framework documentation is in the docstrings.
- `load_private_key_from_file` takes the kind of key from the PEM label. It reads PKCS#8 (plain or
  `ENCRYPTED PRIVATE KEY`), the `<NAME> PRIVATE KEY` blocks of post-quantum and hybrid keys, the traditional
  OpenSSL `RSA`, `EC` and `DSA` blocks, and ignores text around the block (e.g. a license header).
- `load_enc_key` reads the `Proc-Type`/`DEK-Info` encrypted PEM format that `prepare_enc_key_pem` writes, next to
  PKCS#8, so existing key files can be loaded.
- `HybridKeyFactory.get_all_kem_coms_as_dict` and `HybridKeyFactory.get_pq_and_trad_name` (formerly the private
  `_get_pq_and_trad_name`) are public.
- `DHPrivateKey` and `DHPublicKey` are in `KEY_CLASS_MAPPING`, so `get_key_name` knows them.
- `DSAPrivateKey` defines `__eq__` and `__hash__`, like the other key wrappers.

## Changed

- `InvalidKeyCombination` now derives from `BadAlg`, which it is a specialisation of.
- `BadAsn1Data` accepts a keyword-only `failinfo`.
- `generate_key` defaults to `rsa` instead of `hss`.
- `PQPrivateKey.private_bytes` writes the standardised `Choice` for ML-DSA and ML-KEM keys (the seed if the key has
  one, else the expanded key), the only form `PQKeyFactory` reads back. The name to structure mapping is
  `keyutils_py.data_objects.ML_PRIVATE_KEY_STRUCTURES`.
- FrodoKEM no longer requires `liboqs` at the `keyutils` functions, because `keyutils_py.fips.frodokem` is a
  pure Python implementation.

## Fixed

- Generating a composite key by name raises `InvalidKeyCombination` for a combination that is not allowed,
  instead of returning a key whose OID cannot be built.
- Loading the traditional part of a composite key checks for trailing data and the RSA key size, and reports
  every failure as `InvalidKeyData`.
- A malformed public key inside the `OneAsymmetricKey` of a composite key raises `InvalidKeyData` instead of the
  bare `ValueError` of `cryptography`, and a composite KEM public key with the wrong RSA key size is rejected.
- A composite signature public key whose RSA key does not have the size named by the OID (e.g. a 512-bit key under
  a `rsa2048` OID) raises `InvalidKeyData` when its `SubjectPublicKeyInfo` is loaded.
- `check_consistency_sig_alg_id_and_key` accepts the pure SLH-DSA OIDs. `get_hash_from_oid` returned the hash of the
  parameter set for them, which made the check look for a pre-hash name that does not match the OID; it now returns
  `None` for an OID without an embedded hash, like for the pure ML-DSA OIDs. The unused `SLH_DSA_HASH_MAPPING` is removed.

- The pure-Python FrodoKEM implementation now works with `bitstring` 5: the remaining
  `BitArray(length=...)` calls in `__bytes_to_bit_array` and `decode`, and the removed
  `ConstBitStream` in `kem_decaps`, are replaced.
- Malformed ML-DSA / ML-KEM key material (for example a public key of the wrong length) raises
  `InvalidKeyData` instead of the bare `ValueError` raised by `cryptography`.

# 0.0.2

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

- New public functions, exported from `keyutils_py`:
  - `load_private_key_from_one_asym_key`: loads a private key from a
    `OneAsymmetricKey`, given as DER bytes or a decoded structure.
  - `load_public_key_from_spki`: loads a public key from a
    `SubjectPublicKeyInfo`, given as DER bytes or a decoded structure.
    `load_public_key_from_file` now uses it.
  - `check_consistency_sig_alg_id_and_key`: raises `BadSigAlgID` when a
    signature `AlgorithmIdentifier` does not match the given key.

  Like the file loaders, the two loaders support PQ, stateful-hash, hybrid and
  DSA keys; other traditional keys raise `NotImplementedError`.

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
