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
- `KEM_OID_2_NAME` contains the RSA-KEM OID (`1.0.18033.2.2.4`) as `rsa-kem`, next to the PQ and hybrid KEMs.
- `keyutils_py.oids` defines the hash, HMAC, KMAC, AES-GMAC, HKDF, AES-CBC/GCM, AES key wrap and CMP protection
  tables and OID constants that cmp-test-suite takes from its own `resources.oidutils` and `pq_logic.tmp_oids`, with
  the same names and the same OIDs: `SHA_OID_2_NAME`, `SHA2_NAME_2_OID`, `HMAC_OID_2_NAME`, `KMAC_OID_2_NAME`,
  `AES_GMAC_NAME_2_OID`, `AES_GMAC_OID_2_NAME`, `HKDF_NAME_2_OID`, `HKDF_OID_2_NAME`, `AES_CBC_OID_2_NAME`,
  `AES_GCM_OID_2_NAME`, `KEY_WRAP_NAME_2_OID`, `KEY_WRAP_OID_2_NAME`, `KM_KW_ALG`, `LWCMP_MAC_OID_2_NAME`,
  `SYMMETRIC_PROT_ALGO`, `SYMMETRIC_ENCR_ALG_NAME_2_OID`, `MSG_SIG_ALG`, `SUPPORTED_MAC_OID_2_NAME`,
  `id_KemBasedMac`, `id_it_KemCiphertextInfo` and `id_ce_subjectAltPublicKeyInfo` / `id_ce_altSignatureAlgorithm` /
  `id_ce_altSignatureValue`, plus the building blocks `id_alg`, `SHA2_OID_2_NAME`, `HMAC_SHA_OID_2_NAME`,
  `HMAC_SHA3_OID_2_NAME`, `AES_CBC_NAME_2_OID`, `AES_GCM_NAME_2_OID` and `SYMMETRIC_ENCR_ALG_OID_2_NAME`.
  `tests/golden/oid_tables.tsv` holds the cmp-test-suite values; `tests/golden/generate_oid_tables.py` rewrites it
  and is run by hand from a cmp-test-suite checkout.
- `ALG_OID_2_NAME`, one OID -> name table for every OID the tables of `keyutils_py.oids` name. It is built from OID
  -> name tables only and has no entry that maps a name to an OID, unlike `ALL_KNOWN_OIDS_2_NAME` of cmp-test-suite.

## Changed

- `InvalidKeyCombination` now derives from `BadAlg`, which it is a specialisation of.
- `BadAsn1Data` accepts a keyword-only `failinfo`.
- `generate_key` defaults to `rsa` instead of `hss`.
- `PQPrivateKey.private_bytes` writes the standardised `Choice` for ML-DSA and ML-KEM keys (the seed if the key has
  one, else the expanded key), the only form `PQKeyFactory` reads back. The name to structure mapping is
  `keyutils_py.data_objects.ML_PRIVATE_KEY_STRUCTURES`.
- FrodoKEM no longer requires `liboqs` at the `keyutils` functions, because `keyutils_py.fips.frodokem` is a
  pure Python implementation.
- `may_return_oid_to_name` reads `ALG_OID_2_NAME` and names the hash, MAC, AES, key wrap, HKDF and traditional
  signature OIDs (for example `rsa-sha256` and `hmac-sha256`), where it returned the dotted string before. It named
  106 of the 203 OIDs that cmp-test-suite names and now names 163 of them, with the same names; the extension, key
  agreement, curve and PBKDF2/KDF2/KDF3 OIDs still come back as the dotted string.
- The version is `0.1.0`. An SPKI or PKCS#8 key with the old RSA-KEM OID is not accepted any more (see Fixed), so
  `0.0.2` is not compatible with it.

## Fixed

- Generating a composite key by name raises `InvalidKeyCombination` for a combination that is not allowed,
  instead of returning a key whose OID cannot be built.
- Loading the traditional part of a composite key checks for trailing data and the RSA key size, and reports
  every failure as `InvalidKeyData`.
- A malformed public key inside the `OneAsymmetricKey` of a composite key raises `InvalidKeyData` instead of the
  bare `ValueError` of `cryptography`, and a composite KEM public key with the wrong RSA key size is rejected.
- A composite signature public key whose RSA key does not have the size named by the OID (e.g. a 512-bit key under
  a `rsa2048` OID) raises `InvalidKeyCombination` when its `SubjectPublicKeyInfo` is loaded, like the composite KEM
  public key.
- `check_consistency_sig_alg_id_and_key` accepts the pure SLH-DSA OIDs. `get_hash_from_oid` returned the hash of the
  parameter set for them, which made the check look for a pre-hash name that does not match the OID; it now returns
  `None` for an OID without an embedded hash, like for the pure ML-DSA OIDs. The unused `SLH_DSA_HASH_MAPPING` is removed.

- Malformed ML-DSA / ML-KEM key material (for example a public key of the wrong length) raises
  `InvalidKeyData` instead of the bare `ValueError` raised by `cryptography`.
- `compute_hash`, `sha_alg_name_to_oid`, `get_hash_from_oid` and `hash_name_to_instance` read one hash registry.
  Three tables disagreed before: `compute_hash` had no SHA-1 and no SHA-3 (`ValueError`), `sha_alg_name_to_oid` and
  `get_hash_from_oid` had no SHA-3 (`ValueError` and `None`), while `hash_name_to_instance` knew all 11 names.
  The registry has SHA-1, SHA-224 to SHA-512, SHA3-224 to SHA3-512 (`2.16.840.1.101.3.4.2.7` to `.10`, RFC 9688)
  and SHAKE128 / SHAKE256 with 32 / 64 bytes of output (RFC 9814 Section 4). Unknown names still raise `ValueError`.
- `id_rsa_kem_spki` is `1.2.840.113549.1.9.16.3.14` (`id-rsa-kem-spki`, RFC 9690 Appendix B). It was
  `1.2.840.113549.1.9.16.3`, which is the `id-alg` arc. `RSAEncapKey.get_oid()`, `prepare_spki` with the key name
  `rsa-kem` (also for a KGA) and the RSA-KEM `OneAsymmetricKey` use the RFC value, so an RSA-KEM key of another
  implementation loads, where `load_public_key_from_spki` raised `UnsupportedAlgorithm` before. The old OID is not
  accepted any more: keys written by `0.0.2` with it have to be written again. `1.2.840.113549.1.9.16.3.14` is named
  `rsa-kem` by `may_return_oid_to_name`, like `1.0.18033.2.2.4` (`id-kem-rsa`, the KEM algorithm itself).

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
  [draft-ietf-lamps-frodokem-certificates-00](https://www.ietf.org/archive/id/draft-ietf-lamps-frodokem-certificates-00.txt)
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

## Fixed

- The pure-Python FrodoKEM implementation works with `bitstring` 4 and 5: the
  `BitArray(length=...)` / `BitArray(n)` calls and the `ConstBitStream` read of
  the secret key, which `bitstring` 5 removed, are replaced.

## Not supported

- The eFrodoKEM-976/1344 variants: the draft assigns them OIDs (`.3`, `.4`,
  `.7`, `.8`), but they are not relevant for certificates and neither `liboqs`
  nor the bundled implementation provides them.

# 0.0.1

- Created
