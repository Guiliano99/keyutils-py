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
- `keyutils_py.oids.SIG_ALG_OID_2_INFO`: one `SigAlgInfo` row for every signature OID (81: the 80 OIDs of
  `SIG_ALG_OID_2_PARAMETERS_SPEC` and `rsaEncryption`, RFC 3370 Section 3.2), derived once at import from the OID
  tables. A row names the family, the key that may use it, the hash, whether the OID is a pre-hash OID (HashML-DSA,
  HashSLH-DSA), whether it is RSASSA-PSS, the shape of the parameters and the CMS `digestAlgorithm`. Signing,
  verifying, the consistency check and the identifier builder all read it. `tests/golden/sig_alg_table.tsv` holds the
  rows as written from the RFCs (`tests/golden/generate_sig_alg_table.py`), not derived from the code.
  A new algorithm of a known family needs its OID in the family table and one golden row.
- `get_sig_alg_info(alg_id, *, strict=False)` returns the row of a signature OID or `AlgorithmIdentifier`; for
  `id-RSASSA-PSS` it reads hash, MGF1 hash and salt length from the parameters with the DEFAULT values of RFC 4055
  Section 3.1. `list_algorithms("sig")` (`keyutils_py.algorithms`) returns all rows sorted by OID; another kind
  raises `ValueError` naming the known kinds.
- `sign_with_alg_id` and `verify_signature_with_alg_id` take the keyword-only `hash_alg`, the hash for `rsaEncryption`
  (it names none), which is accepted as an identifier of RSA PKCS#1 v1.5.
- `validate_sig_alg_id(alg_id, *, strict=True)`: `strict=False` is the rule of verifiers (absent parameters on the
  PKCS#1 v1.5 identifiers are accepted, RFC 4055 Section 5, RFC 5754 Section 3.2).
- `prepare_hash_alg_id(..., *, with_null=None)`: `False` writes absent parameters (RFC 5754 Section 2), `True` NULL
  (SHA-1 and SHA-2 only; `ValueError` for SHA-3 and SHAKE), `None` keeps the bytes written before.
- `prepare_sig_alg_id` builds the identifier for every signature key: ML-DSA, SLH-DSA (with the pre-hash OID if the
  hash is one that the key registers), Falcon, HSS, XMSS, XMSS^MT and composite keys (`use_rsa_pss` selects the
  `-pss` OID).
- Exported from `keyutils_py` as well (the names that other code imported by module path): `encode_to_der`,
  `try_decode_pyasn1`, `BadAsn1Data`, `BadAlg`, `BadSigAlgID`, `BadSigAlgIDParams`, `KeyUtilsError`,
  `prepare_sig_alg_id`, `prepare_hash_alg_id`, `get_hash_from_oid`, `sha_alg_name_to_oid`, `RSA_OID_2_NAME`,
  `PublicKey`, `SignKey`, `VerifyKey`, `TradVerifyKey` and `DSAPublicKey`, plus `SigAlgInfo`, `SIG_ALG_OID_2_INFO`,
  `get_sig_alg_info` and `list_algorithms`. The module paths keep working. `tests/test_public_api.py` pins
  `keyutils_py.__all__` and the signatures of the signature entry points against `tests/golden/public_api.tsv`.
- `tests/test_negative_output.py` shows that every deviation a negative test makes (flipped, longer, shorter,
  omitted signature; random or NULL parameters; other hash, other OID, other padding, unknown OID, broken or other PSS
  parameters; other key; other context; omitted identifier; legacy SHA-1 and DSA) is produced by explicit calls on a
  valid pair, and that every one is refused as a verifier refuses it.
- The algorithm tables of the key derivation functions (HKDF with SHA-2 and SHA-3, KDF2, KDF3, PBKDF2), the MACs (HMAC
  with SHA-1, SHA-2 and SHA-3, KMAC128/256, AES-GMAC, PBMAC1), AES key wrap (RFC 3394) and key wrap with padding
  (RFC 5649), AES-CBC and AES-GCM, the key agreement schemes of RFC 5753 (12, plus `id-X25519`, `id-X448` and
  `id-alg-ESDH`, which name no hash) and the RSA key transport algorithms, in the private module `keyutils_py/_algs.py`.
  One frozen row per OID with structured fields (a family, a hash by the name of the hash registry, a size), and the
  inverse indexes generated at import, so no code splits a name such as `hkdf-sha3-256` to find the hash. HMAC-SHA1 has
  two rows, `hMAC-SHA1` (RFC 3370) and `id-hmacWithSHA1` (RFC 8018, the default pseudorandom function of PBKDF2).
  `tests/golden/alg_tables.tsv` holds the 55 rows as written from the RFCs (`tests/golden/generate_alg_tables.py`,
  which also checks every OID against `pyasn1_alt_modules`), not derived from the code.
- `keyutils_py.primitives`, the keyless lower layer: HKDF (SHA-1, SHA-2, SHA-3), KDF2 (X9.63), KDF3, PBKDF2, HMAC,
  KMAC128/256, AES-GMAC, AES key wrap (RFC 3394) and key wrap with padding (RFC 5649), AES-CBC with PKCS#7 padding and
  AES-GCM, each by the name of its hash and on plain bytes, with no `AlgorithmIdentifier`, no OID and no table. It is
  importable but neither in `__all__` nor in the API snapshot: it is how a test makes what the identifier-driven
  functions refuse (a KEK that does not fit the key wrap OID) and how it checks them. It imports `cryptography`,
  `pycryptodome` and `keyutils_py.exceptions` only, which a test checks.
- `BadAlgParams` (the parameters of a known algorithm are absent, present wrongly or inconsistent) and `IntegrityError`
  (a key unwrap, CBC padding, GCM tag or MAC does not verify; the message does not say why) in
  `keyutils_py.exceptions`. Both derive from `KeyUtilsError`.
- `keyutils_py.mechanisms.kdf_derive(kdf, secret, length, info=b"")` derives with the key derivation function that an
  `AlgorithmIdentifier` names: HKDF with SHA-256/384/512 and SHA3-224/256/384/512 (the hash is in the OID, the
  parameters must be absent, RFC 8619, RFC 9688), KDF2 (X9.63) and KDF3 (the hash, SHA-1, SHA-2 or SHA-3, is the
  `AlgorithmIdentifier` in the parameters; SHAKE is `BadAlg`), and PBKDF2. `PBKDF2-params` is decoded with its own
  specification, so it works for an identifier after a DER round trip; an absent `prf` is HMAC-SHA-1 (RFC 8018 Appendix
  A.2 DEFAULT); `keyLength`, if present, must equal `length`; a salt from `otherSource` is `BadAlg`; the iteration
  count is capped at `MAX_PBKDF2_ITERATIONS`; PBKDF2 takes no `info`. An OID in no table is `BadAlg`, parameters that
  are absent, present wrongly or inconsistent are `BadAlgParams`, undecodable ones `BadAsn1Data`. Not yet exported from
  `keyutils_py`.
- `keyutils_py.mechanisms.compute_mac(mac, key, data)`, `verify_mac(mac, key, data, expected, *, allow_sha1=False)`
  and `mac_key_length(mac)` for the MAC an `AlgorithmIdentifier` names: HMAC with SHA-1 (both OIDs), SHA-2 and SHA-3
  (parameters absent, NULL also for SHA-1 and SHA-2), KMAC128/256 (absent parameters mean 256 or 512 bits and no
  customization, `KMACwithSHAKE-params` change both, RFC 8702 Section 3.4), AES-GMAC (the key has the size of the OID,
  the parameters are required, the MAC is the tag cut to the `length` of the parameters, DEFAULT 12 octets, RFC 9044
  Section 3.1) and PBMAC1 (`key` is the password; PBKDF2 with a `keyLength` and an HMAC; an absent `keyLength` is
  `BadAlgParams`, RFC 8018 Section 7.1). `verify_mac` compares with `hmac.compare_digest`, raises `IntegrityError` with
  one message whatever differs, and refuses SHA-1 with `BadAlg` (HMAC, or PBMAC1 over SHA-1 as pseudorandom function or
  HMAC) unless the caller passes `allow_sha1=True`; `compute_mac` does not refuse it. `mac_key_length` is 16, 24 or 32
  for AES-GMAC and `None` otherwise. Not yet exported from `keyutils_py`.
- `keyutils_py.mechanisms.wrap_cek(wrap, kek, cek)`, `unwrap_cek(wrap, kek, wrapped)` and `wrap_key_length(wrap)` for
  AES key wrap (RFC 3394, `id-aes128/192/256-wrap`) and AES key wrap with padding (RFC 5649,
  `id-aes128/192/256-wrap-pad`). The KEK must have the size that the OID names (`BadAlgParams` otherwise, also on
  unwrap), the identifier must have no parameters (RFC 3565 Section 2.3.2), and an unwrap that does not verify, for
  whatever reason, is `IntegrityError` with one message. Key wrap with padding wraps a key of any size from 1 octet, key
  wrap one of a multiple of 8 octets from 16 (`ValueError` otherwise).
- `keyutils_py.mechanisms.encrypt_content(enc, cek, plaintext, *, aad=None)`, `decrypt_content(enc, cek, ciphertext, *,
  tag=None, aad=None)` and the frozen `Encrypted(ciphertext, tag=None)` for AES-CBC with PKCS#7 padding (the parameters
  are the 16 octet IV, RFC 3565, RFC 9481 Section 5.1) and AES-GCM (`GCMParameters`: a nonce of 8 to 128 octets and
  `aes-ICVlen`, DEFAULT 12; the tag is cut to that length, RFC 5084). The key must have the size of the OID. A CBC
  padding or length error and a GCM tag error are `IntegrityError` with one message, so that they are no padding oracle.
  `aad` or `tag` for AES-CBC, and a missing `tag` for AES-GCM, are a `TypeError`. Not yet exported from `keyutils_py`.

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
- Breaking for consumers of `sign_data`, `verify_signature`, `sign_with_alg_id`, `verify_signature_with_alg_id`,
  `check_consistency_sig_alg_id_and_key`, `validate_sig_alg_id` and `prepare_sig_alg_id` that pin an older commit
  (nothing changes until they bump):
  - `verify_signature_with_alg_id` still refuses `sha1WithRSAEncryption` with `BadAlg`, and now refuses every
    SHA-1 signature the same way: `rsaEncryption` with `hash_alg="sha1"`, and RSASSA-PSS with SHA-1 (it was
    verified before), the RFC 4055 Section 3.1 defaults included. The new keyword-only `allow_sha1=True` verifies
    them; the caller that accepts SHA-1 says so. Signing and `verify_signature` are not restricted.
  - A PQ, stateful-hash or composite key with an OID of another family or another parameter set raises `BadSigAlgID`
    in `sign_with_alg_id` and `verify_signature_with_alg_id` (it signed and verified under any OID, or raised
    `TypeError` for a composite OID). An ML-DSA key with an ML-DSA OID of another parameter set and a composite key
    with the OID of another combination are refused the same way.
  - A pre-hash OID (`id-ml-dsa-44-with-sha512`, the HashSLH-DSA OIDs) signs and verifies in pre-hash mode and a
    composite `-pss` OID signs and verifies with RSASSA-PSS. Signatures made under these OIDs by the older versions
    (pure mode, PKCS#1 v1.5) no longer verify under them.
  - `check_consistency_sig_alg_id_and_key`: an RSA key matches `id-RSASSA-PSS` and `rsaEncryption` (was `BadSigAlgID`);
    a PQ key with a composite OID, a composite key with a classic OID and a key that is no signature key give
    `BadSigAlgID` (were `TypeError`, `ValueError` and `ValueError`).
  - `validate_sig_alg_id` accepts `rsaEncryption` with NULL (was `BadAlg`) and refuses RSASSA-PSS parameters with a MGF1
    hash that differs from the hash or a trailerField other than 1 (was accepted). Its default stays strict.
  - `sign_with_alg_id` and `verify_signature_with_alg_id` accept PKCS#1 v1.5 identifiers without parameters (were
    `BadSigAlgIDParams`) and raise `BadSigAlgID` if `hash_alg` contradicts the hash of the OID.
  - `sign_data` and `verify_signature` have no default hash: ECDSA, DSA and RSA raise `ValueError` without
    `hash_alg` (they signed with SHA-256, and verified with SHA-256 silently). Their options are keyword-only, an
    unknown keyword is a `TypeError` (it was ignored), the composite keyword `use_pss` is `use_rsa_pss`, and RSA
    keys are signed with PKCS#1 v1.5 (was `NotImplementedError`).
  - `prepare_sig_alg_id(key, hash_alg=None, use_rsa_pss=False)`: the default is `None`, which is still `sha256` for
    RSA, ECDSA and DSA (same bytes), and an SLH-DSA key without a hash now gets the pure OID.
- `SIG_ALG_OID_2_PARAMETERS_SPEC` is derived from the signature algorithm table and has the 81 entries of its rows.
- The private `compute._validate_sig_alg_id`, `compute._resolve_sig_alg_name`, `compute._check_eddsa_oid_matches_key` and
  `keyutils._check_trad_sig_alg_id` are gone; their checks are in `get_sig_alg_info` and `compute._check_key_matches`.

## Fixed

- ML-DSA verification (`MLDSAPublicKey.verify`) raises `InvalidSignature` for a signature of the wrong length. The
  pre-hash (HashML-DSA) path accepted a signature with trailing bytes and raised `IndexError` for a short or empty one.
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
- RSASSA-PSS with a salt length of 0 is signed and verified with a salt of length 0 (`salt_length or digest_size`
  replaced it by the digest size, RFC 4055 Section 3.1). `sign_data_rsa_pss`, `sign_data`, `verify_signature`,
  `verify_rsassa_pss_from_alg_id` and the identifier functions honour it, SHAKE variants too.
- An `id-RSASSA-PSS` identifier that omits `hashAlgorithm`, `maskGenAlgorithm` or `saltLength` is read with the DEFAULT
  values of RFC 4055 Section 3.1; before, `verify_signature_with_alg_id` raised a raw `PyAsn1Error`.
- `sign_data` and `verify_signature` support RSA PKCS#1 v1.5 and RSASSA-PSS with SHA-1, SHA-2, SHA-3 and SHAKE for
  RSA keys, and composite keys take `use_rsa_pss` and `ctx` (`TypeError` before).
- `get_sig_alg_info`, `validate_sig_alg_id` and `sign_with_alg_id` raise `BadAlg` for an `AlgorithmIdentifier` without
  an OID instead of a `PyAsn1Error`.

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
