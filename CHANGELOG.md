<!-- SPDX-FileCopyrightText: Copyright 2026
SPDX-License-Identifier: Apache-2.0 -->

# Changelog

# 0.1.0

## Added

- `keyutils_py.cms_algs.cms_digest_algs(key_name, signed_attrs)` returns the digests that a CMS SignerInfo of a key
  may name, the default first: the one digest of EdDSA (RFC 8419), the digests of ML-DSA (RFC 9882 Table 1 and
  Section 3.3) and of SLH-DSA (RFC 9814 Section 4) as the hashes with at least twice the bits of the security level.
  `PURE_PQ_SIG_NAME_2_OID` holds the identifiers of the pure modes by key name. A CMS library no longer keeps a table
  of its own for either.
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
  are absent, present wrongly or inconsistent are `BadAlgParams`, undecodable ones `BadAsn1Data`.
- `keyutils_py.mechanisms.compute_mac(mac, key, data)`, `verify_mac(mac, key, data, expected, *, allow_sha1=False)`
  and `mac_key_length(mac)` for the MAC an `AlgorithmIdentifier` names: HMAC with SHA-1 (both OIDs), SHA-2 and SHA-3
  (parameters absent, NULL also for SHA-1 and SHA-2), KMAC128/256 (absent parameters mean 256 or 512 bits and no
  customization, `KMACwithSHAKE-params` change both, RFC 8702 Section 3.4), AES-GMAC (the key has the size of the OID,
  the parameters are required, the MAC is the tag cut to the `length` of the parameters, DEFAULT 12 octets, RFC 9044
  Section 3.1) and PBMAC1 (`key` is the password; PBKDF2 with a `keyLength` and an HMAC; an absent `keyLength` is
  `BadAlgParams`, RFC 8018 Section 7.1). `verify_mac` compares with `hmac.compare_digest`, raises `IntegrityError` with
  one message whatever differs, and refuses SHA-1 with `BadAlg` (HMAC, or PBMAC1 over SHA-1 as pseudorandom function or
  HMAC) unless the caller passes `allow_sha1=True`; `compute_mac` does not refuse it. `mac_key_length` is 16, 24 or 32
  for AES-GMAC and `None` otherwise.
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
  `aad` or `tag` for AES-CBC, and a missing `tag` for AES-GCM, are a `TypeError`.
- Limits on the parameters of a received MAC or PBKDF2, in `compute_mac`, `verify_mac` and `kdf_derive`. They are
  fail-closed defaults, named as constants of `keyutils_py.mechanisms`, and each is refused with `BadAlgParams` before
  anything is computed: a PBMAC1 `keyLength` below `MIN_PBMAC1_KEY_LENGTH` (16 octets, RFC 8018 Section 7.1: it is the
  length of the MAC key) or above `MAX_PBMAC1_KEY_LENGTH` (4096); a KMAC `kMACOutputLength` below
  `MIN_KMAC_OUTPUT_BITS` (128 bits; the multiple-of-8 rule stays, there is no upper cap, RFC 8702 Section 3.4); and a
  PBKDF2 work `iterations * ceil(keyLength / digest size of the prf hash)` above `MAX_PBKDF2_WORK` (25 000 000), for
  PBMAC1 and for `kdf_derive` (the `length` argument plays the role of `keyLength`), besides the existing cap of
  `MAX_PBKDF2_ITERATIONS` on the iterations. `verify_mac` raises `IntegrityError` for a value of another length than
  the MAC. `keyutils_py.primitives` has no such limit, so a test can still make a short key or tag.
- `make_alg_id(kind, family, **params)` builds the `AlgorithmIdentifier` of a key derivation function (`hkdf`, `kdf2`,
  `kdf3`, `pbkdf2`), MAC (`hmac`, `kmac`, `gmac`, `pbmac1`), AES key wrap (`aes`, mode `kw` or `kwp`) or AES content
  encryption (`aes-cbc`, `aes-gcm`), one builder per family with the parameters as the RFCs write them (the DER of the
  identifiers of RFC 9690 Appendix D.2 is reproduced). An unknown keyword or a missing one is a `TypeError`, an unknown
  kind, family, hash, size or mode `BadAlg`; the kind `kari` has no builder yet and is `BadAlg`.
  A builder writes what it is asked for and checks no size, so a test can build what a receiver refuses.
  `list_algorithms` lists the kinds `kdf` (10 rows), `mac` (16), `wrap` (6) and `content` (6) as
  `AlgInfo(kind, family, params, oid)`, sorted by OID, `params` being keywords that `make_alg_id` takes.
- Exported from `keyutils_py`: `make_alg_id`, `kdf_derive`, `compute_mac`, `verify_mac`, `mac_key_length`, `wrap_cek`,
  `unwrap_cek`, `wrap_key_length`, `encrypt_content`, `decrypt_content`, `Encrypted`, `AlgInfo`, `AlgKind`,
  `BadAlgParams` and `IntegrityError`. They are in `keyutils_py.mechanisms` (the functions and types),
  `keyutils_py.algorithms` and `keyutils_py.exceptions`. `tests/golden/public_api.tsv` and `tests/test_public_api.py`
  pin the names and the signatures. `keyutils_py.primitives` is not exported.
- `make_alg_id("key_transport", "rsa-oaep", hash=..., mgf1_hash=None, label=b"")` writes RSAES-OAEP-params as RFC 4055
  Section 4.1 does: `hashFunc` and `maskGenFunc` as `AlgorithmIdentifier` values with NULL parameters, the parameter of
  `id-mgf1` the `AlgorithmIdentifier` of its hash (RFC 4055 Section 2.2), `pSourceFunc` as `id-pSpecified` with the
  label, and a field that equals its DEFAULT (SHA-1, the empty label) left out, so SHA-1 alone is an empty SEQUENCE. The
  bytes equal the identifiers that the ASN.1 module of RFC 4055 builds. `("key_transport", "rsa-pkcs1v15")` writes
  `rsaEncryption` with NULL. SHA-1 and SHA-2 only; another hash is `BadAlg`.
- `decrypt_data_with_public_key_alg_id(private_key, alg_id, ciphertext, *, allow_sha1=False)` and
  `encrypt_data_with_public_key_alg_id` read the identifier from the key transport row (`rsaEncryption`, `id-RSAES-OAEP`).
  OAEP parameters are read in the RFC 4055 form: the hash identifiers with NULL or no parameters, absent fields are the
  DEFAULTs of Section 4.1 (SHA-1, empty label), `pSourceFunc` must be `id-pSpecified` (another OID is `BadAlg`), the
  label is at most `keyutils_py.compute.MAX_OAEP_LABEL_LENGTH` (4096) octets, and the parameters themselves must be
  present (the empty SEQUENCE for all defaults). Verified against `openssl cms -encrypt` files (OAEP with SHA-1, SHA-256,
  SHA-384 with an MGF1 over SHA-256, and PKCS#1 v1.5) and against `cryptography`'s own OAEP with labels.
- Exported from `keyutils_py`: `compute_hash` and `ML_DSA_PRE_HASH_OID_2_NAME` (`keyutils_py.oids`),
  `cms_digest_algs` and `PURE_PQ_SIG_NAME_2_OID` (`keyutils_py.cms_algs`) and `InvalidKeyData`
  (`keyutils_py.exceptions`). pkixutils imported them by module path; it can now use the public API.
- `aes_cbc_encrypt_no_padding(key, iv, data)` and `aes_cbc_decrypt_no_padding(key, iv, data)`, AES-CBC without
  padding on `cryptography`, for key-wrap constructions that pad on their own, such as id-alg-PWRI-KEK (RFC 3211
  Section 2.3). They are in `keyutils_py.primitives` and are its only exported functions. A key that is not 16, 24 or
  32 octets, an IV that is not 16 octets and data that is empty or no multiple of 16 octets are a `ValueError`. CMS
  content is still encrypted with `encrypt_content`, which pads. Tested with NIST SP 800-38A F.2.1 to F.2.6.
- `keyutils_py.oids.id_alg_PWRI_KEK`, exported from `keyutils_py`: `1.2.840.113549.1.9.16.3.9`, the key wrap of a
  password recipient (RFC 3211 Section 2.3), built on the `id-alg` arc of `rfc9688`. No pyasn1-alt-modules module has
  it. It is a constant only; no mechanism computes the key wrap.
- `check_consistency_sig_alg_id_and_spki(alg_id, spki)`, exported from `keyutils_py`, checks a signature
  AlgorithmIdentifier against a SubjectPublicKeyInfo. It runs `check_consistency_sig_alg_id_and_key` on the loaded
  key and then applies RFC 4055 to an `id-RSASSA-PSS` SPKI, whose RSASSA-PSS-params the loaded key no longer has:
  such a key is used for RSASSA-PSS only (Section 1.2, `BadSigAlgID` otherwise), and when the SPKI has parameters,
  the signature's hashAlgorithm and MGF1 hash must equal the key's and its saltLength must be greater or equal
  (Section 3.3 case 3, `BadSigAlgIDParams` otherwise). Absent fields are compared as their DEFAULT values. An
  `rsaEncryption` key or an `id-RSASSA-PSS` key without parameters needs no parameter validation (cases 1 and 2).
  The parameters of an `id-RSASSA-PSS` key are read before the key is loaded (`BadSigAlgIDParams` if they cannot be
  read), and a key that `cryptography` refuses although its parameters are readable is `BadSigAlgIDParams` chained to
  the loader's `ValueError`, not a bare `ValueError`: the usual cause is a DEFAULT value encoded explicitly, which
  is not DER (RFC 4055 Section 3.1 has a generator omit it, ITU-T X.690 Section 11.5) and which the DER-only key loader
  refuses. Explicit DEFAULTs are accepted in the parameters of the signature only. Known disagreement with RFC 4055:
  the reader refuses an MGF1 hash that differs from hashAlgorithm, on the key side and on the signature side, where
  Section 3.1 only says that the same hash is "strongly RECOMMENDED". That is the policy of keyutils, and it is why
  comparing the hashAlgorithm also compares the MGF1 hash.
- `is_public_key_oid(oid)`, exported from `keyutils_py` (`keyutils_py.keyutils`), tells whether an OID (an
  `ObjectIdentifier` or its dotted string) is the algorithm of a SubjectPublicKeyInfo that `load_public_key_from_spki`
  loads. It reads the tables the loader dispatches on, so a consumer needs no copy of them: `True` for `rsaEncryption`,
  `id-RSASSA-PSS`, `id-ecPublicKey`, Ed25519, Ed448, X25519, X448, DSA, DH (`dhpublicnumber` and `dhKeyAgreement`),
  RSA-KEM, ML-DSA, ML-KEM, SLH-DSA, Falcon, FrodoKEM, McEliece, sntrup761, HSS, XMSS and XMSS^MT, the composite
  signatures and KEMs, Chempat and X-Wing. `False` for signature algorithms (`sha256WithRSAEncryption`,
  `ecdsa-with-SHA256`, the SHAKE RSASSA-PSS identifiers), hashes, `id-ecDH`, `id-ecMQV` and unknown OIDs. The HashML-DSA
  and HashSLH-DSA identifiers answer `True`, because the loader reads them as the pure key. It needs no `liboqs`.

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
- Breaking for consumers of `encrypt_data_with_public_key_alg_id` and `decrypt_data_with_public_key_alg_id` that pin
  an older commit (nothing changes until they bump):
  - OAEP parameters in the old bytes, a bare hash OID as the parameter of `id-mgf1` (what `get_rsa_oaep_padding` and
    the callers of this package wrote), are `BadAlgParams`; the RFC 4055 form that they refused (an `AlgorithmIdentifier`
    as the parameter of `id-mgf1`, hashes with or without NULL, a label) is read. Absent OAEP parameters are
    `BadAlgParams` (they were a `PyAsn1Error`), a `pSourceFunc` other than `id-pSpecified` is `BadAlg` (a non-empty label
    was `NotImplementedError`), `rsaEncryption` with other parameters than absent or NULL is `BadAlgParams` (was
    `ValueError`).
  - Decryption of OAEP over SHA-1, also by the DEFAULT of an absent `hashFunc` or `maskGenFunc`, is `BadAlg` unless the
    caller passes `allow_sha1=True`.
  - A failed decryption is `IntegrityError` with one message (was `ValueError`); a key that is no RSA key is
    `InvalidKeyCombination` (was an `AttributeError`).
  - `get_rsa_oaep_padding` is removed from `keyutils_py.compute` and from `keyutils_py.__all__`: it read the old form.
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

- The pure-Python FrodoKEM implementation now works with `bitstring` 5: the remaining
  `BitArray(length=...)` calls in `__bytes_to_bit_array` and `decode`, and the removed
  `ConstBitStream` in `kem_decaps`, are replaced.
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
- `load_public_key_from_spki` (and `CombinedKeyFactory.load_public_key_from_spki`) raise `BadAlg` for a key that
  `cryptography` cannot load, for example an unknown algorithm OID or an EC key on a curve it does not support such as
  secp112r1. The `UnsupportedAlgorithm` of `cryptography` escaped before; it is the cause of the `BadAlg` now, so a
  caller that catches `KeyUtilsError` needs no `cryptography` import for this case.

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
