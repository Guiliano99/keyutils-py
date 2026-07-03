<!-- SPDX-FileCopyrightText: Copyright 2026
SPDX-License-Identifier: Apache-2.0 -->

# Changelog

# Unreleased

- Add `keyutils_py.jwt`: JSON Web Key (JWK) serialization and deserialization for
  EC, OKP (Ed/X 25519/448), RSA, ML-DSA, ML-KEM, SLH-DSA, and composite signature
  keys, with RFC 7638 thumbprints. Exposes `key_to_jwk`, `key_from_jwk`, and
  `jwk_thumbprint` at the package top level.
- Add JWS/JWT signing to `keyutils_py.jwt`: `sign_jwt`/`verify_jwt` (and lower-level
  `sign_jws`/`verify_jws`) produce and verify compact JOSE tokens for RSA (RS/PS),
  EC (ES256/384/512/ES256K), EdDSA, ML-DSA, SLH-DSA, and composite signature keys.
  ECDSA uses raw R‖S; verification rejects `alg:"none"` and enforces key/allowlist
  algorithm matching. `sign_jwt`/`verify_jwt` are re-exported at the top level.

# 0.0.1

- Created