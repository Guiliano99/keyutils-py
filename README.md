<!--
SPDX-FileCopyrightText: Copyright 2025

SPDX-License-Identifier: Apache-2.0
-->
# keyutils-py

A self-contained Python library for **post-quantum** and **hybrid** key
operations: key generation, signing, verification, encapsulation,
decapsulation, ECDH, key persistence (PKCS#8 / SPKI), and security-strength
estimation. Built around `pyasn1`, `cryptography`, `pyhsslms`, and
optionally `liboqs`.

## Supported algorithms

| Family                  | Algorithms                                                                     | Backed by                       |
|-------------------------|--------------------------------------------------------------------------------|---------------------------------|
| PQ signature            | ML-DSA-44/65/87 (± pre-hash), SLH-DSA-* (12 modes), Falcon-512/1024 (± padded) | bundled FIPS 204/205 / liboqs   |
| PQ KEM                  | ML-KEM-512/768/1024, McEliece-* (5 modes), FrodoKEM-* (6 modes), SNTRUP761     | bundled FIPS 203 / liboqs       |
| PQ-Stateful-hash        | HSS / LMS, XMSS, XMSSMT                                                        | `pyhsslms` / liboqs             |
| Hybrid                  | composite-sig, composite-kem, chempat, xwing                                   | local                           |
| Traditional KEM helpers | RSA-KEM (RFC 9690), DHKEM (RFC 9180), ECDH                                     | `cryptography`                  |
| RSA-PSS                 | SHA-1/2/3 + SHAKE128/256                                                       | `cryptography` + `pycryptodome` |

## Install

```bash
pip install -e .                # HSS / LMS works out of the box
pip install -e '.[pq]'          # adds liboqs for XMSS / XMSSMT / Falcon / McEliece / FrodoKEM / SNTRUP761
pip install -e '.[dev]'         # dev tooling
```

Without the `pq` extra, OQS-backed entry points raise
`MissingOQSDependencyError` at the dispatch boundary.

## Quick tour

### 1. Generate, sign, verify

```python
from keyutils_py import generate_key, sign_data, verify_signature

key = generate_key("ml-dsa-44")
sig = sign_data(b"hello", key)
verify_signature(key.public_key(), sig, b"hello")
```

### 2. Encapsulate, decapsulate

```python
from keyutils_py import generate_key, compute_encaps, compute_decaps

priv = generate_key("ml-kem-768")
shared, ct = compute_encaps(priv.public_key())
recovered = compute_decaps(priv, ct)
assert recovered == shared
```

For hybrid KEMs the same calls work; pass `other_key=` for ECDH-based
schemes:

```python
from cryptography.hazmat.primitives.asymmetric import x25519
priv = generate_key("xwing")
ephemeral = x25519.X25519PrivateKey.generate()
shared, ct = compute_encaps(priv.public_key(), other_key=ephemeral)
```

### 3. ECDH (with cofactor option) — accepts a cert

```python
from cryptography.hazmat.primitives.asymmetric import ec
from keyutils_py import compute_ecdh

a = ec.generate_private_key(ec.SECP256R1())
b = ec.generate_private_key(ec.SECP256R1())

# public-key form
shared = compute_ecdh(a, b.public_key())
# or pass an rfc9480.CMPCertificate that carries an ECDH SPKI
# shared = compute_ecdh(a, peer_cert)
# cofactor multiplication for non-1 cofactor curves
shared = compute_ecdh(a, b.public_key(), use_cofactor=True)
```

### 4. Save and load (PKCS#8 PEM)

```python
from keyutils_py import generate_key, save_key, load_private_key_from_file

key = generate_key("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=2)
save_key(key, "/tmp/k.pem", password="hunter2")
restored = load_private_key_from_file("/tmp/k.pem", password="hunter2")
```

### 5. Build a SubjectPublicKeyInfo

```python
from keyutils_py import generate_key, prepare_spki

key = generate_key("ml-dsa-44")
spki = prepare_spki(key)                                  # default
spki = prepare_spki(key, hash_alg="sha512")               # ML-DSA pre-hash OID
spki = prepare_spki(rsa_key, use_rsa_pss=True)            # RSA-PSS-tagged
spki = prepare_spki(for_kga=True, key_name="rsa")         # empty-key SPKI
```

### 6. AlgorithmIdentifier-driven sign/verify

```python
from keyutils_py import sign_with_alg_id, verify_signature_with_alg_id, validate_sig_alg_id
from keyutils_py.rsa_pss import prepare_rsa_pss_alg_id

alg_id = prepare_rsa_pss_alg_id("sha256")
validate_sig_alg_id(alg_id)                # raises BadSigAlgIDParams if malformed
sig = sign_with_alg_id(rsa_key, alg_id, b"data")
verify_signature_with_alg_id(rsa_key.public_key(), alg_id, b"data", sig)
```

### 7. Estimate security strength

```python
from keyutils_py import generate_key, estimate_key_security_strength

estimate_key_security_strength(generate_key("xwing"))      # min(192, 128) = 128
estimate_key_security_strength(generate_key("ml-kem-1024"))  # 256
```

### 8. Negative-test helpers

`manipulate_bytes_based_on_key` produces a guaranteed-invalid signature
shaped like the original (for regression tests):

```python
from keyutils_py import generate_key, sign_data, manipulate_sig_based_on_key

key = generate_key("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=2)
sig = sign_data(b"msg", key)
broken = manipulate_sig_based_on_key(sig, key)   # corrupts LMOTS, leaves auth-path intact
```

## Public API at a glance

The everyday surface lives at the top level:

| Concern | Functions |
|---|---|
| Lifecycle | `generate_key`, `save_key`, `load_private_key_from_file`, `load_public_key_from_file` |
| Signing | `sign_data`, `verify_signature`, `sign_with_alg_id`, `verify_signature_with_alg_id`, `validate_sig_alg_id` |
| KEMs / ECDH | `compute_encaps`, `compute_decaps`, `compute_ecdh` |
| SPKI | `prepare_spki` |
| Inspection | `get_key_name`, `estimate_key_security_strength` |
| Negative tests | `manipulate_bytes_based_on_key` |

Power-user helpers live in topic submodules:

| Submodule | Contents |
|---|---|
| `keyutils_py.algid_utils` | `prepare_alg_id`, `prepare_hash_alg_id`, `prepare_mgf1_alg_id`, `SIG_ALG_OID_2_PARAMETERS_SPEC`, `SigAlgParametersSpec`, `decode_alg_id_parameters`, `try_decode_pyasn1` |
| `keyutils_py.rsa_pss` | `sign_data_rsa_pss`, `verify_rsassa_pss_from_alg_id`, `verify_rsassa_pss_shake`, `prepare_rsa_pss_alg_id`, `FixedSHAKE128`, `FixedSHAKE256` |
| `keyutils_py.spki` | `subject_public_key_info_from_pubkey`, `prepare_subject_public_key_info` |
| `keyutils_py.info` | `get_supported_pq_algorithms`, `get_supported_pq_stfl_algorithms`, `get_key_name` |
| `keyutils_py.gen` | `generate_key`, `generate_key_based_on_alg_id` |
| `keyutils_py.keystore` | `load_pq_stfl_keys_from_dir` and the everyday save/load helpers |
| `keyutils_py.factories` | `HybridKeyFactory`, `PQKeyFactory`, `PQStatefulSigFactory`, `TradKeyFactory`, `AbstractKeyFactory` |

## Listing what's available

```bash
$ python -m keyutils_py
keyutils-py — PQ + hybrid key library

Stateful-hash families:
  hss: 80 algorithm(s)
  xmss: 21 algorithm(s)
  xmssmt: 16 algorithm(s)

PQ signature + KEM families:
  ml-dsa: 6 algorithm(s)
  slh-dsa: 24 algorithm(s)
  ...
```

## Development

```bash
# Install dev tooling
pip install -e '.[dev]'

# Run the suite
python -m unittest discover -s tests

# Lint and type-check
ruff check .
ruff format --check .
pyright
```

## License

Apache-2.0. See `LICENSES/`.
