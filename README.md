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
spki = prepare_spki(key)  # default
spki = prepare_spki(key, hash_alg="sha512")  # ML-DSA pre-hash OID
spki = prepare_spki(rsa_key, use_rsa_pss=True)  # RSA-PSS-tagged
spki = prepare_spki(for_kga=True, key_name="rsa")  # empty-key SPKI
```

### 6. AlgorithmIdentifier-driven sign/verify

```python
from keyutils_py import (
    get_sig_alg_info,
    prepare_sig_alg_id,
    sign_with_alg_id,
    validate_sig_alg_id,
    verify_signature_with_alg_id,
)
from keyutils_py.keyutils import prepare_rsa_pss_alg_id

alg_id = prepare_rsa_pss_alg_id("sha256", salt_length=0)
validate_sig_alg_id(alg_id)  # raises BadSigAlgIDParams if malformed; strict=False is the verifier's rule
sig = sign_with_alg_id(rsa_key, alg_id, b"data")  # hash and salt length come from the parameters
verify_signature_with_alg_id(rsa_key.public_key(), alg_id, b"data", sig)
get_sig_alg_info(alg_id).salt_length  # 0: the row of the OID, read from the parameters

alg_id = prepare_sig_alg_id(ml_dsa_key, "sha512")  # the HashML-DSA OID; the OID decides the signing mode
```

The OID decides how a signature is made: a pre-hash OID signs in pre-hash mode, a composite `-pss` OID signs with
RSASSA-PSS, and a key with the OID of another family or parameter set raises `BadSigAlgID`. `sign_data` and
`verify_signature` choose the algorithm from the key instead and need `hash_alg=` for RSA, ECDSA and DSA keys (no
default hash). `verify_signature_with_alg_id` refuses SHA-1 signatures with `BadAlg` unless the caller passes
`allow_sha1=True`; signing is not restricted.

### 7. Key derivation, MACs, key wrap and content encryption by AlgorithmIdentifier

`make_alg_id(kind, family, **params)` builds the identifier of a key derivation function, MAC, AES key wrap or AES
content encryption with its parameters as the RFCs write them; the functions below read an identifier the way a
receiver does and run what it names. `list_algorithms("kdf" | "mac" | "wrap" | "content")` lists every row.

```python
from keyutils_py import (
    compute_mac,
    decrypt_content,
    encrypt_content,
    kdf_derive,
    make_alg_id,
    unwrap_cek,
    verify_mac,
    wrap_cek,
)

kdf = make_alg_id("kdf", "pbkdf2", salt=b"salty salt", iterations=100_000, key_length=32, prf_hash="sha256")
kek = kdf_derive(kdf, b"password", 32)  # PBKDF2-params are read from the identifier, keyLength must equal the length
wrap = make_alg_id("wrap", "aes", bits=256, mode="kw")  # "kwp": key wrap with padding (RFC 5649)
wrapped = wrap_cek(wrap, kek, b"0123456789abcdef")  # the KEK must have the size that the OID names
assert unwrap_cek(wrap, kek, wrapped) == b"0123456789abcdef"  # IntegrityError if it does not verify

enc = make_alg_id("content", "aes-gcm", bits=256, nonce=bytes(12))
sealed = encrypt_content(enc, kek, b"payload", aad=b"header")  # Encrypted(ciphertext, tag)
decrypt_content(enc, kek, sealed.ciphertext, tag=sealed.tag, aad=b"header")

mac = make_alg_id("mac", "hmac", hash="sha3_256")
value = compute_mac(mac, b"key", b"data")
verify_mac(mac, b"key", b"data", value)  # constant time, IntegrityError; SHA-1 only with allow_sha1=True
```

An OID in no table is `BadAlg`, parameters that are absent, present wrongly or inconsistent are `BadAlgParams`,
undecodable ones `BadAsn1Data`. Limits on received parameters (a PBMAC1 `keyLength` of 16 to 4096 octets, a KMAC output
of at least 128 bits, at most 25 000 000 blocks of PBKDF2 work) are constants of `keyutils_py.mechanisms`.

The functions of `keyutils_py.primitives` (`hkdf`, `kdf2`, `kdf3`, `pbkdf2`, `hmac_digest`, `kmac`, `gmac`,
`aes_kw_wrap`, `aes_cbc_encrypt`, ...) take the name of the hash and plain bytes, no identifier, and have no limits.
The module is importable but not public API: a test uses it to make what the functions above refuse on purpose (a KEK
that does not fit the OID, a one octet PBMAC1 key) and to check them against an independent computation. One pair is
the exception: `aes_cbc_encrypt_no_padding` and `aes_cbc_decrypt_no_padding` are exported from `keyutils_py`, for
key-wrap constructions that pad on their own and are built outside keyutils, such as id-alg-PWRI-KEK (RFC 3211
Section 2.3).

### 8. Estimate security strength

```python
from keyutils_py import generate_key, estimate_key_security_strength

estimate_key_security_strength(generate_key("xwing"))  # min(192, 128) = 128
estimate_key_security_strength(generate_key("ml-kem-1024"))  # 256
```

### 9. Negative-test helpers

`manipulate_bytes_based_on_key` produces a guaranteed-invalid signature
shaped like the original (for regression tests):

```python
from keyutils_py import generate_key, sign_data, manipulate_sig_based_on_key

key = generate_key("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=2)
sig = sign_data(b"msg", key)
broken = manipulate_sig_based_on_key(sig, key)  # corrupts LMOTS, leaves auth-path intact
```

## Public API at a glance

The everyday surface lives at the top level:

| Concern | Functions |
|---|---|
| Lifecycle | `generate_key`, `save_key`, `load_private_key_from_file`, `load_public_key_from_file` |
| Signing | `sign_data`, `verify_signature`, `sign_with_alg_id`, `verify_signature_with_alg_id`, `validate_sig_alg_id`, `prepare_sig_alg_id` |
| Signature algorithm table | `get_sig_alg_info`, `list_algorithms("sig")`, `SIG_ALG_OID_2_INFO`, `SigAlgInfo` |
| KDF, MAC, key wrap, content encryption | `make_alg_id`, `list_algorithms("kdf" \| "mac" \| "wrap" \| "content")`, `AlgInfo`, `kdf_derive`, `compute_mac`, `verify_mac`, `mac_key_length`, `wrap_cek`, `unwrap_cek`, `wrap_key_length`, `encrypt_content`, `decrypt_content`, `Encrypted` |
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
