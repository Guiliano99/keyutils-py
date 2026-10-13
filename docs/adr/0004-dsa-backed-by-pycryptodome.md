# DSA is backed by pycryptodome, not cryptography

`cryptography` has deprecated DSA and announced its removal ("DSA is deprecated
and support will be removed in a future release", pyca docs, still present in
49.0). Six modules dispatched on `dsa.DSAPrivateKey` / `dsa.DSAPublicKey`, so
the removal would have broken the package at import time, not merely disabled
DSA signing.

We keep DSA by wrapping pycryptodome (already a dependency for RSASSA-PSS-SHAKE)
in `keyutils_py/keys/trad_keys.py`. The wrapper classes carry the same names and
the same positional call shapes as the `cryptography` classes (`sign(data,
hash)`, `verify(signature, data, hash)`, `private_bytes` / `public_bytes` with
`cryptography`'s enums, `InvalidSignature` on failure), so the six dispatch
sites and the cmp-test-suite kept their code shape; only the import moved
behind the `keyutils_py.types` facade. Signatures are DER `Dss-Sig-Value`
(pycryptodome `encoding="der"`), which is byte-compatible with `cryptography`
and X.509. Hashes are named by string as everywhere else in the package; a
`cryptography` `HashAlgorithm` instance is tolerated so old call sites keep
working. Signing is limited to SHA-256 (the suite exercises `dsa-sha256`); verification still
accepts SHA-1, SHA-224, SHA-384 and SHA-512 so signatures from other implementations can be checked.

Alternatives rejected: dropping DSA (the suite still exercises `dsa-sha256`
negative paths and `id-dsa` SPKI/KGA tables), and hand-rolling DSA over pyasn1
and `pow()` (more code, no constant-time guarantees, and PEM/PKCS#8 parsing to
maintain). DSA is therefore the only traditional key the package loads and
generates itself rather than delegating to `cryptography`; RSA/EC/Ed keys stay
with `cryptography`. Known ceiling: pycryptodome generates 1024/2048/3072-bit
keys only (the FIPS 186-4 sizes), pairs 2048 with N = 224 where `cryptography`
used N = 256 (both valid; q travels in the domain parameters, so verification
is unaffected), and DSA is still rejected by the
`AlgorithmIdentifier`-driven `sign_with_alg_id` / `verify_signature_with_alg_id`
paths, exactly as before.
