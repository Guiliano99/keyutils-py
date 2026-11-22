# Mechanisms read algorithm table rows; the lower layer reads nothing

What an `AlgorithmIdentifier` of a key derivation function, MAC, key wrap or content encryption stands for was worked out
again by every caller: the hash of HKDF from a name split at `"-"` (HKDF with SHA-3 failed because of it), the size of an
AES key from `"128" in name` at five places, the PBKDF2 parameters decoded as an `AlgorithmIdentifier` instead of
`PBKDF2-params`, the PRF hash resolved a second time in PBMAC1. The cryptographic call itself is one line in each case;
the resolution from an identifier to a function and its parameters is what differed and what broke.

Three layers, imports going down only:

- `keyutils_py/_algs.py` (private): one literal tuple of frozen rows per fact (`KdfRow`, `MacRow`, `WrapRow`,
  `ContentRow`, `KariRow`, `KtRow`) and the indexes generated from them by comprehension. Every field is structured; no
  code splits a name. A new member of a known family is one row, one row in `tests/golden/alg_tables.tsv` (written from the
  RFCs by `tests/golden/generate_alg_tables.py`, not from the code) and a CHANGELOG line.
- `keyutils_py/primitives.py`: keyless functions by the name of the hash, on plain bytes. No identifier, no OID, no table;
  it imports `cryptography`, `pycryptodome` and `keyutils_py.exceptions` only (an `ast` test). Importable, not in
  `__all__`, not in the API snapshot (one pair is the exception, see the amendment of 2026-11-22).
- `keyutils_py/mechanisms.py`: `make_alg_id`, `kdf_derive`, `compute_mac`, `verify_mac`, `mac_key_length`, `wrap_cek`,
  `unwrap_cek`, `wrap_key_length`, `encrypt_content`, `decrypt_content`. They look the OID up in the rows, read and check
  the parameters, and call the function of the lower layer.

Decisions, with their reason:

- The public surface is the mechanisms, not the primitives. Every call of a KDF or key wrap in the callers sits inside one
  of a few mechanisms (key agreement, KEM, password, key transport, MAC), so a consumer needs the resolution, and a public
  primitive would leave it to redo that. The lower layer stays importable because negative tests need unchecked access: a
  key wrap whose KEK does not fit the OID that is written next to it, a one octet PBMAC1 key, a KMAC output below the
  limit. A name that a second suite needs is promoted by a row or a mechanism, not by exporting the function
  (one exception, see the amendment of 2026-11-22).
- Mechanisms are strict receivers. An OID in no table is `BadAlg`; parameters that are absent, present where they must be
  absent, or inconsistent with the OID or the other arguments are `BadAlgParams` (trailing data included); parameters that
  do not decode are `BadAsn1Data`; a value that does not verify is `IntegrityError` with one message, so that a wrong
  length, wrong padding and wrong tag are not told apart. `BadAlgParams` and `IntegrityError` derive from
  `KeyUtilsError` and carry no protocol detail.
- The identifier that is passed in and the identifier that a caller writes are two statements. A test makes a mismatch by
  passing one and writing the other; there is no `bad_*` flag and no `**kwargs` that is swallowed (`make_alg_id` raises
  `TypeError` for an unknown keyword). Builders write what they are asked for and do not check sizes.
- Parameters are decoded once, against the specification of the algorithm, from DER or from an already decoded object of
  that specification. `PBKDF2-params` is therefore read correctly after a DER round trip; `keyLength` is optional and, if
  present, must equal the length that is derived; an absent `prf` is HMAC-SHA-1 (RFC 8018 Appendix A.2); a salt from
  `otherSource` is `BadAlg`.
- HMAC with SHA-1 has two OIDs, `hMAC-SHA1` (RFC 3370, the OID of a MAC) and `id-hmacWithSHA1` (RFC 8018, the PBKDF2
  function). Both are rows; the MAC builder writes the first and the PBKDF2 builder the second (`MacRow.prf`).
- AES-GMAC follows RFC 9044: the MAC is the GCM tag cut to the `length` of the parameters, DEFAULT 12 octets, and the
  parameters are required. A 16 octet tag next to parameters that name only the nonce does not verify.
- KMAC reads the optional `KMACwithSHAKE-params` (RFC 8702 Section 3.4); HKDF over SHAKE does not exist (HKDF is HMAC
  based), and KDF2 and KDF3 take SHA-1, SHA-2 or SHA-3 only (RFC 9688 Section 5.3).
- Fail closed where a received identifier decides the strength of a check. SHA-1 is refused by `verify_mac` unless the
  caller passes `allow_sha1=True` (HMAC, and PBMAC1 over SHA-1), as in `verify_signature_with_alg_id`; producing it with
  `compute_mac` and deriving with `kdf_derive` is not restricted. A PBMAC1 `keyLength` outside 16 to 4096 octets, a KMAC
  output below 128 bits and a PBKDF2 work above 25 000 000 blocks are `BadAlgParams` before anything is computed; the
  limits are named constants of `keyutils_py.mechanisms` and `keyutils_py.primitives` has none.
- The key agreement and key transport rows are data in `_algs`; `make_alg_id` raises `BadAlg` for those two kinds until
  their builders exist.

Alternatives rejected: a public by-name primitive layer next to the mechanisms (each consumer would resolve identifiers
again), a spec object per algorithm that is passed around (a second public type for what the row already says), and a
`strict` flag on the mechanisms (a switch keeps the misreading it was meant to remove alive).

## Amendment 2026-11-22: the unpadded AES-CBC pair is public

`aes_cbc_encrypt_no_padding` and `aes_cbc_decrypt_no_padding` of `keyutils_py.primitives` are exported from `keyutils_py`
(in `__all__` and in the API snapshot). This is an exception to the second decision above, which keeps the primitives
private and promotes a needed name by a row or a mechanism. The decision itself stands for every other function of the
lower layer.

Reason: a key-wrap construction that pads on its own, such as id-alg-PWRI-KEK (RFC 3211 Section 2.3), formats the CEK
with random padding (not PKCS #5) and runs CBC twice, the second time over its own output with the last ciphertext block
as IV. `encrypt_content` pads, so it cannot be used, and no mechanism is the right place for it: the construction is built
outside keyutils, and the identifier is a constant (`id_alg_PWRI_KEK`) only. Promoting it by a mechanism would add a
mechanism that nothing in keyutils calls; the pair has no table row to read and no parameter to check, so a consumer
loses nothing by taking the bare function. The pair still takes no identifier and no OID, and still raises `ValueError`
for a key that is not 16, 24 or 32 octets, an IV that is not 16 octets, and data that is empty or no multiple of 16
octets.
