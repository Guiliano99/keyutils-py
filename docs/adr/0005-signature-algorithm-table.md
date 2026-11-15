# One table row per signature OID decides how a signature is made

Which hash, padding, key and CMS digest a signature OID stands for was spread over six OID tables and
`name.split("-")` string surgery in two isinstance chains (`sign_with_alg_id`, `verify_signature_with_alg_id`), the
consistency check and the identifier builder. The chains disagreed with each other: PQ, stateful-hash and composite
keys accepted any OID, a pre-hash OID signed in pure mode, a composite `-pss` OID signed PKCS#1 v1.5, and RSASSA-PSS
with salt length 0 signed with the digest size.

`keyutils_py.oids.SIG_ALG_OID_2_INFO` now has one frozen `SigAlgInfo` row per signature OID (81), derived at import
from the family tables. `sign_with_alg_id`, `verify_signature_with_alg_id`, `check_consistency_sig_alg_id_and_key`,
`validate_sig_alg_id` and `prepare_sig_alg_id` read the row, ask the one function `_check_key_matches` whether the key
belongs to it, and call `sign_data` / `verify_signature`, the only code that looks at the class of a key. A new
algorithm of a known family is an OID in the family table and one row in `tests/golden/sig_alg_table.tsv`, which is
written from the RFCs and not generated from the code, so a wrong derivation cannot confirm itself.

Decisions, with their reason:

- The OID is the authority. A pre-hash OID (ML-DSA, SLH-DSA) runs the pre-hash mode with the hash it names: RFC 9881
  Section 8.3 says ML-DSA and HashML-DSA are incompatible algorithms. A composite `-pss` OID signs with RSASSA-PSS: the
  OID is the domain separator of the composite draft. The library never refuses such an OID; whether a certificate may
  carry it is a conformance verdict for the caller, who reads `SigAlgInfo.pre_hash`.
- `rsaEncryption` is a signature identifier of RSA PKCS#1 v1.5, parameters NULL, with the digest from the caller
  (`hash_alg=`) (RFC 3370 Section 3.2). It is in the table but not in `TRAD_SIG_OID_2_NAME`, so the RFC 9481 profile
  sets of the callers do not change.
- Two parameter contracts, one table. Generating and `validate_sig_alg_id` are strict: PKCS#1 v1.5 carries NULL.
  Signing and verifying accept absent and NULL, as RFC 4055 Section 5 and RFC 5754 Section 3.2 require of receivers.
  Parameters that must be absent (ECDSA, EdDSA, PQ, composite) are refused in both.
- An RSA key matches id-RSASSA-PSS rows (RFC 4055 Section 1.2: an `rsaEncryption` key may be used with RSASSA-PSS).
  A key restricted to PSS by its SubjectPublicKeyInfo is not modelled; the key classes carry no such parameters.
- The RSASSA-PSS salt length is honoured as given, 0 included; omitted fields of the parameters have the DEFAULT values
  of RFC 4055 Section 3.1 (SHA-1, MGF1 with SHA-1, salt length 20). A MGF1 hash that differs from the hash stays
  `BadSigAlgIDParams`; the builder can still write it, so it remains a negative-test input.
- SHA-1 is refused on verification unless the caller passes `allow_sha1=True`. RFC 9481 lists RSA-SHA1 as
  deprecated, and verification is a trust decision, so the library keeps the fail-closed default it had for
  `sha1WithRSAEncryption` and applies it to every identifier that names SHA-1 (PKCS#1 v1.5, `rsaEncryption` with
  `hash_alg="sha1"`, RSASSA-PSS with SHA-1 or MGF1 with SHA-1). A conformance suite still has to judge what a
  peer sends, so each caller that accepts SHA-1 opts in in its own code. Signing is not restricted: a suite must
  produce SHA-1 material.
- DSA stays by-name only (`sign_data`, `verify_signature`); the identifier functions raise `BadAlg` for a DSA key, as
  before (ADR 0004).
- `sign_data` and `verify_signature` have no default hash and keyword-only options, so a misspelled option raises
  `TypeError` instead of being dropped.

Negative output stays producible: the identifier functions never sign or verify a mismatch, so a deviation is made from
a valid pair by editing the structure afterwards, or by the by-name pair, which does not look at the identifier
(`tests/test_negative_output.py`). There is no `bad_*` flag and no unchecked entry point.

Alternatives rejected: a spec object per algorithm that is passed around (a second public type for what the row
already says), and keeping the isinstance chains and fixing each defect where it stood (the defects were the
disagreement between the copies).
