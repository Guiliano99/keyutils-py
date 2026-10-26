# Raw-hybrid EC scalars stay padded to key_size-in-bits bytes

When a raw hybrid (Chempat) serializes a bare EC traditional half, the private
scalar is zero-padded to `key.key_size` bytes — but `cryptography`'s
`key_size` is in **bits**, so a P-256 scalar occupies 256 bytes instead of 32.
This wrong-width encoding shipped, keys serialized with it exist, and loaders
tolerate any padding — so byte-identical round-trips (which our tests pin)
matter more than a "correct" width. The consolidation of the traditional-half
codec into `keyutils_py/keys/trad_half.py` (2026-07) deliberately preserved
it; do not "fix" the width without a versioned format migration.
