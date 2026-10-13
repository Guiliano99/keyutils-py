<!--
SPDX-FileCopyrightText: Copyright 2026

SPDX-License-Identifier: Apache-2.0
-->
# AGENTS.md

Guidance for AI coding agents (and humans) working on `keyutils-py`.

## Purpose

`keyutils-py` is the **key layer for test tooling**, mainly the
[cmp-test-suite](https://github.com/siemens/cmp-test-suite). It generates,
loads, saves, signs, verifies, encapsulates and decapsulates traditional,
post-quantum and hybrid keys so that a test suite can check whether **real-world
implementations** (CMP servers, CAs, PKIX libraries) behave correctly.

It is not a production crypto library. The consequences matter when changing it:

- **Negative testing is a first-class use case.** The suite must be able to
  produce *wrong* material on purpose: signatures with flipped bytes, keys that
  do not match, malformed or mutated `OneAsymmetricKey` structures, reused or
  out-of-range stateful-hash (HSS/XMSS) state, and so on. See
  `keyutils_py/negative_testing.py`. Do not "harden" an API in a way that makes
  such invalid output impossible to produce.
- **Ease of use and debuggability beat defensive design.** Defaults such as the
  test password `"11111"`, debug logging of intermediate values, and legacy
  options (SHA-1, 1024-bit DSA) are intentional. Local semgrep rules for these
  are disabled on purpose (`make semgrep`, `.semgrepignore`); do not re-add
  them as "fixes".
- **Correctness against the specs still matters.** A test tool that produces
  wrong *valid* material would make the suite blame the wrong side. Positive
  paths must match the RFCs and drafts (FIPS 203/204/205, RFC 9180, RFC 9690,
  composite / Chempat / X-Wing drafts, see `REFERENCES.md`).
- **Untrusted input is still bounded.** Keys loaded from files can come from the
  implementation under test. Parsers must fail with a clean `ValueError` and not
  hang or crash, e.g. the PBKDF2 limits in `keys/key_pyasn1_utils.py`.

## Layout

| Path | Role |
|---|---|
| `keyutils_py/keyutils.py` | Public entry points: generate, load, save, naming |
| `keyutils_py/compute.py` | Sign, verify, encaps, decaps, ECDH |
| `keyutils_py/negative_testing.py` | Helpers that create deliberately invalid keys and signatures |
| `keyutils_py/types.py` | Facade for key type aliases; import key types from here |
| `keyutils_py/keys/` | Key classes: PQ, stateful hash, hybrid, `trad_keys.py` (DSA) |
| `keyutils_py/factories/` | Per-family key factories and `dispatch.py` (routes names/OIDs to the owner) |
| `keyutils_py/fips/` | Bundled pure-Python FIPS 203/204/205 and FrodoKEM |
| `keyutils_py/data/` | PEM key fixtures |
| `tests/` | Unit tests |
| `CONTEXT.md` | Domain glossary (hybrid key, PQ half, traditional half, ...) |
| `docs/adr/` | Architecture decisions |

## Working here

- Use the project environment: `uv sync --extra dev --extra pq`, then
  `.venv/bin/python`. System Python lacks the dependencies.
- Tests: `.venv/bin/python -m unittest discover -s tests`. Some modules and
  tests are known to be broken by unfinished work in progress; check which
  failures are yours (run the modules you touched, and compare with HEAD).
- Gates: `ruff check` / `ruff format`, `pylint --fail-under=9.4 keyutils_py`,
  `pyright`, `codespell`. `ruff.toml` excludes `tests/`; use `--no-force-exclude`
  to check test files.
- `make show-outdated` lists outdated dependencies; `make semgrep` is a local
  scan and is not part of CI.
- Verify before claiming done: add or run a test that would fail without your
  change.

## Conventions

- Reference key types through `keyutils_py/types.py`, not directly from
  `cryptography` or other libraries.
- Fix lint findings properly; no suppression hacks to dodge a rule.
- Keep changes small and scoped. Commit only the files that belong to the task
  (pathspec commits); the working tree often holds unrelated WIP such as `jwk/`.
- Licensing: every file needs copyright and license information (an inline
  header or a `REUSE.toml` annotation); `reuse lint` runs in CI. Do not write
  the literal SPDX tag names followed by a colon inside prose, since REUSE
  parses them as real tags. The copyright line naming Siemens AG (and the
  `Code owner` / cmp-test-suite note) is only for files taken over from the
  [cmp-test-suite](https://github.com/siemens/cmp-test-suite). It **MUST NOT**
  be added to new files: they are new code created in this project, so use a
  plain `Copyright <year>` copyright line without a company name, and
  Apache-2.0 as the license.
- Record non-obvious decisions as an ADR in `docs/adr/` and new domain terms in
  `CONTEXT.md`.
