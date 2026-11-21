<!--
SPDX-FileCopyrightText: Copyright 2026

SPDX-License-Identifier: Apache-2.0
-->
# pkix-devtools

The development tools that keyutils-py, pkixutils and the PKIX test suites (OCSP, CMS, CMP, ...) share, as one
dev-only distribution instead of a copy in every repository. Each tool is a console script that the Makefile and CI
of a repository call; none of them is imported by the code of a repository.

| Script | What it does | Replaces |
|---|---|---|
| `release-metadata` | `resolve-version`, `validate-tag`, `write-release-notes` for the release workflows: the version is `[project].version`, and the CHANGELOG has a `# x.y.z` heading for it | `scripts/release/release_metadata.py` |
| `validate-sbom FILE` | validates a CycloneDX JSON SBOM (needs the `sbom` extra) | `scripts/sbom/validate_sbom.py` |
| `extract-requirements --check\|--update` | the requirement items of the RFCs pinned in `data/requirements/manifest.toml` | `scripts/extract_requirements.py` |
| `traceability --id-prefix NAME [--coverage FILE] [--check]` | checks the tests against the items and the texts, and writes the trace and coverage tables | `scripts/traceability.py` |
| `add-licenses [DIR ...] [--no-markdown]` | adds the SPDX header where it is missing | `scripts/add_licenses.py` |
| `check-config [FILE ...]` | fails if `LICENSE` or `.github/dependabot.yml` differs from the shared copy in `pkix_devtools/canonical/` | (new) |
| `check-pins --kind suite\|library [--allow-commit-pins]` | fails if a shared package is pinned to a local path, a branch or nothing; a suite pins one version, a library a range | (new) |
| `check-import-boundaries` | fails if a file imports what `[tool.pkix-devtools.import-boundaries]` in `pyproject.toml` forbids for its directory | `unit_tests/test_import_boundaries.py` |

Install it into the dev environment of a repository, pinned like the other shared packages:

```toml
[dependency-groups]
dev = ["pkix-devtools[sbom] @ git+https://github.com/Guiliano99/keyutils-py.git@<tag>#subdirectory=pkix-devtools"]
```

It lives in the keyutils-py repository because that repository is public, so that private repositories can install
it and call the reusable workflows next to it without credentials. It does not depend on keyutils-py.

Run the tests from this directory: `python -m unittest discover -s tests` (with the package installed).
