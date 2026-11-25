<!-- SPDX-FileCopyrightText: Copyright 2026
SPDX-License-Identifier: Apache-2.0 -->

# Changelog

# 0.1.0

- `release-metadata`, `validate-sbom`, `extract-requirements` and `traceability`, moved unchanged from the copies in
  DefaultPy, pkixutils-py, keyutils-py and the OCSP and CMS suites, with their unit tests.
- `add-licenses`, the four copies in one, with the directories as arguments.
- `check-config`, `check-pins` and `check-import-boundaries`, new. `check-pins` refuses a local repository both as a
  direct reference and as a `[tool.uv.sources]` git source, also with `--allow-commit-pins`.
- `python-quality.yml` and `mutation-check.yml` take a second deploy key, `PKIXCA_DEPLOY_KEY`, for the private
  pkixca-py. Each repository is read through an ssh host of its own, as GitHub takes the repository from the key.
  The keys are removed after the install, and `python-quality.yml` refuses a key in a public repository, where a fork
  could read the private packages from the cached venv.
