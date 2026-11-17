# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

help:
	@echo  'Commands:'
	@echo  '  setup              - Set up the python environment (creating env. and install dependencies)'
	@echo  '  setup-dev          - Set up the python environment for development (creating env. and install dependencies, including dev dependencies)'
	@echo  '  unit_tests         - Run all compliance tests.'
	@echo  '  show-outdated      - Show outdated python dependencies.'
	@echo  '  semgrep            - Run semgrep locally, minus the accepted findings (not part of CI).'

unit_tests:
	# Run the tests itself.
	python3 -m unittest discover -s tests

setup:
	@echo "Setting up the python environment..."
	chmod +x scripts/setup.sh
	./scripts/setup.sh

setup-dev:
	@echo "Setting up the python environment for development (including dev dependencies)..."
	chmod +x scripts/setup.sh
	./scripts/setup.sh dev=1

show-outdated:
	@echo "Showing outdated dependencies..."
	uv tree --outdated --depth 1

# Local-only security scan. This is a usability/debugging library, so the rules below are
# accepted by design; paths are skipped via .semgrepignore.
#  - python-logger-credential-disclosure: debug logging of intermediate values is intentional.
#  - hardcoded-password-default-argument: the default test password keeps the helpers easy to use.
#  - crypto-mode-without-authentication: PKCS#8 PBES2 mandates AES-CBC.
#  - insecure-hash-algorithm-sha1: SHA-1 is a supported (legacy) signature / OID option.
SEMGREP_ACCEPTED_RULES = \
	python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure \
	python.lang.security.audit.hardcoded-password-default-argument.hardcoded-password-default-argument \
	python.cryptography.security.mode-without-authentication.crypto-mode-without-authentication \
	python.cryptography.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1

semgrep:
	semgrep scan --config p/python --config p/security-audit --metrics=off --error \
		$(addprefix --exclude-rule ,$(SEMGREP_ACCEPTED_RULES)) keyutils_py

start-app:
	@echo "Start the web interface"