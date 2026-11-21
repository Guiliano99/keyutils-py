# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0
"""Validate CycloneDX JSON SBOM files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator

SCHEMA_VERSIONS = {
    "1.0": SchemaVersion.V1_0,
    "1.1": SchemaVersion.V1_1,
    "1.2": SchemaVersion.V1_2,
    "1.3": SchemaVersion.V1_3,
    "1.4": SchemaVersion.V1_4,
    "1.5": SchemaVersion.V1_5,
    "1.6": SchemaVersion.V1_6,
    "1.7": SchemaVersion.V1_7,
}


def main() -> int:
    """Run the CycloneDX JSON schema validation command."""
    parser = argparse.ArgumentParser(description="Validate a CycloneDX JSON SBOM.")
    parser.add_argument("sbom", type=Path, help="Path to a CycloneDX JSON SBOM.")
    args = parser.parse_args()

    raw_sbom = args.sbom.read_text(encoding="utf-8")
    sbom = json.loads(raw_sbom)
    schema_version = SCHEMA_VERSIONS.get(str(sbom.get("specVersion", "")))
    if schema_version is None:
        print(f"Unsupported or missing CycloneDX specVersion in {args.sbom}", file=sys.stderr)
        return 1

    validator = make_schemabased_validator(OutputFormat.JSON, schema_version)
    try:
        validation_error = validator.validate_str(raw_sbom)
    except MissingOptionalDependencyException as exc:
        print(f"Validation dependencies are missing: {exc}", file=sys.stderr)
        return 1

    if validation_error:
        print(f"Invalid CycloneDX SBOM: {validation_error}", file=sys.stderr)
        return 1

    print(f"Valid CycloneDX {sbom['specVersion']} SBOM: {args.sbom}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
