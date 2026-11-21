# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Fail if a Python file imports a module that the rules of its directory forbid.

    check-import-boundaries [--pyproject pyproject.toml]

The rules are a table in `pyproject.toml`, one entry per directory (relative to the file), with the modules that the
files below it must not import; a module forbids its submodules too:

    [tool.pkix-devtools.import-boundaries]
    "mock_ca" = ["resources", "cryptography"]
    "resources" = ["cryptography.hazmat"]

A directory without Python files is an error, so that a renamed directory does not leave a rule that checks nothing.
"""

import argparse
import ast
import sys
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Set


def imported_modules(source: str) -> Set[str]:
    """Return the names of the modules a source text imports, anywhere in it (relative imports are left out)."""
    names: Set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def violations(root: Path, rules: Dict[str, List[str]]) -> List[str]:
    """Return one line per forbidden import, and per rule whose directory has no Python file."""
    found: List[str] = []
    for directory, forbidden in rules.items():
        files = sorted((root / directory).rglob("*.py"))
        if not files:
            found.append(f"{directory}: no Python files, the rule checks nothing")
        for path in files:
            for imported in sorted(imported_modules(path.read_text(encoding="utf-8"))):
                if any(imported == name or imported.startswith(name + ".") for name in forbidden):
                    found.append(f"{path.relative_to(root)} imports {imported}, which {directory}/ must not")
    return found


def main(argv: Optional[List[str]] = None) -> int:
    """Run the tool."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    args = parser.parse_args(argv)
    config = tomllib.loads(args.pyproject.read_text(encoding="utf-8"))
    rules = config.get("tool", {}).get("pkix-devtools", {}).get("import-boundaries")
    if not rules:
        print(f"{args.pyproject} has no [tool.pkix-devtools.import-boundaries] table")
        return 2
    found = violations(args.pyproject.parent, rules)
    for line in found:
        print(line)
    print(f"{len(found)} import rule violation(s)" if found else f"imports keep the rules of {len(rules)} directories")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
