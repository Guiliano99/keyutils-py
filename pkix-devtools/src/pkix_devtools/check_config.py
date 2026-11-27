# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Fail if a configuration file of the repository differs from the copy that all the repositories share.

    check-config [FILE ...]

Without arguments every shared file is checked. The shared copies are package data of pkix-devtools; change one
there, and every repository that runs this check follows.
"""

import argparse
import difflib
import sys
from importlib import resources
from pathlib import Path
from typing import List, Optional

# Path in the repository -> name of the shared copy.
CANONICAL = {
    "LICENSE": "LICENSE",
    ".github/dependabot.yml": "dependabot.yml",
}


def canonical_text(path: str) -> str:
    """Return the shared copy of a file of the repository."""
    return resources.files("pkix_devtools").joinpath("canonical", CANONICAL[path]).read_text(encoding="utf-8")


def differences(root: Path, path: str) -> List[str]:
    """Return the unified diff of a file of the repository against its shared copy; empty if they agree."""
    local = root / path
    if not local.is_file():
        return [f"{path}: missing\n"]
    actual = local.read_text(encoding="utf-8")
    expected = canonical_text(path)
    if actual == expected:
        return []
    return list(difflib.unified_diff(expected.splitlines(True), actual.splitlines(True), "shared/" + path, path))


def main(argv: Optional[List[str]] = None) -> int:
    """Run the tool."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*", help=f"files to check, out of: {', '.join(CANONICAL)}")
    parser.add_argument("--root", type=Path, default=Path("."), help="the repository (default: the current directory)")
    args = parser.parse_args(argv)
    unknown = [f for f in args.files if f not in CANONICAL]
    if unknown:
        parser.error(f"no shared copy of {', '.join(unknown)}")
    failed = False
    for path in args.files or CANONICAL:
        diff = differences(args.root, path)
        if diff:
            failed = True
            sys.stdout.writelines(line if line.endswith("\n") else line + "\n" for line in diff)
    print("config files differ from the shared copies" if failed else "config files agree with the shared copies")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
