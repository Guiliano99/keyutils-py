# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Fail if a shared package is pinned in a way that works on one machine only, follows a branch, or is not pinned.

    check-pins --kind suite|library [--pyproject pyproject.toml] [--allow-commit-pins] [--packages NAME,...]

The rules, for the shared packages only (`--packages`, default keyutils-py, pkixutils, pkix-devtools and
x509verbose-testing), in the dependencies, the optional dependencies, the dependency groups and `[tool.uv.sources]`:

- no `git+file:`, `file:` or path source: it resolves on one machine only;
- a git URL or source names a tag (`v1.2.3` or `1.2.3`): not nothing and not a branch. A commit passes with
  `--allow-commit-pins`, for as long as the packages have no tags;
- a version specifier: a suite pins one version (`==`), a library asks for a range with a lower and an upper bound.
"""

import argparse
import re
import tomllib
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

SHARED = ("keyutils-py", "pkixutils", "pkix-devtools", "x509verbose-testing")
_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
_TAG = re.compile(r"^v?\d+(\.\d+)*([.-]?(a|b|rc|post|dev)\d*)?$")


def normalize(name: str) -> str:
    """Return the normalized name of a distribution (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _ref_problem(ref: Optional[str], allow_commits: bool) -> Optional[str]:
    if not ref:
        return "names no revision; pin a tag"
    if _COMMIT.match(ref):
        return None if allow_commits else f"is pinned to the commit {ref[:12]}; pin a tag"
    if _TAG.match(ref):
        return None
    return f"names {ref!r}, which is not a tag (a branch?); pin a tag"


def url_problem(url: str, allow_commits: bool) -> Optional[str]:
    """Return what is wrong with a direct reference (`name @ url`), or None."""
    url = url.split(";")[0].strip()
    if url.startswith(("git+file:", "file:")):
        return "points at a local repository; it resolves on this machine only"
    if not url.startswith("git+"):
        return None
    path = url.split("://", 1)[-1].partition("/")[2].split("#")[0]
    return _ref_problem(path.rsplit("@", 1)[1] if "@" in path else None, allow_commits)


def specifier_problem(specifier: str, kind: str) -> Optional[str]:
    """Return what is wrong with a version specifier for a suite or a library, or None."""
    specifier = specifier.split(";")[0].replace(" ", "")
    if not specifier:
        return "has no version; pin one" if kind == "suite" else "has no version range"
    if kind == "suite":
        return None if specifier.startswith("==") and "," not in specifier else "a suite pins one version (==)"
    lower = re.search(r"(>=|>|~=|==)", specifier)
    upper = re.search(r"(<=|<(?!=)|~=|==)", specifier)
    return None if lower and upper else "a library asks for a range with a lower and an upper bound"


def _requirements(config: dict) -> Iterator[Tuple[str, str]]:
    project = config.get("project", {})
    for requirement in project.get("dependencies", []):
        yield "[project] dependencies", requirement
    for extra, requirements in project.get("optional-dependencies", {}).items():
        for requirement in requirements:
            yield f"[project.optional-dependencies] {extra}", requirement
    for group, requirements in config.get("dependency-groups", {}).items():
        for requirement in requirements:
            if isinstance(requirement, str):
                yield f"[dependency-groups] {group}", requirement


def problems(config: dict, kind: str, allow_commits: bool, packages=SHARED) -> List[str]:
    """Return one line per pin of a shared package that breaks a rule."""
    shared = {normalize(name) for name in packages}
    sources = {normalize(name) for name in config.get("tool", {}).get("uv", {}).get("sources", {})}
    found: List[str] = []
    for where, requirement in _requirements(config):
        match = _REQUIREMENT.match(requirement)
        if not match or normalize(match.group(1)) not in shared:
            continue
        rest = match.group(2).strip()
        if not rest.split(";")[0].strip() and normalize(match.group(1)) in sources:
            continue  # the version comes from the uv source, which is checked below
        problem = url_problem(rest[1:], allow_commits) if rest.startswith("@") else specifier_problem(rest, kind)
        if problem:
            found.append(f"{where}: {requirement.strip()}: {problem}")
    for name, sources in config.get("tool", {}).get("uv", {}).get("sources", {}).items():
        if normalize(name) not in shared:
            continue
        for source in sources if isinstance(sources, list) else [sources]:
            if "path" in source:
                problem: Optional[str] = "is a path source; it resolves on this machine only"
            elif "git" in source:
                problem = _ref_problem(source.get("tag") or source.get("rev"), allow_commits)
                if "branch" in source:
                    problem = f"follows the branch {source['branch']!r}; pin a tag"
            else:
                problem = None
            if problem:
                found.append(f"[tool.uv.sources] {name}: {problem}")
    return found


def main(argv: Optional[List[str]] = None) -> int:
    """Run the tool."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kind", choices=["suite", "library"], required=True)
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--allow-commit-pins", action="store_true", help="accept a git commit until there are tags")
    parser.add_argument("--packages", default=",".join(SHARED), help="the shared packages, separated by commas")
    args = parser.parse_args(argv)
    config = tomllib.loads(args.pyproject.read_text(encoding="utf-8"))
    found = problems(config, args.kind, args.allow_commit_pins, tuple(args.packages.split(",")))
    for line in found:
        print(f"{args.pyproject}: {line}")
    print(f"{len(found)} pin(s) break the rules" if found else "the shared packages are pinned by the rules")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
