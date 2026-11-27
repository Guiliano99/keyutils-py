# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests of add-licenses, check-config, check-import-boundaries and check-pins."""

import contextlib
import io
import os
import tempfile
import tomllib
import unittest
from pathlib import Path

from pkix_devtools import add_licenses, check_config, check_import_boundaries, check_pins


def _quiet(function, *args):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        code = function(*args)
    return code, out.getvalue()


class TestAddLicenses(unittest.TestCase):
    def test_only_files_without_a_header_get_one(self):
        """
        GIVEN a directory with a Python file without a header, one with a header and an __init__.py.
        WHEN add-licenses runs on it.
        THEN the first and the __init__.py get the header once, the second is left as it is.
        """
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("pkg").mkdir()
            Path("pkg/plain.py").write_text("x = 1\n", encoding="utf-8")
            Path("pkg/__init__.py").write_text("", encoding="utf-8")
            Path("pkg/done.py").write_text(add_licenses.BASE_HEADER + "\ny = 2\n", encoding="utf-8")
            _quiet(add_licenses.main, ["pkg", "--no-markdown"])
            _quiet(add_licenses.main, ["pkg", "--no-markdown"])
            self.assertEqual(Path("pkg/plain.py").read_text(encoding="utf-8"), add_licenses.BASE_HEADER + "\nx = 1\n")
            self.assertTrue(Path("pkg/__init__.py").read_text(encoding="utf-8").startswith("# noqa D104"))
            self.assertEqual(Path("pkg/done.py").read_text(encoding="utf-8").count("SPDX-License-Identifier"), 1)


class TestCheckConfig(unittest.TestCase):
    def test_a_copy_passes_and_a_changed_file_fails_with_its_diff(self):
        """
        GIVEN a repository whose LICENSE is the shared copy and whose dependabot.yml has one line changed.
        WHEN check-config runs.
        THEN it fails, and its output is the diff of dependabot.yml only.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github").mkdir()
            (root / "LICENSE").write_text(check_config.canonical_text("LICENSE"), encoding="utf-8")
            changed = check_config.canonical_text(".github/dependabot.yml").replace("weekly", "daily", 1)
            (root / ".github/dependabot.yml").write_text(changed, encoding="utf-8")
            self.assertEqual(check_config.differences(root, "LICENSE"), [])
            code, out = _quiet(check_config.main, ["--root", tmp])
            self.assertEqual(code, 1)
            self.assertIn("+++ .github/dependabot.yml", out)
            self.assertNotIn("+++ LICENSE", out)

    def test_a_missing_file_fails(self):
        """
        GIVEN an empty repository.
        WHEN check-config checks the LICENSE.
        THEN it reports the file as missing.
        """
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(check_config.differences(Path(tmp), "LICENSE"), ["LICENSE: missing\n"])


class TestCheckImportBoundaries(unittest.TestCase):
    def test_forbidden_imports_and_empty_directories_are_found(self):
        """
        GIVEN rules for two directories: one with a file that imports a forbidden submodule, one with no Python file.
        WHEN the imports are checked.
        THEN both are reported, and an allowed import and a relative import are not.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mock").mkdir()
            (root / "mock/a.py").write_text(
                "import json\nfrom cryptography.hazmat import primitives\nfrom . import sibling\n", encoding="utf-8"
            )
            found = check_import_boundaries.violations(root, {"mock": ["cryptography"], "gone": ["x"]})
            self.assertEqual(len(found), 3, found)  # cryptography.hazmat and cryptography.hazmat.primitives, gone/
            self.assertTrue(any("gone: no Python files" in line for line in found))
            self.assertFalse(any("json" in line or "sibling" in line for line in found))

    def test_the_rules_come_from_pyproject(self):
        """
        GIVEN a pyproject.toml without the table, and one with a rule that the files keep.
        WHEN check-import-boundaries runs.
        THEN the first ends with 2 and the second with 0.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
            self.assertEqual(_quiet(check_import_boundaries.main, ["--pyproject", str(root / "pyproject.toml")])[0], 2)
            (root / "lib").mkdir()
            (root / "lib/m.py").write_text("import json\n", encoding="utf-8")
            (root / "pyproject.toml").write_text(
                '[tool.pkix-devtools.import-boundaries]\n"lib" = ["cryptography"]\n', encoding="utf-8"
            )
            self.assertEqual(_quiet(check_import_boundaries.main, ["--pyproject", str(root / "pyproject.toml")])[0], 0)


class TestCheckPins(unittest.TestCase):
    def _problems(self, toml: str, kind: str = "suite", allow: bool = False):
        return check_pins.problems(tomllib.loads(toml), kind, allow)

    def test_git_references(self):
        """
        GIVEN git references to a shared package: a tag, a commit, no revision, a branch, git+file, and an ssh URL
              with a tag and a subdirectory.
        WHEN the pins are checked.
        THEN the tags pass, the commit passes only when commit pins are allowed, and the rest fail.
        """
        base = "https://github.com/o/keyutils-py.git"
        cases = {
            f"keyutils-py @ git+{base}@v0.2.0": (True, True),
            f"keyutils-py @ git+{base}@2f44e29b82791ded6fccc648ebacfb54624e4d38": (False, True),
            f"keyutils-py @ git+{base}": (False, False),
            f"keyutils-py @ git+{base}@main": (False, False),
            "keyutils-py @ git+file:///home/me/keyutils-py@v0.2.0": (False, False),
            "pkix-devtools @ git+ssh://git@github.com/o/keyutils-py.git@0.1.0#subdirectory=pkix-devtools": (True, True),
        }
        for requirement, (strict, allowed) in cases.items():
            toml = f"[project]\ndependencies = [{requirement!r}]\n"
            with self.subTest(requirement=requirement):
                self.assertEqual(not self._problems(toml), strict)
                self.assertEqual(not self._problems(toml, allow=True), allowed)

    def test_version_specifiers_for_suites_and_libraries(self):
        """
        GIVEN version specifiers of a shared package, and one of a package that is not shared.
        WHEN they are checked for a suite and for a library.
        THEN a suite needs ==, a library a lower and an upper bound, and the other package is not looked at.
        """
        for specifier, suite_ok, library_ok in (
            ("==0.2.0", True, True), (">=0.2,<0.3", False, True), ("~=0.2.0", False, True), (">=0.1.0", False, False),
            ("", False, False),
        ):  # fmt: skip
            toml = f"[project]\ndependencies = ['pkixutils{specifier}', 'requests']\n"
            with self.subTest(specifier=specifier):
                self.assertEqual(not self._problems(toml, "suite"), suite_ok)
                self.assertEqual(not self._problems(toml, "library"), library_ok)

    def test_uv_sources(self):
        """
        GIVEN uv sources of a shared package: a tag, a commit, a branch, a path and a local git repository, with the
              dev group naming it without a version.
        WHEN the pins are checked.
        THEN only the tag passes, the local repository fails even when commit pins are allowed, and the dev group
             entry is left to its source.
        """
        for source, ok in (("tag = 'v0.2.0'", True), ("rev = '2f44e29'", False), ("branch = 'main'", False)):
            toml = (
                "[dependency-groups]\ndev = ['keyutils-py']\n"
                f"[tool.uv.sources]\nkeyutils-py = {{ git = 'https://github.com/o/keyutils-py.git', {source} }}\n"
            )
            with self.subTest(source=source):
                self.assertEqual(not self._problems(toml), ok)
        toml = "[tool.uv.sources]\nkeyutils-py = { path = '../keyutils-py', editable = true }\n"
        self.assertTrue(self._problems(toml))
        toml = "[tool.uv.sources]\nkeyutils-py = { git = 'file:///home/me/keyutils-py', rev = '2f44e29' }\n"
        self.assertTrue(self._problems(toml, allow=True))


if __name__ == "__main__":
    unittest.main()
