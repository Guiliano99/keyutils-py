# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""``keyutils_py.types`` is the single access point for the key types."""

import ast
import importlib
import pathlib
import unittest

import keyutils_py.types as key_types


class TestTypesExports(unittest.TestCase):
    """The names ``keyutils_py.types`` promises are available and are the real key classes."""

    def test_every_export_resolves(self):
        """GIVEN `__all__` / WHEN every name is accessed / THEN each one resolves."""
        for name in key_types.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(key_types, name))

    def test_lazy_export_is_the_defining_class(self):
        """GIVEN the lazily exported classes / WHEN compared to the defining module / THEN they are identical."""
        for module, names in key_types._LAZY_EXPORTS.items():
            defined_in = importlib.import_module(module)
            for name in names:
                with self.subTest(name=name):
                    self.assertIs(getattr(key_types, name), getattr(defined_in, name))

    def test_all_lists_every_lazy_export(self):
        """GIVEN the lazy exports / WHEN `__all__` is read / THEN it contains all of them."""
        self.assertLessEqual(set(key_types._LAZY_MODULE_OF), set(key_types.__all__))

    def test_type_checking_block_matches_lazy_exports(self):
        """GIVEN the `TYPE_CHECKING` imports / WHEN compared to the lazy table / THEN type checkers see every name."""
        tree = ast.parse(pathlib.Path(key_types.__file__).read_text())
        guarded = next(
            node for node in tree.body if isinstance(node, ast.If) and getattr(node.test, "id", None) == "TYPE_CHECKING"
        )
        imported = {alias.name for node in guarded.body if isinstance(node, ast.ImportFrom) for alias in node.names}
        self.assertEqual(imported, set(key_types._LAZY_MODULE_OF))

    def test_unknown_name_raises_attribute_error(self):
        """GIVEN a name that is not exported / WHEN it is accessed / THEN an AttributeError is raised."""
        with self.assertRaises(AttributeError):
            _ = key_types.NoSuchKeyClass
