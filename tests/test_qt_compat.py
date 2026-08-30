"""Regression tests for the IDA Qt compatibility shim."""

import ast
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import qt_compat


class TestQtCompat(unittest.TestCase):
    def test_named_members_do_not_depend_on_module_all(self):
        """PySide members omitted from wildcard exports remain available."""
        module = SimpleNamespace(
            __all__=(),
            QObject=object,
            QDateTime=object,
            QPointF=object,
        )

        exports = qt_compat._binding_exports(module)

        self.assertIn("QObject", exports)
        self.assertIn("QDateTime", exports)
        self.assertIn("QPointF", exports)

    def test_all_consumer_imports_are_exported(self):
        """Every symbol imported from qt_compat is present in this binding."""
        source_root = Path(__file__).resolve().parent.parent / "src"
        requested = set()

        for path in source_root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (isinstance(node, ast.ImportFrom) and node.module and
                        node.module.endswith("qt_compat")):
                    requested.update(
                        alias.name for alias in node.names if alias.name != "*"
                    )

        missing = sorted(name for name in requested if not hasattr(qt_compat, name))
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
