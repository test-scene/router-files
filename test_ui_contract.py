"""Static UI contract tests work even without Tk/CustomTkinter in CI."""
import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent


class UIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / 'app.py').read_text(encoding='utf-8')
        cls.program = ast.parse(cls.source)
        cls.methods = set()
        for node in ast.walk(cls.program):
            if isinstance(node, ast.ClassDef) and node.name == 'WiFiVendorApp':
                cls.methods = {n.name for n in node.body if isinstance(n, ast.FunctionDef)}

    def test_navigation_handlers_exist(self):
        for method in ('_open_selected', '_go_back', '_connect_selected', '_ask_password',
                       '_on_row_click', '_build_details'):
            self.assertIn(method, self.methods)

    def test_channel_column_is_removed(self):
        self.assertNotIn('("channel", "Канал",', self.source)
        self.assertNotIn('"channel", "security", "adapter"', self.source)
        self.assertNotIn('"Канал", "Защита / WPS"', self.source)
        self.assertIn('("signal", "Сигнал")', self.source)

    def test_connect_happens_only_from_detail_handler(self):
        self.assertIn('command=self._connect_selected', self.source)
        self.assertIn('command=self._go_back', self.source)
        self.assertIn('self.tree.bind("<ButtonRelease-1>", self._on_row_click)', self.source)
        self.assertNotIn('self.choose_button', self.source)
        self.assertIn('selection()', self.source)


if __name__ == '__main__':
    unittest.main()
