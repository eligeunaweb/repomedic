import tempfile
import unittest
from pathlib import Path
from repomedic.audit import scan, html_report
from repomedic.cli import main

class TestAudit(unittest.TestCase):
    def test_missing_docs(self):
        with tempfile.TemporaryDirectory() as temp:
            result = scan(Path(temp))
            self.assertIn("missing-readme", [f["id"] for f in result["findings"]])
    def test_redaction(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            secret = "ghp_" + "a" * 36
            (path / "app.py").write_text("token = '" + secret + "'\n")
            result = scan(path)
            self.assertEqual(result["summary"]["high"], 1)
            self.assertNotIn(secret, str(result))
            self.assertEqual(main([temp, "--fail-on-high", "--output", str(path / "report.txt")]), 1)
    def test_html_escaping(self):
        report = {"files_scanned": 0, "findings": [{"message": "<script>alert(1)</script>"}]}
        self.assertNotIn("<script>", html_report(report))
    def test_ignores_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "outside.py").write_text("hello")
            (root / "link.py").symlink_to(root / "outside.py")
            self.assertEqual(scan(root)["files_scanned"], 1)

if __name__ == "__main__": unittest.main()
