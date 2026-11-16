import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import restore_drill as r


class T(unittest.TestCase):
    def test_drill_passes(self):
        passed, rep = r.run_drill(out=lambda *_: None)
        self.assertTrue(passed)
        self.assertEqual(rep["files"], 4)

    def test_tampered_backup_fails(self):
        passed, rep = r.run_drill(tamper=True, out=lambda *_: None)
        self.assertFalse(passed)
        self.assertTrue(rep["problems"])

    def test_verify_detects_changed_missing_and_extra(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "a.txt").write_text("a")
            (root / "b.txt").write_text("b")
            manifest = r.build_manifest(root)
            self.assertEqual(r.verify(manifest, root), [])
            (root / "a.txt").write_text("changed")
            (root / "b.txt").unlink()
            (root / "c.txt").write_text("c")
            joined = " | ".join(r.verify(manifest, root))
            self.assertIn("hash mismatch: a.txt", joined)
            self.assertIn("missing: b.txt", joined)
            self.assertIn("unexpected file: c.txt", joined)

    def test_exit_codes(self):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(r.main([]), 0)
            self.assertEqual(r.main(["--tamper"]), 1)


if __name__ == "__main__":
    unittest.main()
