import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("verify_dco", ROOT / "tools/verify_dco.py")
dco = importlib.util.module_from_spec(spec); spec.loader.exec_module(dco)


class DCOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.git("init", "-q")
        self.git("config", "user.name", "Contributor"); self.git("config", "user.email", "contributor@example.invalid")
        (self.root/"f").write_text("base\n"); self.git("add", "f"); self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args): return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()
    def commit(self, title, trailers=""):
        (self.root/"f").write_text((self.root/"f").read_text()+title+"\n"); self.git("add", "f")
        args=["commit","-qm",title]
        if trailers: args += ["-m", trailers]
        self.git(*args); return self.git("rev-parse","HEAD")

    def test_author_and_distinct_cosigner_pass(self):
        head=self.commit("ok","Signed-off-by: Contributor <contributor@example.invalid>\nSigned-off-by: Reviewer <reviewer@example.invalid>")
        self.assertEqual(dco.verify_range(self.root,f"{self.base}..{head}"),[head])

    def test_unsigned_mixed_range_fails(self):
        self.commit("ok","Signed-off-by: Contributor <contributor@example.invalid>")
        head=self.commit("bad")
        with self.assertRaises(dco.DCOError): dco.verify_range(self.root,f"{self.base}..{head}")

    def test_fixed_baseline_catches_violation_before_event_range(self):
        unsigned=self.commit("unsigned")
        head=self.commit("signed","Signed-off-by: Contributor <contributor@example.invalid>")
        self.assertEqual(dco.verify_range(self.root,f"{unsigned}..{head}"),[head])
        with self.assertRaises(dco.DCOError):dco.verify_head(self.root,head,self.base)

    def test_malformed_duplicate_and_wrong_author_fail(self):
        cases=(
            "Signed-off-by Contributor <contributor@example.invalid>",
            "Signed-off-by: Contributor <contributor@example.invalid>\nSigned-off-by: Contributor <contributor@example.invalid>",
            "Signed-off-by: Other <other@example.invalid>",
            "Signed-off-by: Contributor <contributor@example.invalid>\nSigned-off-by malformed",
        )
        for trailers in cases:
            head=self.commit("case",trailers)
            with self.subTest(trailers=trailers), self.assertRaises(dco.DCOError): dco.verify_range(self.root,f"{head}^..{head}")

    def test_zero_and_empty_ranges_fail(self):
        head=self.git("rev-parse","HEAD")
        for value in (f"{'0'*40}..{head}",f"{head}..{head}"):
            with self.subTest(value=value), self.assertRaises(dco.DCOError): dco.verify_range(self.root,value)

    def test_three_dot_and_non_ancestor_ranges_fail(self):
        head=self.commit("signed","Signed-off-by: Contributor <contributor@example.invalid>")
        for value in (f"{self.base}...{head}",f"{head}..{self.base}"):
            with self.subTest(value=value),self.assertRaises(dco.DCOError):dco.verify_range(self.root,value)


if __name__ == "__main__": unittest.main()
