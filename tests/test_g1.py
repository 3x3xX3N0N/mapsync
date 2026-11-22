"""g1 on the shipped repo: exit 0, the forgery rows exist, every C2-C7 check has a red row."""
import os
import subprocess
import sys
import unittest

from tests.worlds import REPO
from mapsynclib import g1 as g1mod

CLI = os.path.join(REPO, "mapsync.py")

FORGERY = [
    "Alice's Cody signs Bob's node (cross-key forgery)",
    "Bob's owner key signs Alice's root",
    "an agent signs as the owner (namespace confusion: mapsync-agent sig used as root.sig)",
    "an owner sig reused as an anchor receipt sig (namespace confusion)",
]


class G1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = subprocess.run([sys.executable, CLI, "g1"], capture_output=True, text=True, cwd="/")
        cls.listed = subprocess.run([sys.executable, CLI, "g1", "--list"], capture_output=True, text=True, cwd="/")

    def test_exit_0_and_summary(self):
        self.assertEqual(self.r.returncode, 0, self.r.stdout + self.r.stderr)
        n = len(g1mod.rows())
        self.assertIn(f"G1: {n} rows", self.r.stdout)
        self.assertNotIn("BAD", self.r.stdout)
        self.assertEqual(sum(1 for l in self.r.stdout.splitlines() if l.startswith("ok ")), n)

    def test_forgery_rows_present_and_red(self):
        for name in FORGERY:
            line = next((l for l in self.r.stdout.splitlines() if name in l), None)
            self.assertIsNotNone(line, name)
            self.assertTrue(line.startswith("ok "), line)
            self.assertIn("-> red (expected red)", line)

    def test_list(self):
        self.assertEqual(self.listed.returncode, 0)
        for name in FORGERY:
            self.assertIn(name, self.listed.stdout)
        self.assertIn(f"{len(g1mod.rows())} rows", self.listed.stdout)

    def test_namespaces_distinct(self):
        self.assertTrue(g1mod.namespaces_distinct())
        self.assertEqual(len(set(g1mod.NAMESPACES.values())), 4)

    def test_every_group_has_a_red_row(self):
        groups = {}
        for group, _, _, want, _ in g1mod.rows():
            groups.setdefault(group, []).append(want)
        for g in ("verify", "log", "anchor", "keys", "vocab", "forgery", "proof", "sync", "audit"):
            self.assertIn(False, groups[g], g)


if __name__ == "__main__":
    unittest.main()
