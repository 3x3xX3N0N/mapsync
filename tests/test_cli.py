import json
import os
import subprocess
import sys
import unittest

from tests.worlds import REPO, SHIPPED_ROOTS, demo_world, tmpdir
from mapsynclib.files import read_json
from mapsynclib.world import load, save

CLI = os.path.join(REPO, "mapsync.py")


def run(*args, cwd=None):
    return subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, cwd=cwd or tmpdir_cwd)


tmpdir_cwd = "/"


class CLI_(unittest.TestCase):
    def test_verify_temp_world_exit_0(self):
        w = demo_world(self)
        r = run("--base", w["base"], "verify")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("GREEN", r.stdout)

    def test_tampered_world_exit_1(self):
        w = demo_world(self)
        m = load(w["base"], "alice")
        m["nodes"][0]["content"] += "!"
        save(w["base"], "alice", m)
        r = run("--base", w["base"], "verify")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("INVALID", r.stdout)

    def test_base_after_subcommand_and_default_command(self):
        w = demo_world(self)
        self.assertEqual(run("verify", "--base", w["base"]).returncode, 0)
        r = run("--base", w["base"])          # no command = verify
        self.assertEqual(r.returncode, 0)
        self.assertIn(w["top_root"][:16], r.stdout)

    def test_edit_sign_index_cycle(self):
        w = demo_world(self)
        b = w["base"]
        m = load(b, "bob")
        m["nodes"][-1]["content"] = "Thursday"
        save(b, "bob", m)
        self.assertEqual(run("--base", b, "verify").returncode, 1)
        self.assertEqual(run("--base", b, "sign", "maps/bob/map.json", w["owners"]["bob"]).returncode, 0)
        r = run("--base", b, "index")
        self.assertTrue(r.stdout.startswith("top_root "))
        self.assertEqual(read_json(os.path.join(b, "index.json"))["top_root"], r.stdout.split()[1])
        self.assertEqual(run("--base", b, "verify").returncode, 0)
        root = run("--base", b, "root", "maps/bob/map.json").stdout.strip()
        self.assertEqual(root, read_json(os.path.join(b, "index.json"))["maps"][1]["root"])

    def test_shipped_commands(self):
        self.assertEqual(run("root", "maps/alice/map.json", cwd=REPO).stdout.strip(), SHIPPED_ROOTS["alice"])
        self.assertIn("COLLISION", run("names").stdout)
        self.assertIn("IntentionalProcess   alice:'Review readiness', bob:'PR check'", run("concepts").stdout)
        d = run("diff", "maps/alice/map.json", "maps/bob/map.json", cwd=REPO).stdout
        self.assertIn("+ changelog  only in maps/bob/map.json", d)
        self.assertIn("~ cody  differs", d)

    def test_demo_command_and_g1_on_it(self):
        d = os.path.join(tmpdir(self), "demo")
        r = run("demo", d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(run("--base", d, "verify").returncode, 0)
        g = run("--base", d, "g1")
        self.assertEqual(g.returncode, 0, g.stdout)
        self.assertNotIn("BAD", g.stdout)

    def test_unknown_command_exit_2(self):
        self.assertEqual(run("bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
