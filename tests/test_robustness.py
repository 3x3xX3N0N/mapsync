"""verify never crashes on malformed input: it prints RED with a reason and exits 1."""
import os
import subprocess
import sys
import unittest

from tests.worlds import REPO, quietly, shipped_copy
from mapsynclib.files import read_json, write_json
from mapsynclib.index import verify

CLI = os.path.join(REPO, "mapsync.py")


class Malformed(unittest.TestCase):
    def check(self, sabotage, reason):
        d = shipped_copy(self)
        sabotage(d)
        r = subprocess.run([sys.executable, CLI, "--base", d, "verify"], capture_output=True, text=True, cwd="/")
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 1, out)
        self.assertNotIn("Traceback", out)
        self.assertTrue(any(l.startswith("RED") and reason in l for l in out.splitlines()), out)
        ok, _ = quietly(verify, d)                 # the library call does not raise either
        self.assertFalse(ok)

    def test_missing_file(self):
        self.check(lambda d: os.remove(os.path.join(d, "maps", "alice", "root.sig")), "missing file")

    def test_missing_index(self):
        self.check(lambda d: os.remove(os.path.join(d, "index.json")), "index.json")

    def test_invalid_json_map(self):
        def go(d):
            with open(os.path.join(d, "maps", "bob", "map.json"), "w") as f:
                f.write("{not json")
        self.check(go, "invalid JSON")

    def test_invalid_json_index(self):
        def go(d):
            with open(os.path.join(d, "index.json"), "w") as f:
                f.write("[1, 2")
        self.check(go, "invalid JSON")

    def edit_alice(self, fn):
        def go(d):
            p = os.path.join(d, "maps", "alice", "map.json")
            m = read_json(p)
            fn(m)
            write_json(p, m)
        return go

    def test_missing_field(self):
        self.check(self.edit_alice(lambda m: m["nodes"][0].pop("salt")), "missing field 'salt'")

    def test_missing_nodes(self):
        self.check(self.edit_alice(lambda m: m.pop("nodes")), "missing field 'nodes'")

    def test_wrong_types(self):
        self.check(self.edit_alice(lambda m: m["nodes"].__setitem__(0, "x")), "must be a JSON object")
        self.check(self.edit_alice(lambda m: m["nodes"][1].update(same_as=5)), "same_as must be a list")

    def test_map_not_an_object(self):
        self.check(lambda d: write_json(os.path.join(d, "maps", "alice", "map.json"), [1, 2]),
                   "must be a JSON object")

    def test_index_not_an_object(self):
        self.check(lambda d: write_json(os.path.join(d, "index.json"), []), "")


if __name__ == "__main__":
    unittest.main()
