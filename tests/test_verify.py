import os
import unittest

from tests.worlds import REPO, demo_world, quietly, shipped_copy
from mapsynclib.files import read_json, write_json
from mapsynclib.g1 import NAMES_ROWS, VERIFY_ROWS, cody_collision, g1, run_row
from mapsynclib.index import verify, write_index
from mapsynclib.signing import sign
from mapsynclib.world import load, map_path, save


class Verify(unittest.TestCase):
    def test_shipped_repo_green(self):
        ok, out = quietly(verify, REPO)
        self.assertTrue(ok, out)
        self.assertIn("GREEN", out)

    def test_make_world_green(self):
        w = demo_world(self)
        ok, out = quietly(verify, w["base"])
        self.assertTrue(ok, out)
        for o in ("alice", "bob"):
            self.assertTrue(os.path.exists(w["owners"][o]))
            self.assertTrue(os.path.exists(os.path.join(w["base"], "maps", o, "root.sig")))
        self.assertEqual(sorted(w["agents"]), ["alice:cody", "bob:cody"])
        self.assertTrue(os.path.exists(os.path.join(w["base"], "maps", "alice", "agent_sigs", "review.sig")))

    def test_make_world_has_shipped_shape(self):
        w = demo_world(self)
        for o in ("alice", "bob"):
            ids = lambda b: [(n["id"], n["label"], n["sumo"], sorted(n)) for n in load(b, o)["nodes"]]
            self.assertEqual(ids(w["base"]), ids(REPO), o)

    def test_each_sabotage_goes_red_on_shipped(self):
        for name, sabotage, want in VERIFY_ROWS:
            with self.subTest(name):
                d = shipped_copy(self)
                sabotage(d)
                self.assertEqual(verify(d, quiet=True), want)

    def test_each_sabotage_goes_red_on_make_world(self):
        w = demo_world(self)
        for name, sabotage, want in VERIFY_ROWS:
            with self.subTest(name):
                self.assertEqual(run_row(w["base"], sabotage, lambda d: verify(d, quiet=True)), want)
        for name, sabotage, want in NAMES_ROWS:
            with self.subTest(name):
                self.assertEqual(run_row(w["base"], sabotage, cody_collision), want)

    def test_g1_passes_on_shipped_and_demo(self):
        ok, out = quietly(g1, REPO)
        self.assertTrue(ok, out)
        self.assertNotIn("BAD", out)
        w = demo_world(self)
        self.assertTrue(quietly(g1, w["base"])[0])

    def test_owner_can_resign_after_edit(self):
        w = demo_world(self)
        d = w["base"]
        m = load(d, "bob")
        m["nodes"][-1]["content"] = "Thursday"
        save(d, "bob", m)
        self.assertFalse(verify(d, quiet=True))
        quietly(sign, map_path(d, "bob"), w["owners"]["bob"], d)
        self.assertFalse(verify(d, quiet=True))          # index still stale
        write_index(d)
        self.assertTrue(verify(d, quiet=True))

    def test_owner_signing_with_wrong_key_is_red(self):
        w = demo_world(self)
        d = w["base"]
        quietly(sign, map_path(d, "alice"), w["owners"]["bob"], d)
        write_index(d)
        self.assertFalse(verify(d, quiet=True))

    def test_missing_index_entry_is_red(self):
        d = shipped_copy(self)
        p = os.path.join(d, "index.json")
        j = read_json(p)
        j["maps"] = j["maps"][:1]
        write_json(p, j)
        self.assertFalse(verify(d, quiet=True))


if __name__ == "__main__":
    unittest.main()
