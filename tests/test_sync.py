import os
import shutil
import subprocess
import sys
import unittest

from tests.worlds import REPO, demo_world, shipped_copy
from mapsynclib.files import write_bytes
from mapsynclib.index import write_index
from mapsynclib.signing import sign
from mapsynclib.sync import sync_report
from mapsynclib.world import load, map_path, save

CLI = os.path.join(REPO, "mapsync.py")


def edit(base, owner, node_id, **kw):
    m = load(base, owner)
    next(n for n in m["nodes"] if n["id"] == node_id).update(**kw)
    save(base, owner, m)


class Sync(unittest.TestCase):
    def test_in_sync_with_copy(self):
        same, lines = sync_report(REPO, shipped_copy(self))
        self.assertTrue(same)
        self.assertEqual(lines, ["IN SYNC  top_root 5063e96c07099d44…"])

    def test_one_changed_node_named(self):
        b = shipped_copy(self)
        edit(b, "alice", "review", content="Changed later")
        write_index(b)
        same, lines = sync_report(REPO, b)
        self.assertFalse(same)
        self.assertTrue(lines[0].startswith("OUT OF SYNC"))
        self.assertIn("~ alice  root 656b6e9d362ee0bb…", "\n".join(lines))
        self.assertIn("    ~ alice:review  differs", lines)
        self.assertFalse(any("bob" in ln for ln in lines))
        # the other index was rebuilt, so no staleness warning (its alice root.sig is stale, but
        # sync-check compares published roots; `verify` is what checks signatures)
        self.assertFalse(any(ln.startswith("warning") for ln in lines))

    def test_added_removed_owner_and_nodes(self):
        b = shipped_copy(self)
        m = load(b, "bob")
        m["nodes"] = [n for n in m["nodes"] if n["id"] != "deadline"]
        m["nodes"].append({"id": "extra", "label": "x", "sumo": "Text", "content": "y", "salt": "z"})
        save(b, "bob", m)
        shutil.rmtree(os.path.join(b, "maps", "alice"))
        os.makedirs(os.path.join(b, "maps", "carol"))
        save(b, "carol", {"owner": "carol", "nodes": []})
        write_bytes(os.path.join(b, "maps", "carol", "root.sig"), b"none")
        write_index(b)
        same, lines = sync_report(REPO, b)
        self.assertFalse(same)
        for want in ("- alice  only here", "+ carol  only there", "    - bob:deadline  only here",
                     "    + bob:extra  only there"):
            self.assertIn(want, lines)

    def test_index_json_paths_and_stale_warning(self):
        b = shipped_copy(self)
        same, _ = sync_report(os.path.join(REPO, "index.json"), os.path.join(b, "index.json"))
        self.assertTrue(same)
        edit(b, "bob", "deadline", content="Monday")        # map changed, index not rebuilt
        same, lines = sync_report(REPO, b)
        self.assertTrue(same)                              # the published tops still agree...
        self.assertTrue(lines[0].startswith("warning: there"))  # ...but it says so

    def test_resigned_and_vocabulary(self):
        w = demo_world(self)
        b = w["base"]
        other = os.path.join(os.path.dirname(b), "w2")
        shutil.copytree(b, other)
        edit(other, "bob", "deadline", content="Monday")
        sign(map_path(other, "bob"), w["owners"]["bob"], other, quiet=True)
        write_index(other)
        same, lines = sync_report(b, other)
        self.assertFalse(same)
        self.assertIn("    ~ bob:deadline  differs", lines)
        with open(os.path.join(other, "sumo", "terms.txt"), "a") as f:
            f.write("Unicorn\n")
        write_index(other)
        same, lines = sync_report(b, other)
        self.assertTrue(any("vocabulary differs" in ln for ln in lines))
        self.assertIn("    (no node differs: the map head changed — owner name or vocabulary)", lines)


class SyncCLI(unittest.TestCase):
    def run_(self, *a):
        return subprocess.run([sys.executable, CLI, *a], capture_output=True, text=True, cwd="/")

    def test_exit_codes(self):
        b = shipped_copy(self)
        r = self.run_("sync-check", b)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("IN SYNC", r.stdout)
        edit(b, "bob", "changelog", label="Changes")
        write_index(b)
        r = self.run_("sync-check", b)
        self.assertEqual(r.returncode, 1)
        self.assertIn("~ bob:changelog  differs", r.stdout)
        r = self.run_("sync-check", os.path.join(b, "index.json"), REPO)   # two worlds, either order
        self.assertEqual(r.returncode, 1)
        self.assertIn("~ bob:changelog  differs", r.stdout)
        self.assertEqual(self.run_("--base", b, "sync-check", b).returncode, 0)


if __name__ == "__main__":
    unittest.main()
