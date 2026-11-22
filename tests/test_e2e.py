"""End to end: one temp world through the whole lifecycle, driven only through the CLI
(subprocess, --base). Keys are ephemeral, in the temp dir; nothing touches the repo."""
import os
import shutil
import subprocess
import sys
import unittest

from tests.worlds import REPO, tmpdir
from mapsynclib.demo import keygen
from mapsynclib.files import read_json, write_json

CLI = os.path.join(REPO, "mapsync.py")


class EndToEnd(unittest.TestCase):
    def cli(self, *args, ok=True):
        r = subprocess.run([sys.executable, CLI, "--base", self.base, *args], capture_output=True,
                           text=True, cwd="/")
        out = r.stdout + r.stderr
        if ok is not None:
            self.assertEqual(r.returncode, 0 if ok else 1, f"{' '.join(args)}:\n{out}")
        self.assertNotIn("Traceback", out)
        return out

    def green(self, when):
        out = self.cli("verify")
        self.assertIn("GREEN", out, when)

    def test_whole_lifecycle(self):
        t = tmpdir(self)
        self.base = os.path.join(t, "w")
        keys = os.path.join(self.base, "keys")

        # 1. make a world (fresh keys in w/keys), owner signs, index
        out = self.cli("demo", self.base)
        self.assertIn("top_root", out)
        self.cli("sign", "maps/alice/map.json", os.path.join(keys, "alice"))
        self.cli("index")
        self.green("fresh world")

        # 2. publish: log append, two witnesses anchor the head
        self.assertIn("seq 0", self.cli("log", "append"))
        with open(os.path.join(self.base, "witnesses"), "w") as f:
            for wit in ("w1", "w2"):
                f.write(f"{wit} {keygen(os.path.join(t, 'wk', wit), wit)}\n")
        for wit in ("w1", "w2"):
            self.assertIn(f"{wit} witnessed seq 0", self.cli("anchor", wit, os.path.join(t, "wk", wit)))
        self.cli("anchor", "verify", "--min-witnesses", "2")
        self.green("after anchoring seq 0")

        # 3. prove one node; the proof checks on its own
        proof = os.path.join(t, "review.proof.json")
        self.cli("prove", "alice", "review", "-o", proof)
        self.assertIn("VALID", self.cli("check-proof", proof))
        self.assertEqual(read_json(proof)["node"]["id"], "review")

        # 4. rotate alice's Cody (owner + old agent key sign), the new key re-signs its nodes
        new = os.path.join(keys, "alice_cody2")
        keygen(new, "alice:cody#2")
        self.assertIn("rotated", self.cli("keys", "rotate", "alice", "agent:cody", new + ".pub",
                                          "--sign", os.path.join(keys, "alice"),
                                          "--sign", os.path.join(keys, "alice_cody")))
        for node in ("review", "notes"):
            self.cli("agent-sign", "maps/alice/map.json", node, new)
        self.cli("sign", "maps/alice/map.json", os.path.join(keys, "alice"))
        self.cli("index")
        self.assertIn("rotated 1 time", self.cli("keys", "show", "alice"))
        self.cli("keys", "verify")

        # 5. publish again and anchor the new head
        self.assertIn("seq 1", self.cli("log", "append"))
        for wit in ("w1", "w2"):
            self.assertIn(f"{wit} witnessed seq 1", self.cli("anchor", wit, os.path.join(t, "wk", wit)))
        self.cli("log", "verify")
        self.cli("anchor", "verify", "--min-witnesses", "2")
        self.green("after rotation and seq 1")
        # the old proof still checks on its own (it proves seq 0), but not against the new top_root
        self.assertIn("VALID", self.cli("check-proof", proof))
        top = read_json(os.path.join(self.base, "index.json"))["top_root"]
        self.assertIn("INVALID", self.cli("check-proof", proof, "--top-root", top, ok=False))
        self.cli("prove", "alice", "review", "-o", proof)
        self.assertIn("VALID", self.cli("check-proof", proof, "--top-root", top))

        # 6. read the world: claims, suggester
        out = self.cli("claims", "--strict")            # exit 0: no CONTRADICTION
        self.assertIn("alice:review", out)
        self.assertIn("bob:prcheck", out)
        out = self.cli("suggest", "Draft", "of", "what", "shipped", "this", "week")
        self.assertIn("Text", out)
        self.cli("suggest", "--map", "alice")

        # 7. sync-check against a copy: in sync; then one edit names owner and node
        other = os.path.join(t, "other")
        shutil.copytree(self.base, other, ignore=shutil.ignore_patterns("keys"))
        self.assertIn("IN SYNC", self.cli("sync-check", other))
        mp = os.path.join(other, "maps", "bob", "map.json")
        m = read_json(mp)
        next(n for n in m["nodes"] if n["id"] == "deadline")["content"] = "Monday"
        write_json(mp, m, indent=2)
        subprocess.run([sys.executable, CLI, "--base", other, "index"], capture_output=True, check=True)
        out = self.cli("sync-check", other, ok=False)
        self.assertIn("OUT OF SYNC", out)
        self.assertIn("~ bob", out)
        self.assertIn("bob:deadline  differs", out)
        self.assertNotIn("~ alice", out)

        # 8. this world is untouched by all that: still green, still witnessed twice
        self.green("at the end")
        self.cli("anchor", "verify", "--min-witnesses", "2")
        self.cli("anchor", "verify", "--min-witnesses", "3", ok=False)


if __name__ == "__main__":
    unittest.main()
