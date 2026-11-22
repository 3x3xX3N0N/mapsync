import copy
import json
import os
import shutil
import subprocess
import sys
import unittest

from tests.worlds import REPO, SHIPPED_ROOTS, SHIPPED_TOP, demo_world, shipped_copy, tmpdir
from mapsynclib.files import write_json
from mapsynclib.hashing import climb, merkle, merkle_path, path_sides, sha
from mapsynclib.proofs import check_proof, prove
from mapsynclib.world import load, owners

SIGNERS = os.path.join(REPO, "allowed_signers")
CLI = os.path.join(REPO, "mapsync.py")


class AuditPaths(unittest.TestCase):
    def test_every_leaf_of_every_size_climbs_to_merkle(self):
        for n in range(1, 12):
            hs = [sha(bytes([k])) for k in range(n)]
            for i in range(n):
                p = merkle_path(hs, i)
                self.assertEqual([s["side"] for s in p], path_sides(i, n))
                self.assertEqual(climb(hs[i], p, i, n), merkle(hs), (n, i))

    def test_odd_level_duplicate_is_enforced(self):
        hs = [sha(bytes([k])) for k in range(3)]
        p = merkle_path(hs, 2)
        self.assertEqual(p[0]["hash"], hs[2])            # paired with itself
        p[0]["hash"] = hs[1]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            climb(hs[2], p, 2, 3)

    def test_wrong_shape_rejected(self):
        hs = [sha(bytes([k])) for k in range(4)]
        p = merkle_path(hs, 1)
        with self.assertRaises(ValueError):
            climb(hs[1], p[:1], 1, 4)
        with self.assertRaises(ValueError):
            climb(hs[1], p, 1, 5)
        with self.assertRaises(ValueError):
            path_sides(4, 4)


class ValidProofs(unittest.TestCase):
    def test_every_shipped_node(self):
        for o in owners(REPO):
            for n in load(REPO, o)["nodes"]:
                p = prove(REPO, o, n["id"])
                ok, why = check_proof(p, SIGNERS, SHIPPED_TOP)
                self.assertTrue(ok, f"{o}:{n['id']}: {why}")
                self.assertEqual(p["map"]["root"], SHIPPED_ROOTS[o])

    def test_every_demo_world_node(self):
        w = demo_world(self)
        signers = os.path.join(w["base"], "allowed_signers")
        for o in owners(w["base"]):
            for n in load(w["base"], o)["nodes"]:
                ok, why = check_proof(prove(w["base"], o, n["id"]), signers, w["top_root"])
                self.assertTrue(ok, f"{o}:{n['id']}: {why}")

    def test_selective_disclosure(self):
        """Only the revealed node's content and salt are in the proof; nothing reads the world."""
        p = prove(REPO, "alice", "review")
        text = json.dumps(p)
        for n in load(REPO, "alice")["nodes"] + load(REPO, "bob")["nodes"]:
            if n["id"] == "review" and n.get("by") == "cody" and "pubkey" not in n:
                self.assertIn(n["salt"], text)
                continue
            self.assertNotIn(n["salt"], text, n["id"])
            self.assertNotIn(n["content"], text, n["id"])
        # check with the world gone: only the proof and a signers file
        d = tmpdir(self)
        shutil.copy(SIGNERS, d)
        ok, why = check_proof(json.loads(text), os.path.join(d, "allowed_signers"))
        self.assertTrue(ok, why)

    def test_unknown_node_or_stale_index(self):
        with self.assertRaises(KeyError):
            prove(REPO, "alice", "nope")
        b = shipped_copy(self)
        m = load(b, "bob")
        m["nodes"][0]["content"] += "!"
        write_json(os.path.join(b, "maps", "bob", "map.json"), m)
        with self.assertRaisesRegex(ValueError, "index.json"):
            prove(b, "alice", "review")


def _tamper(fn):
    p = copy.deepcopy(prove(REPO, "alice", "review"))
    fn(p)
    return check_proof(p, SIGNERS)


class TamperedProofs(unittest.TestCase):
    def assertRed(self, fn, reason=""):
        ok, why = _tamper(fn)
        self.assertFalse(ok)
        if reason:
            self.assertRegex(why, reason)

    def test_revealed_node_content(self):
        self.assertRed(lambda p: p["node"].update(content="Something else"), "does not hash")

    def test_revealed_node_every_field_and_extra_field(self):
        for k in ("id", "label", "sumo", "salt", "by"):
            self.assertRed(lambda p, k=k: p["node"].update({k: p["node"][k] + "x"}))
        self.assertRed(lambda p: p["node"].update(secret="added"), "unexpected")

    def test_node_and_leaf_rewritten_together(self):
        from mapsynclib.hashing import leaf
        def go(p):
            p["node"]["content"] = "Rewritten"
            p["leaf"] = leaf(p["node"])
        self.assertRed(go, "map root|duplicate")  # review is the lone last leaf of 5

    def test_each_sibling_hash(self):
        for which in ("path", "head_path"):
            for k in range(len(prove(REPO, "alice", "review")["map"][which])):
                self.assertRed(lambda p, w=which, k=k: p["map"][w][k].update(hash="ab" * 32))
        for which in ("path", "terms_path"):
            self.assertRed(lambda p, w=which: p["index"][w][0].update(hash="cd" * 32))

    def test_path_flags(self):
        flip = {"L": "R", "R": "L"}
        for k in range(len(prove(REPO, "alice", "review")["map"]["path"])):
            self.assertRed(lambda p, k=k: p["map"]["path"][k].update(side=flip[p["map"]["path"][k]["side"]]),
                           "side")
        self.assertRed(lambda p: p["map"].update(leaf_index=p["map"]["leaf_index"] ^ 1))
        self.assertRed(lambda p: p["map"].update(leaf_index=0), "not a node position")
        self.assertRed(lambda p: p["map"]["path"].pop(), "steps")

    def test_signature(self):
        bob_sig = prove(REPO, "bob", "deadline")["map"]["root_sig"]
        self.assertRed(lambda p: p["map"].update(root_sig=bob_sig), "signature")
        self.assertRed(lambda p: p["map"].update(root_sig=p["map"]["root_sig"].replace("A", "B", 1)))
        # a verifier who trusts different keys for alice rejects it
        w = demo_world(self)
        ok, why = check_proof(prove(REPO, "alice", "review"), os.path.join(w["base"], "allowed_signers"))
        self.assertFalse(ok)
        self.assertIn("signature", why)

    def test_claimed_owner(self):
        self.assertRed(lambda p: p.update(owner="bob"), "head")
        def all_bob(p):                                # rewrite every owner field consistently
            p["owner"] = "bob"
            p["map"]["head"]["owner"] = "bob"
            p["index"]["entry"]["owner"] = "bob"
        self.assertRed(all_bob)

    def test_top_root_and_index(self):
        self.assertRed(lambda p: p["index"].update(top_root="0" * 64), "top_root")
        self.assertRed(lambda p: p["index"]["entry"].update(sig_sha="0" * 64), "index entry")
        ok, why = check_proof(prove(REPO, "alice", "review"), SIGNERS, "1" * 64)
        self.assertFalse(ok)
        self.assertIn("expected", why)

    def test_vocabulary(self):
        self.assertRed(lambda p: p.update(sumo_terms=p["sumo_terms"] + "Unicorn\n"), "term list")

    def test_malformed(self):
        self.assertRed(lambda p: p.pop("map"), "malformed")
        self.assertRed(lambda p: p.update(format="v0"), "format")


class ProofCLI(unittest.TestCase):
    def run_(self, *a):
        return subprocess.run([sys.executable, CLI, *a], capture_output=True, text=True, cwd="/")

    def test_prove_then_check_on_shipped_repo(self):
        f = os.path.join(tmpdir(self), "p.json")
        r = self.run_("prove", "alice", "review", "-o", f)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_("check-proof", f)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(r.stdout.startswith("VALID"))
        r = self.run_("check-proof", f, "--top-root", SHIPPED_TOP)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_stdout_tampered_and_errors(self):
        r = self.run_("prove", "bob", "deadline")
        p = json.loads(r.stdout)
        p["node"]["content"] = "Monday"
        f = os.path.join(tmpdir(self), "bad.json")
        write_json(f, p)
        r = self.run_("check-proof", f)
        self.assertEqual(r.returncode, 1)
        self.assertTrue(r.stdout.startswith("INVALID"))
        self.assertEqual(self.run_("check-proof", "/nonexistent.json").returncode, 1)
        self.assertEqual(self.run_("prove", "alice", "nope").returncode, 1)

    def test_demo_world_with_base(self):
        w = demo_world(self)
        f = os.path.join(tmpdir(self), "p.json")
        self.assertEqual(self.run_("--base", w["base"], "prove", "bob", "changelog", "-o", f).returncode, 0)
        self.assertEqual(self.run_("--base", w["base"], "check-proof", f).returncode, 0)
        self.assertEqual(self.run_("check-proof", f).returncode, 1)      # repo's signers: other keys
        self.assertEqual(self.run_("check-proof", f, "--signers",
                                   os.path.join(w["base"], "allowed_signers")).returncode, 0)


if __name__ == "__main__":
    unittest.main()
