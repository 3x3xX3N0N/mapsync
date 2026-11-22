"""[C7] claims: same_as clusters side by side, attributed; contradictions reported, not merged."""
import json
import os
import subprocess
import sys
import unittest

from tests.worlds import REPO, demo_world, quietly, shipped_copy
from mapsynclib.claims import AGREE, CONTRADICTION, DIFFERENT, REFINES, compare, gather
from mapsynclib.demo import resign
from mapsynclib.files import read_json
from mapsynclib.index import verify
from mapsynclib.vocab import load_vocab
from mapsynclib.world import load, save

CLI = os.path.join(REPO, "mapsync.py")


def run(*args):
    return subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, cwd="/")


def retag(base, owner, node, term, **extra):
    m = load(base, owner)
    n = next(x for x in m["nodes"] if x["id"] == node)
    n["sumo"] = term
    n.update(extra)
    save(base, owner, m)


def cluster_of(data, ref):
    return next(c for c in data["clusters"] if ref in [m["ref"] for m in c["members"]])


class Shipped(unittest.TestCase):
    def test_shipped_clusters(self):
        data = gather(REPO)
        self.assertEqual([[m["ref"] for m in c["members"]] for c in data["clusters"]],
                         [["alice:notes", "bob:changelog"], ["alice:review", "bob:prcheck"]])
        review = cluster_of(data, "alice:review")["pairs"]
        self.assertEqual([(p["link"], p["verdict"]) for p in review], [("LINKED", AGREE)])
        notes = cluster_of(data, "alice:notes")["pairs"]
        self.assertEqual([(p["link"], p["verdict"]) for p in notes], [("CLAIMED", AGREE)])
        self.assertEqual(data["counts"][CONTRADICTION], 0)

    def test_attribution(self):
        c = cluster_of(gather(REPO), "alice:review")
        a, b = c["members"]
        self.assertEqual(a["author"]["by"], "alice:cody")
        self.assertTrue(a["author"]["lineage"].startswith("key "))
        self.assertEqual(b["author"]["text"], "owner bob")
        idx = read_json(os.path.join(REPO, "index.json"))
        roots = {e["owner"]: e["root"] for e in idx["maps"]}
        self.assertEqual((a["root"], b["root"]), (roots["alice"], roots["bob"]))
        self.assertTrue(a["signed"] and b["signed"])
        self.assertEqual(a["content"], "Check a change is ready for review")

    def test_cli_text_json_redact(self):
        r = run("claims")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("alice:review ~ bob:prcheck  LINKED: AGREE", r.stdout)
        self.assertIn("alice:notes ~ bob:changelog  CLAIMED: AGREE", r.stdout)
        self.assertIn("by agent alice:cody [key ", r.stdout)
        self.assertIn("Check a change is ready for review", r.stdout)
        r = run("claims", "--redact")
        self.assertNotIn("Check a change is ready for review", r.stdout)
        self.assertIn("<hidden>", r.stdout)
        r = run("claims", "--json", "--redact")
        data = json.loads(r.stdout)
        self.assertTrue(all(m["content"] == "<hidden>" for c in data["clusters"] for m in c["members"]))
        self.assertEqual(run("claims", "--strict").returncode, 0)


class Verdicts(unittest.TestCase):
    def test_compare(self):
        v = load_vocab(REPO)
        self.assertEqual(compare(v, "Text", "Text")[0], AGREE)
        self.assertEqual(compare(v, "CodingAgent", "ComputerProgram")[0], REFINES)
        self.assertEqual(compare(v, "Proposition", "CodingAgent")[0], REFINES)
        self.assertEqual(compare(v, "Human", "ComputerProgram")[0], CONTRADICTION)
        self.assertEqual(compare(v, "Text", "Process")[0], CONTRADICTION)
        self.assertEqual(compare(v, "Human", "Organization")[0], DIFFERENT)
        self.assertEqual(compare(v, "Event", "Process")[0], DIFFERENT)
        self.assertEqual(compare(v, "Unicorn", "Text")[0], DIFFERENT)
        self.assertIn("Agent / Proposition", compare(v, "Human", "ComputerProgram")[1])


class Contradiction(unittest.TestCase):
    def world(self):
        """Signed demo world where linked alice:review / bob:prcheck are Human / ComputerProgram."""
        w = demo_world(self)
        b = w["base"]
        retag(b, "alice", "review", "Human")
        retag(b, "bob", "prcheck", "ComputerProgram")
        resign(w, "alice")
        resign(w, "bob")
        return w

    def test_contradiction_reported_verify_green(self):
        w = self.world()
        b = w["base"]
        self.assertTrue(quietly(verify, b)[0])                 # a contradiction is not a verify failure
        p = cluster_of(gather(b), "alice:review")["pairs"][0]
        self.assertEqual((p["link"], p["verdict"]), ("LINKED", CONTRADICTION))
        r = run("--base", b, "claims")
        self.assertEqual(r.returncode, 0)
        self.assertIn("LINKED: CONTRADICTION", r.stdout)
        self.assertIn("never merged", r.stdout)
        r = run("--base", b, "claims", "--strict")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(run("--base", b, "verify").returncode, 0)
        # both claims are still there, unchanged: nothing was merged
        self.assertEqual(next(n for n in load(b, "alice")["nodes"] if n["id"] == "review")["sumo"], "Human")
        self.assertEqual(next(n for n in load(b, "bob")["nodes"] if n["id"] == "prcheck")["sumo"], "ComputerProgram")

    def test_refines_and_different_kind(self):
        w = demo_world(self)
        b = w["base"]
        retag(b, "alice", "notes", "Proposition")
        retag(b, "bob", "changelog", "Text")
        self.assertEqual(cluster_of(gather(b), "alice:notes")["pairs"][0]["verdict"], CONTRADICTION)
        retag(b, "bob", "changelog", "CodingAgent")
        self.assertEqual(cluster_of(gather(b), "alice:notes")["pairs"][0]["verdict"], REFINES)
        retag(b, "bob", "changelog", "Event")
        self.assertEqual(cluster_of(gather(b), "alice:notes")["pairs"][0]["verdict"], DIFFERENT)

    def test_transitive_cluster(self):
        b = shipped_copy(self)
        retag(b, "carol", "ask", "Requesting", same_as=["bob:prcheck"])  # carol claims bob's PR check
        c = cluster_of(gather(b), "carol:ask")
        self.assertEqual([m["ref"] for m in c["members"]], ["alice:review", "bob:prcheck", "carol:ask"])
        got = {(p["a"], p["b"]): (p["link"], p["verdict"]) for p in c["pairs"]}
        self.assertEqual(got[("alice:review", "carol:ask")], ("via cluster", REFINES))
        self.assertEqual(got[("bob:prcheck", "carol:ask")], ("CLAIMED", REFINES))
        self.assertEqual(got[("alice:review", "bob:prcheck")], ("LINKED", AGREE))


if __name__ == "__main__":
    unittest.main()
