"""[C7] The offline tag suggester: pinned lexicon, deterministic ranking, `suggest`, `tag`."""
import os
import subprocess
import sys
import unittest

from tests.worlds import REPO, SHIPPED_TOP, SHIPPED_TOP_V1, demo_world, quietly, shipped_copy
from mapsynclib.demo import resign
from mapsynclib.files import append_text, read_bytes
from mapsynclib.hashing import sha
from mapsynclib.index import build_index, verify, write_index
from mapsynclib.suggest import (LEXICON, Lexicon, LexiconError, load_lexicon, stem, suggest_map,
                                suggest_text, tag, words)
from mapsynclib.vocab import load_terms, load_vocab
from mapsynclib.world import load

CLI = os.path.join(REPO, "mapsync.py")


def run(*args):
    return subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, cwd="/")


def top(text, base=REPO):
    return load_lexicon(base).score(text)[0][0]


class Suggestions(unittest.TestCase):
    def test_release_note_and_changelog_are_text(self):
        self.assertEqual(top("Release note"), "Text")
        self.assertEqual(top("Changelog"), "Text")

    def test_ship_date_is_time_interval(self):
        self.assertEqual(top("Ship date"), "TimeInterval")

    def test_cody_coding_agent_is_a_program(self):
        t = top("Cody coding agent")
        self.assertTrue(load_vocab(REPO).is_a(t, "ComputerProgram"), t)

    def test_ranking_is_deterministic_and_ties_go_deeper(self):
        v = load_vocab(REPO)
        lx = Lexicon(b"thing Agent\nthing Human\nthing Text\n", v)
        self.assertEqual([t for t, _ in lx.score("thing")], ["Human", "Agent", "Text"])  # Human is_a Agent
        self.assertEqual(load_lexicon(REPO).score("the router hands tasks"),
                         load_lexicon(REPO).score("the router hands tasks"))

    def test_weights_add_up(self):
        lx = Lexicon(b"note Text 2\ndraft Text\ndate TimeInterval 2.5\n", load_vocab(REPO))
        self.assertEqual(lx.score("Draft note, due date"), [("Text", 3.0), ("TimeInterval", 2.5)])

    def test_stemming(self):
        for a, b in (("notes", "note"), ("planning", "plan"), ("shipped", "ship"), ("changes", "change"),
                     ("Releases", "release"), ("agents", "agent"), ("processes", "process")):
            self.assertEqual(stem(a), stem(b), (a, b))
        self.assertEqual(words("Notes, notes and NOTE"), [stem("note"), "and"])

    def test_no_hit(self):
        self.assertEqual(load_lexicon(REPO).score("zzz qqq"), [])
        self.assertIn("no suggestion", suggest_text(REPO, "zzz qqq")[0])

    def test_top5_with_ancestors(self):
        lines = suggest_text(REPO, "Cody coding agent")
        self.assertLessEqual(len(lines), 5)
        self.assertTrue(lines[0].startswith("CodingAgent"))
        self.assertIn("(ComputerProgram -> Proposition)", lines[0])


class Lexicon_(unittest.TestCase):
    def test_shipped_lexicon_covers_every_term(self):
        lx = load_lexicon(REPO)
        v = load_vocab(REPO)
        self.assertGreaterEqual(lx.count, 80)
        self.assertEqual(set(v.parents) - lx.terms(), set())   # every base and local term

    def test_pinned_under_top_root(self):
        idx = build_index(REPO)
        self.assertEqual(idx["lexicon_sha"], sha(read_bytes(os.path.join(REPO, LEXICON))))
        self.assertEqual(idx["top_root"], SHIPPED_TOP)
        log = read_bytes(os.path.join(REPO, "log", "roots.jsonl")).decode().splitlines()
        self.assertIn(idx["lexicon_sha"], log[-1])

    def test_edit_lexicon_is_red_until_republished(self):
        b = shipped_copy(self)
        append_text(os.path.join(b, LEXICON), "gizmo ComputerProgram\n")
        self.assertFalse(quietly(verify, b)[0])

    def test_invalid_lexicon(self):
        v = load_vocab(REPO)
        for raw, msg in ((b"gizmo Gadget\n", "not a base or local term"),
                         (b"gizmo\n", "expected"),
                         (b"gizmo Text x\n", "not a number"),
                         (b"gizmo Text 0\n", "positive"),
                         (b"note Text\nnotes Text\n", "duplicate")):
            with self.assertRaisesRegex(LexiconError, msg):
                Lexicon(raw, v)
        b = shipped_copy(self)
        append_text(os.path.join(b, LEXICON), "gizmo Gadget\n")
        ok, out = quietly(verify, b)
        self.assertFalse(ok)
        self.assertIn("Gadget", out)

    def test_world_without_lexicon_hashes_as_before(self):
        b = shipped_copy(self)
        os.remove(os.path.join(b, LEXICON))
        idx = build_index(b)
        self.assertNotIn("lexicon_sha", idx)
        self.assertEqual(idx["top_root"], SHIPPED_TOP_V1)      # = log seq 1, before the lexicon

    def test_map_roots_do_not_depend_on_lexicon(self):
        b = shipped_copy(self)
        append_text(os.path.join(b, LEXICON), "gizmo ComputerProgram\n")
        self.assertEqual([e["root"] for e in build_index(b)["maps"]],
                         [e["root"] for e in build_index(REPO)["maps"]])


class SuggestMap(unittest.TestCase):
    def test_shipped_maps_have_no_mismatch(self):
        for o in ("alice", "bob", "carol"):
            out = suggest_map(REPO, o)
            self.assertEqual(len(out), len(load(REPO, o)["nodes"]))
            self.assertFalse([x for x in out if "MISMATCH?" in x], out)

    def test_unrelated_tag_is_flagged(self):
        b = shipped_copy(self)
        m = load(b, "bob")
        next(n for n in m["nodes"] if n["id"] == "deadline")["sumo"] = "Human"
        from mapsynclib.world import save
        save(b, "bob", m)
        line = next(x for x in suggest_map(b, "bob") if x.startswith("bob:deadline"))
        self.assertIn("tag Human", line)
        self.assertIn("TimeInterval", line)
        self.assertIn("MISMATCH?", line)

    def test_cli(self):
        r = run("suggest", "Ship", "date")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("TimeInterval"))
        r = run("suggest", "--map", "alice")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("alice:notes", r.stdout)
        r = run("suggest", "--map", os.path.join(REPO, "maps", "bob", "map.json"))
        self.assertIn("bob:deadline", r.stdout)
        self.assertEqual(run("suggest").returncode, 2)


class Tag(unittest.TestCase):
    def test_without_yes_changes_nothing(self):
        w = demo_world(self)
        b = w["base"]
        before = read_bytes(os.path.join(b, "maps", "alice", "map.json"))
        out = tag(b, "alice", "notes", "Proposition")
        self.assertIn("would retag alice:notes", out[0])
        self.assertEqual(read_bytes(os.path.join(b, "maps", "alice", "map.json")), before)
        r = run("--base", b, "tag", "alice", "notes", "Proposition")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--yes", r.stdout)
        self.assertEqual(read_bytes(os.path.join(b, "maps", "alice", "map.json")), before)
        self.assertTrue(quietly(verify, b)[0])

    def test_with_yes_goes_red_until_resigned(self):
        w = demo_world(self)
        b = w["base"]
        r = run("--base", b, "tag", "alice", "notes", "Proposition", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(next(n for n in load(b, "alice")["nodes"] if n["id"] == "notes")["sumo"], "Proposition")
        self.assertIn("must re-sign", r.stdout)                # owner
        self.assertIn("agent alice:cody must re-sign", r.stdout)   # notes is by=cody
        self.assertFalse(quietly(verify, b)[0])                # never re-signs on its own
        write_index(b)
        self.assertFalse(quietly(verify, b)[0])                # a fresh index doesn't help: sigs are stale
        resign(w, "alice")                                     # agent + owner, ephemeral keys
        self.assertTrue(quietly(verify, b)[0])

    def test_owner_node_reminder_has_no_agent(self):
        w = demo_world(self)
        out = tag(w["base"], "bob", "deadline", "Event", yes=True)
        self.assertTrue(any("bob re-signs" in x for x in out), out)
        self.assertFalse(any("agent" in x for x in out), out)

    def test_bad_term_or_node(self):
        w = demo_world(self)
        with self.assertRaisesRegex(ValueError, "unknown term"):
            tag(w["base"], "alice", "notes", "Unicorn", yes=True)
        with self.assertRaises(KeyError):
            tag(w["base"], "alice", "nope", "Text", yes=True)
        r = run("--base", w["base"], "tag", "alice", "notes", "Unicorn", "--yes")
        self.assertEqual(r.returncode, 1)
        self.assertTrue(quietly(verify, w["base"])[0])

    def test_same_tag_is_a_no_op(self):
        w = demo_world(self)
        self.assertIn("already tagged", tag(w["base"], "alice", "notes", "Text", yes=True)[0])
        self.assertTrue(quietly(verify, w["base"])[0])

    def test_demo_world_carries_lexicon(self):
        w = demo_world(self)
        self.assertEqual(build_index(w["base"])["lexicon_sha"], build_index(REPO)["lexicon_sha"])
        _, terms_sha = load_terms(w["base"])
        self.assertEqual(terms_sha, build_index(REPO)["sumo_terms_sha"])


if __name__ == "__main__":
    unittest.main()
