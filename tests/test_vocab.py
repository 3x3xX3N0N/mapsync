import os
import shutil
import subprocess
import sys
import unittest

from tests.worlds import REPO, SHIPPED_ROOTS, SHIPPED_TOP, quietly, shipped_copy, tmpdir
from mapsynclib.demo import make_world
from mapsynclib.files import append_text, read_bytes, read_json, write_bytes
from mapsynclib.hashing import head, map_root, map_root_of
from mapsynclib.index import build_index, verify, write_index
from mapsynclib.proofs import check_proof, prove
from mapsynclib.suggest import LEXICON
from mapsynclib.vocab import (DISJOINT, HIERARCHY, LOCAL, TERMS, VOCAB_FILES, VocabError, concepts_report,
                              concepts_tree, load_terms, load_vocab, parse_vocab, vocab_report)
from mapsynclib.world import load, map_path

CLI = os.path.join(REPO, "mapsync.py")
TERMS_TEXT = read_bytes(os.path.join(REPO, TERMS)).decode()


def V(hierarchy="", local="", disjoint=""):
    return parse_vocab(TERMS_TEXT, {HIERARCHY: hierarchy.encode(), LOCAL: local.encode(),
                                    DISJOINT: disjoint.encode()})


class Loading(unittest.TestCase):
    def test_shipped_vocabulary_loads(self):
        v = load_vocab(REPO)
        self.assertTrue(v.present)
        self.assertIn("CodingAgent", v.local)
        self.assertEqual(v.parents["Planning"], ["IntentionalProcess"])
        self.assertEqual(v.ancestors("Requesting"),
                         ["Directing", "LinguisticCommunication", "Communication", "IntentionalProcess", "Process"])
        ok, lines = vocab_report(REPO)
        self.assertTrue(ok, lines)
        self.assertIn(v.sha, lines[1])

    def test_comments_blank_lines_and_forward_parent(self):
        v = V(local="# c\n\nB A   # B under a later-declared A\nA ComputerProgram\n")
        self.assertEqual(v.ancestors("B"), ["A", "ComputerProgram"])

    def test_cycle_rejected(self):
        with self.assertRaisesRegex(VocabError, "cycle"):
            V(hierarchy="IntentionalProcess Process\nProcess IntentionalProcess\n")
        with self.assertRaisesRegex(VocabError, "cycle"):
            V(local="A B\nB C\nC A\n")
        with self.assertRaisesRegex(VocabError, "cycle"):
            V(hierarchy="Process Process\n")

    def test_unknown_parent_rejected(self):
        with self.assertRaisesRegex(VocabError, "unknown parent 'Gizmo'"):
            V(local="Gadget Gizmo\n")
        with self.assertRaisesRegex(VocabError, "not a base term"):
            V(hierarchy="Planning Thinking\n")       # hierarchy.txt: base terms only
        with self.assertRaisesRegex(VocabError, "unknown term"):
            V(disjoint="Agent Unicorn\n")

    def test_duplicates_and_redefinition_rejected(self):
        with self.assertRaisesRegex(VocabError, "duplicate"):
            V(local="A Text\nA Process\n")
        with self.assertRaisesRegex(VocabError, "duplicate edge"):
            V(hierarchy="Planning IntentionalProcess\nPlanning IntentionalProcess\n")
        with self.assertRaisesRegex(VocabError, "duplicate pair"):
            V(disjoint="Agent Process\nProcess Agent\n")
        with self.assertRaisesRegex(VocabError, "may not redefine"):
            V(local="Text Proposition\n")

    def test_malformed_and_inconsistent_rejected(self):
        with self.assertRaisesRegex(VocabError, "two term names"):
            V(local="A B C\n")
        with self.assertRaisesRegex(VocabError, "itself"):
            V(disjoint="Agent Agent\n")
        with self.assertRaisesRegex(VocabError, "inconsistent"):
            V(local="Robot Agent\nX Robot\n", hierarchy="Agent Proposition\n",
              disjoint="Agent Proposition\n")
        with self.assertRaisesRegex(VocabError, "inconsistent"):
            V(local="Both Agent\n", disjoint="Both Agent\n")   # a subclass disjoint from its parent

    def test_no_files_means_not_present(self):
        v = parse_vocab(TERMS_TEXT, {})
        self.assertFalse(v.present)
        self.assertEqual(v.ancestors("Planning"), [])

    def test_sha_covers_every_file_and_framing(self):
        a = V(local="A Text\n")
        self.assertNotEqual(a.sha, V(local="A Text\n", disjoint="# x\n").sha)
        self.assertNotEqual(V(hierarchy="# x\n").sha, V(local="# x\n").sha)   # same bytes, other file


class Queries(unittest.TestCase):
    v = V(hierarchy="IntentionalProcess Process\nPlanning IntentionalProcess\nComputerProgram Proposition\n",
          local="CodingAgent ComputerProgram\nRoutingAgent ComputerProgram\nPairCoder CodingAgent\n",
          disjoint="Process Proposition\nCodingAgent RoutingAgent\n")

    def test_is_a_inherits(self):
        v = self.v
        self.assertTrue(v.is_a("PairCoder", "PairCoder"))
        self.assertTrue(v.is_a("PairCoder", "CodingAgent"))
        self.assertTrue(v.is_a("PairCoder", "Proposition"))
        self.assertFalse(v.is_a("CodingAgent", "PairCoder"))
        self.assertFalse(v.is_a("CodingAgent", "RoutingAgent"))
        self.assertFalse(v.is_a("Planning", "Proposition"))
        with self.assertRaises(KeyError):
            v.is_a("Unicorn", "Agent")

    def test_disjoint_inherits(self):
        v = self.v
        self.assertTrue(v.disjoint("Process", "Proposition"))
        self.assertTrue(v.disjoint("Proposition", "Process"))     # symmetric
        self.assertTrue(v.disjoint("Planning", "PairCoder"))      # both sides inherited
        self.assertTrue(v.disjoint("PairCoder", "RoutingAgent"))  # local axiom inherited
        self.assertFalse(v.disjoint("PairCoder", "ComputerProgram"))
        self.assertFalse(v.disjoint("Agent", "Process"))          # not declared here

    def test_module_functions_on_repo(self):
        from mapsynclib import vocab
        self.assertTrue(vocab.is_a("CodingAgent", "ComputerProgram"))
        self.assertTrue(vocab.disjoint("Human", "Planning"))
        self.assertIn("Agent", vocab.ancestors("Organization"))


class Pinning(unittest.TestCase):
    def test_shipped_roots_unchanged(self):
        for o in ("alice", "bob"):
            self.assertEqual(map_root(map_path(REPO, o), REPO), SHIPPED_ROOTS[o])
        idx = build_index(REPO)
        self.assertEqual({e["owner"]: e["root"] for e in idx["maps"]}, SHIPPED_ROOTS)
        self.assertEqual(idx["top_root"], SHIPPED_TOP)
        self.assertEqual(idx["vocab_sha"], load_vocab(REPO).sha)

    def test_base_term_maps_ignore_the_hierarchy(self):
        b = shipped_copy(self)
        shutil.rmtree(os.path.join(b, "maps", "carol"))     # the one map that uses local terms
        for f in VOCAB_FILES + (LEXICON,):   # an older world: no hierarchy, no lexicon
            os.remove(os.path.join(b, f))
        self.assertEqual(map_root(map_path(b, "alice"), b), SHIPPED_ROOTS["alice"])
        self.assertNotIn("vocab_sha", build_index(b))
        append_text(os.path.join(b, LOCAL), "Gadget ComputerProgram\n")
        self.assertEqual(map_root(map_path(b, "bob"), b), SHIPPED_ROOTS["bob"])

    def test_local_term_pins_vocab_sha(self):
        _, terms_sha = load_terms(REPO)
        m = load(REPO, "carol")
        v = load_vocab(REPO)
        from mapsynclib.hashing import merkle, leaf
        want = merkle([head("carol", terms_sha, v.sha)] + [leaf(n) for n in sorted(m["nodes"], key=lambda n: n["id"])])
        self.assertEqual(map_root_of(m, REPO), want)
        self.assertEqual(map_root_of(m, REPO), SHIPPED_ROOTS["carol"])
        self.assertNotEqual(head("carol", terms_sha, v.sha), head("carol", terms_sha))

    def test_editing_local_txt_reddens_map_using_it(self):
        b = shipped_copy(self)
        append_text(os.path.join(b, LOCAL), "TestingAgent ComputerProgram\n")
        self.assertEqual(map_root(map_path(b, "alice"), b), SHIPPED_ROOTS["alice"])
        self.assertNotEqual(map_root(map_path(b, "carol"), b), SHIPPED_ROOTS["carol"])
        write_index(b)                              # even with the index rebuilt...
        ok, out = quietly(verify, b)
        self.assertFalse(ok)
        self.assertIn("RED  carol: root", out)      # ...carol's signature no longer matches
        self.assertIn("ok   alice: root 656b6e9d", out)
        self.assertIn("ok   bob: root 2ea2aa8c", out)

    def test_comment_edit_counts_too(self):
        b = shipped_copy(self)
        append_text(os.path.join(b, DISJOINT), "# harmless?\n")
        self.assertNotEqual(map_root(map_path(b, "carol"), b), SHIPPED_ROOTS["carol"])

    def test_invalid_vocab_reddens_verify(self):
        for f, line in ((HIERARCHY, "IntentionalProcess Planning\n"), (LOCAL, "Gadget Gizmo\n"),
                        (LOCAL, "Text Proposition\n"), (HIERARCHY, "Text Proposition\n")):
            b = shipped_copy(self)
            append_text(os.path.join(b, f), line)
            ok, out = quietly(verify, b)
            self.assertFalse(ok, line)
            self.assertIn("RED", out)

    def test_unknown_tag_still_red(self):
        m = load(REPO, "carol")
        m["nodes"][0]["sumo"] = "Unicorn"
        with self.assertRaisesRegex(ValueError, "nor a local term"):
            map_root_of(m, REPO)


class SyncAndLog(unittest.TestCase):
    def test_sync_check_names_the_hierarchy(self):
        from mapsynclib.sync import sync_report
        b = shipped_copy(self)
        append_text(os.path.join(b, DISJOINT), "# edited\n")
        write_index(b)
        same, lines = sync_report(REPO, b)
        self.assertFalse(same)
        self.assertTrue(any(ln.startswith("! vocabulary hierarchy differs") for ln in lines), lines)
        self.assertTrue(any(ln.startswith("~ carol  root 18aabd5eb9a6c7d1… vs ") for ln in lines), lines)
        self.assertFalse(any(ln.startswith("~ alice") or ln.startswith("~ bob") for ln in lines))

    def test_log_head_records_vocab_sha(self):
        from mapsynclib.log import load_log, log_path
        _, entries = load_log(log_path(REPO))
        self.assertNotIn("vocab_sha", entries[0])            # seq 0 predates the hierarchy
        self.assertEqual(entries[-1]["vocab_sha"], read_json(os.path.join(REPO, "index.json"))["vocab_sha"])


class DemoWorld(unittest.TestCase):
    def test_local_terms_demo_green_and_pinned(self):
        d = os.path.join(tmpdir(self), "w")
        w = make_world(d, local_terms=True)
        ok, out = quietly(verify, d)
        self.assertTrue(ok, out)
        tags = {n["id"]: n["sumo"] for n in load(d, "alice")["nodes"]}
        self.assertEqual((tags["cody"], tags["coordinator"]), ("CodingAgent", "RoutingAgent"))
        self.assertEqual({n["id"]: n["sumo"] for n in load(d, "bob")["nodes"]}["cody"], "CodingAgent")
        append_text(os.path.join(d, LOCAL), "TestingAgent ComputerProgram\n")
        write_index(d)
        ok, out = quietly(verify, d)
        self.assertFalse(ok)
        self.assertIn("RED  alice: root", out)
        self.assertIn("RED  bob: root", out)
        self.assertTrue(w["top_root"])

    def test_base_terms_demo_unaffected_by_local_edit(self):
        d = os.path.join(tmpdir(self), "w")
        make_world(d)
        append_text(os.path.join(d, LOCAL), "TestingAgent ComputerProgram\n")
        write_index(d)
        ok, out = quietly(verify, d)
        self.assertTrue(ok, out)


class Proofs(unittest.TestCase):
    signers = os.path.join(REPO, "allowed_signers")

    def test_local_term_node_proves(self):
        p = prove(REPO, "carol", "builder")
        self.assertEqual(p["map"]["head"]["vocab_sha"], load_vocab(REPO).sha)
        ok, why = check_proof(p, self.signers, SHIPPED_TOP)
        self.assertTrue(ok, why)
        self.assertIn("CodingAgent", why)

    def test_base_term_node_in_vocab_world_proves(self):
        p = prove(REPO, "alice", "review")
        self.assertNotIn("vocab_sha", p["map"]["head"])
        self.assertTrue(check_proof(p, self.signers, SHIPPED_TOP)[0])

    def test_tampering_vocab_in_proof_red(self):
        for sabotage in (lambda p: p["vocab"].update({LOCAL: p["vocab"][LOCAL] + "X ComputerProgram\n"}),
                         lambda p: p.pop("vocab"),
                         lambda p: p["map"]["head"].pop("vocab_sha"),
                         lambda p: p["index"].pop("vocab_path"),
                         lambda p: p["vocab"].update({HIERARCHY: "Process Process\n"})):
            p = prove(REPO, "carol", "builder")
            sabotage(p)
            self.assertFalse(check_proof(p, self.signers)[0])
        p = prove(REPO, "alice", "review")
        p["vocab"][DISJOINT] += "Agent Text\n"
        self.assertFalse(check_proof(p, self.signers)[0])

    def test_proof_from_world_without_vocab_files(self):
        b = shipped_copy(self)
        shutil.rmtree(os.path.join(b, "maps", "carol"))
        for f in VOCAB_FILES + (LEXICON,):   # an older world: no hierarchy, no lexicon
            os.remove(os.path.join(b, f))
        write_index(b)
        p = prove(b, "alice", "review")
        self.assertNotIn("vocab", p)
        self.assertTrue(check_proof(p, os.path.join(b, "allowed_signers"))[0])
        p["vocab"] = {LOCAL: ""}                     # a fake vocab can't be slotted in
        self.assertFalse(check_proof(p, os.path.join(b, "allowed_signers"))[0])


class Concepts(unittest.TestCase):
    def test_tree_groups_local_under_base(self):
        lines = concepts_tree(REPO)
        i = next(k for k, ln in enumerate(lines) if ln.strip().startswith("ComputerProgram "))
        cp_indent = len(lines[i]) - len(lines[i].lstrip())
        under = []
        for ln in lines[i + 1:]:
            if len(ln) - len(ln.lstrip()) <= cp_indent:
                break
            under.append(ln.split()[0])
        self.assertEqual(under, ["CodingAgent*", "RoutingAgent*"])
        self.assertIn("carol:'Builder'", next(ln for ln in lines if "CodingAgent*" in ln))
        self.assertIn("carol:'Switchboard'", next(ln for ln in lines if "RoutingAgent*" in ln))
        self.assertIn("[6 in all]", lines[i])                    # rolls up to ComputerProgram
        self.assertTrue(lines[i - 1].startswith("Proposition"))

    def test_demo_codys_separate_from_routers(self):
        d = os.path.join(tmpdir(self), "w")
        make_world(d, local_terms=True)
        rows = [" ".join(ln.split()) for ln in concepts_tree(d)]   # whitespace-insensitive
        i = rows.index("ComputerProgram - [4 in all]")
        self.assertEqual(rows[i + 1:i + 3], ["CodingAgent* alice:'Cody', bob:'Cody'",
                                             "RoutingAgent* alice:'Psyche', bob:'the router'"])
        self.assertEqual(rows[i - 1], "Proposition - [4 in all]")

    def test_flat_is_the_old_output(self):
        r = subprocess.run([sys.executable, CLI, "concepts", "--flat"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.splitlines(), concepts_report(REPO))
        self.assertIn("ComputerProgram      alice:'Psyche', alice:'Cody', bob:'Cody', bob:'the router'",
                      r.stdout)
        self.assertIn("CodingAgent          carol:'Builder'", r.stdout)

    def test_cli_vocab(self):
        r = subprocess.run([sys.executable, CLI, "vocab", "CodingAgent"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("is a:          ComputerProgram -> Proposition", r.stdout)
        b = shipped_copy(self)
        append_text(os.path.join(b, HIERARCHY), "IntentionalProcess Planning\n")
        r = subprocess.run([sys.executable, CLI, "--base", b, "vocab"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("cycle", r.stdout)


if __name__ == "__main__":
    unittest.main()
