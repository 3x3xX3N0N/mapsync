import os
import unittest

from tests.worlds import REPO, demo_world, shipped_copy
from mapsynclib.identity import identity_checks, name_pairs, names_report
from mapsynclib.index import verify
from mapsynclib.signing import agent_sig_ok, agent_sign
from mapsynclib.world import load, map_path, save


def set_same_as(d, owner, node, targets):
    m = load(d, owner)
    n = next(x for x in m["nodes"] if x["id"] == node)
    n["same_as"] = targets
    save(d, owner, m)


class Names(unittest.TestCase):
    def test_two_codys_collide(self):
        pairs = name_pairs(REPO)
        self.assertIn(("cody", "alice:cody", "bob:cody", "COLLISION"), pairs)
        line = next(l for l in names_report(REPO) if l.startswith("'cody'"))
        self.assertIn("COLLISION", line)
        self.assertEqual(line.count("[key "), 2)

    def test_mutual_same_as_is_linked_one_side_is_claimed(self):
        d = shipped_copy(self)
        set_same_as(d, "alice", "cody", ["bob:cody"])
        self.assertIn(("cody", "alice:cody", "bob:cody", "CLAIMED"), name_pairs(d))
        set_same_as(d, "bob", "cody", ["alice:cody"])
        self.assertIn(("cody", "alice:cody", "bob:cody", "LINKED"), name_pairs(d))

    def test_cross_label_links(self):
        out = names_report(REPO)
        self.assertIn("   alice:notes -> bob:changelog  CLAIMED (one side only)", out)
        self.assertIn("   alice:review -> bob:prcheck  LINKED", out)

    def test_same_label_same_owner_is_not_a_collision(self):
        d = shipped_copy(self)
        m = load(d, "bob")
        m["nodes"][1]["label"] = "Ship date"   # two "Ship date"s, both bob's
        save(d, "bob", m)
        self.assertFalse(any(p[0] == "ship date" for p in name_pairs(d)))


class AgentSigs(unittest.TestCase):
    def setUp(self):
        self.w = demo_world(self)
        self.d = self.w["base"]

    def agents(self, owner):
        return {n["id"]: n for n in load(self.d, owner)["nodes"] if "pubkey" in n}

    def node(self, owner, nid):
        return next(n for n in load(self.d, owner)["nodes"] if n["id"] == nid)

    def test_good_agent_sig(self):
        self.assertIsNone(agent_sig_ok(self.d, "alice", self.node("alice", "notes"), self.agents("alice")))

    def test_other_cody_cannot_sign_for_this_cody(self):
        # cross-key forgery: bob's Cody signs alice's node that alice's Cody is credited with
        agent_sign(map_path(self.d, "alice"), "notes", self.w["agents"]["bob:cody"], quiet=True)
        why = agent_sig_ok(self.d, "alice", self.node("alice", "notes"), self.agents("alice"))
        self.assertIn("not by alice:cody", why)
        self.assertFalse(verify(self.d, quiet=True))

    def test_missing_sig_and_non_agent_author(self):
        os.remove(os.path.join(self.d, "maps", "bob", "agent_sigs", "changelog.sig"))
        self.assertEqual(agent_sig_ok(self.d, "bob", self.node("bob", "changelog"), self.agents("bob")),
                         "no agent signature")
        n = {**self.node("bob", "changelog"), "by": "orchestrator"}
        self.assertIn("not an agent node", agent_sig_ok(self.d, "bob", n, self.agents("bob")))

    def test_dangling_same_as_is_red(self):
        lines = []
        self.assertTrue(identity_checks(self.d, lines.append))
        set_same_as(self.d, "bob", "deadline", ["alice:ghost"])
        lines = []
        self.assertFalse(identity_checks(self.d, lines.append))
        self.assertTrue(any("alice:ghost: no such node" in l for l in lines))


if __name__ == "__main__":
    unittest.main()
