import json
import os
import unittest

from tests.worlds import REPO, SHIPPED_ROOTS, SHIPPED_TOP, shipped_copy
from mapsynclib.files import read_json
from mapsynclib.hashing import head, leaf, map_root, merkle, sha
from mapsynclib.index import build_index
from mapsynclib.world import load, map_path, save

NODE = {"id": "n", "label": "L", "sumo": "Text", "content": "c", "salt": "s"}


class Leaf(unittest.TestCase):
    def test_deterministic_and_key_order_free(self):
        rev = dict(reversed(list(NODE.items())))
        self.assertEqual(leaf(NODE), leaf(dict(NODE)))
        self.assertEqual(leaf(NODE), leaf(rev))
        self.assertEqual(len(leaf(NODE)), 64)

    def test_every_signed_field_changes_the_leaf(self):
        base = leaf(NODE)
        seen = {base}
        for k in ("id", "label", "sumo", "content", "salt"):
            h = leaf({**NODE, k: NODE[k] + "x"})
            self.assertNotIn(h, seen, k)
            seen.add(h)
        for k, v in (("pubkey", "ssh-ed25519 AAAA"), ("by", "cody"), ("same_as", ["bob:x"])):
            h = leaf({**NODE, k: v})
            self.assertNotIn(h, seen, k)
            seen.add(h)

    def test_unknown_fields_are_not_hashed(self):
        self.assertEqual(leaf(NODE), leaf({**NODE, "note": "unsigned extra"}))

    def test_leaf_prefix_is_0x00(self):
        canon = json.dumps(NODE, sort_keys=True, separators=(",", ":"))
        self.assertEqual(leaf(NODE), sha(b"\x00" + canon.encode()))


class Merkle(unittest.TestCase):
    def test_shapes(self):
        a, b, c = sha(b"a"), sha(b"b"), sha(b"c")
        inner = lambda x, y: sha(b"\x01" + bytes.fromhex(x) + bytes.fromhex(y))
        self.assertEqual(merkle([]), sha(b""))
        self.assertEqual(merkle([a]), a)
        self.assertEqual(merkle([a, b]), inner(a, b))
        self.assertEqual(merkle([a, b, c]), inner(inner(a, b), inner(c, c)))  # odd: last duplicated
        self.assertNotEqual(merkle([a, b]), merkle([b, a]))


class MapRoot(unittest.TestCase):
    def test_shipped_roots_are_known(self):
        for o, want in SHIPPED_ROOTS.items():
            self.assertEqual(map_root(map_path(REPO, o), REPO), want, o)
        self.assertEqual(build_index(REPO)["top_root"], SHIPPED_TOP)
        self.assertEqual(read_json(os.path.join(REPO, "index.json"))["top_root"], SHIPPED_TOP)

    def test_node_order_does_not_matter(self):
        d = shipped_copy(self)
        m = load(d, "bob")
        m["nodes"].reverse()
        save(d, "bob", m)
        self.assertEqual(map_root(map_path(d, "bob"), d), SHIPPED_ROOTS["bob"])

    def test_owner_is_in_the_head(self):
        self.assertNotEqual(head("alice", "0" * 64), head("bob", "0" * 64))

    def test_term_outside_pinned_list_raises(self):
        d = shipped_copy(self)
        m = load(d, "alice")
        m["nodes"][0]["sumo"] = "Unicorn"
        save(d, "alice", m)
        with self.assertRaises(ValueError):
            map_root(map_path(d, "alice"), d)


if __name__ == "__main__":
    unittest.main()
