import json
import os
import subprocess
import sys
import unittest

from tests.worlds import REPO, SHIPPED_ROOTS, SHIPPED_TOP, demo_world, quietly, shipped_copy
from mapsynclib import keys as K
from mapsynclib.demo import fresh_key
from mapsynclib.files import read_json
from mapsynclib.g1 import KEY_ROWS, run_row
from mapsynclib.hashing import map_root
from mapsynclib.identity import names_report
from mapsynclib.index import build_index, verify, write_index
from mapsynclib.log import append
from mapsynclib.proofs import check_proof, prove
from mapsynclib.signing import agent_sign, sign
from mapsynclib.world import load, map_path

CLI = os.path.join(REPO, "mapsync.py")


def run(*args):
    return subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, cwd="/")


def _verify(base, out):
    ok, text = quietly(verify, base)
    out.extend(text.splitlines())
    return ok


class KeyWorld(unittest.TestCase):
    def setUp(self):
        self.w = demo_world(self)
        self.d = self.w["base"]
        self.now = 1_700_000_000

    def key(self, name):
        return fresh_key(self.d, name)

    def tick(self):
        self.now += 60
        return self.now

    def green(self):
        out = []
        ok = _verify(self.d, out)
        self.assertTrue(ok, "\n".join(out))
        return out

    def red(self, why):
        out = []
        ok = _verify(self.d, out)
        self.assertFalse(ok, "\n".join(out))
        self.assertTrue(any(x.startswith("RED") and why in x for x in out), "\n".join(out))
        return out

    def rotate_cody(self):
        k2, pub = self.key("alice_cody2")
        K.rotate(self.d, "alice", "agent:cody", pub,
                 [self.w["owners"]["alice"], self.w["agents"]["alice:cody"]], now=self.tick())
        write_index(self.d)
        return k2, pub

    def rotate_owner(self, signers_extra=()):
        k2, pub = self.key("alice2")
        K.rotate(self.d, "alice", "owner", pub, [self.w["owners"]["alice"], k2, *signers_extra], now=self.tick())
        write_index(self.d)
        return k2, pub

    def recovery(self):
        kr, rpub = self.key("alice_rec")
        K.recovery(self.d, "alice", self.w["owners"]["alice"], rpub, now=self.tick())
        write_index(self.d)
        return kr, rpub


class AgentRotation(KeyWorld):
    def test_old_signatures_stay_green_and_lineage_id_is_stable(self):
        first = "key " + K.fp(self.w["pubkeys"]["alice:cody"])
        before = next(l for l in names_report(self.d) if l.startswith("'cody'"))
        self.assertIn(f"alice:cody [{first}]", before)
        k2, pub = self.rotate_cody()
        self.assertEqual(next(n for n in load(self.d, "alice")["nodes"] if n["id"] == "cody")["pubkey"], pub)
        out = self.green()                            # review/notes still signed by the retired key
        self.assertIn("ok   alice:notes written by agent alice:cody", out)
        line = next(l for l in names_report(self.d) if l.startswith("'cody'"))
        self.assertIn(f"alice:cody [{first}, rotated 1 time]", line)
        self.assertIn("COLLISION", line)                 # still distinct from bob's Cody
        self.assertNotIn(K.fp(pub), line)                # the new key is not a new identity
        agent_sign(map_path(self.d, "alice"), "notes", k2, quiet=True)   # new signatures green too
        write_index(self.d)
        self.green()
        k3, pub3 = self.key("alice_cody3")
        K.rotate(self.d, "alice", "agent:cody", pub3, [self.w["owners"]["alice"]], now=self.tick())
        write_index(self.d)
        self.green()
        self.assertIn(f"[{first}, rotated 2 times]", "\n".join(names_report(self.d)))

    def test_agent_rotation_needs_the_owner(self):
        k2, pub = self.key("alice_cody2")
        with self.assertRaisesRegex(K.KeyChainError, "not signed by the owner key"):
            K.rotate(self.d, "alice", "agent:cody", pub, [self.w["agents"]["alice:cody"], k2])
        self.assertFalse(os.path.exists(K.keys_path(self.d, "alice")))   # refused: nothing written
        with self.assertRaisesRegex(ValueError, "is none of"):
            K.rotate(self.d, "alice", "agent:cody", pub, [self.w["owners"]["bob"]])

    def test_map_pubkey_must_follow_the_chain(self):
        self.rotate_cody()
        m = load(self.d, "alice")
        next(n for n in m["nodes"] if n["id"] == "cody")["pubkey"] = self.w["pubkeys"]["alice:cody"]
        from mapsynclib.world import save
        save(self.d, "alice", m)
        sign(map_path(self.d, "alice"), self.w["owners"]["alice"], self.d, quiet=True)
        write_index(self.d)
        self.red("is not the lineage's current key")

    def test_other_cody_still_cannot_sign(self):
        self.rotate_cody()
        agent_sign(map_path(self.d, "alice"), "notes", self.w["agents"]["bob:cody"], quiet=True)
        write_index(self.d)
        self.red("not by any key in alice:cody's lineage")


class AgentRevocation(KeyWorld):
    def test_revoked_key_red_until_resigned(self):
        k2, pub = self.rotate_cody()
        K.revoke(self.d, "alice", "agent:cody", self.w["pubkeys"]["alice:cody"], "owner",
                 self.w["owners"]["alice"], now=self.tick())
        write_index(self.d)
        out = self.red("signed by REVOKED key")
        self.assertEqual(sum("REVOKED key" in x for x in out), 2, out)   # review and notes
        agent_sign(map_path(self.d, "alice"), "notes", k2, quiet=True)
        write_index(self.d)
        out = self.red("alice:review written by agent alice:cody: signed by REVOKED")
        self.assertIn("ok   alice:notes written by agent alice:cody", out)
        agent_sign(map_path(self.d, "alice"), "review", k2, quiet=True)
        write_index(self.d)
        self.green()

    def test_revoking_the_current_agent_key_is_red_until_rotated(self):
        K.revoke(self.d, "alice", "agent:cody", self.w["pubkeys"]["alice:cody"], "owner",
                 self.w["owners"]["alice"], now=self.tick())
        write_index(self.d)
        self.red("its current key")
        k2, pub = self.key("alice_cody2")
        K.rotate(self.d, "alice", "agent:cody", pub, [self.w["owners"]["alice"]], now=self.tick())
        for n in ("review", "notes"):
            agent_sign(map_path(self.d, "alice"), n, k2, quiet=True)
        write_index(self.d)
        self.green()

    def test_revoke_needs_owner_or_recovery(self):
        with self.assertRaisesRegex(K.KeyChainError, "does not verify"):
            K.revoke(self.d, "alice", "agent:cody", self.w["pubkeys"]["alice:cody"], "owner",
                     self.w["owners"]["bob"])
        with self.assertRaisesRegex(K.KeyChainError, "no recovery key"):
            K.revoke(self.d, "alice", "agent:cody", self.w["pubkeys"]["alice:cody"], "recovery",
                     self.w["owners"]["alice"])


class OwnerRotation(KeyWorld):
    def test_rotation_signed_by_old_and_new_green(self):
        k2, pub = self.rotate_owner()
        self.assertEqual(K.allowed_key(self.d, "alice"), pub)
        out = self.green()
        self.assertTrue(any("alice: keys.jsonl: 1 events" in x and "rotated 1 time" in x for x in out), out)
        st = K.state(self.d, "alice")
        self.assertEqual(st.owner.id, "key " + K.fp(self.w["pubkeys"]["alice"]))
        self.assertEqual(st.owner.status[self.w["pubkeys"]["alice"]], "rotated")
        # the old owner key can no longer sign the map
        sign(map_path(self.d, "alice"), self.w["owners"]["alice"], self.d, quiet=True)
        write_index(self.d)
        self.red("signature INVALID")

    def test_rotation_signed_only_by_the_new_key_red(self):
        k2, pub = self.key("alice2")
        with self.assertRaisesRegex(K.KeyChainError, "rotation not signed by the old key"):
            K.rotate(self.d, "alice", "owner", pub, [k2])
        lines = []
        e = K.event(lines, "rotate", "owner", self.w["pubkeys"]["alice"], pub, "x", {"new": k2}, now=self.now)
        K.write_lines(self.d, "alice", [K.canonical(e)])
        K.set_allowed_key(self.d, "alice", pub)
        sign(map_path(self.d, "alice"), k2, self.d, quiet=True)
        write_index(self.d)
        self.red("rotation not signed by the old key")

    def test_rotation_signed_only_by_the_old_key_red(self):
        k2, pub = self.key("alice2")
        e = K.event([], "rotate", "owner", self.w["pubkeys"]["alice"], pub, "x",
                    {"old": self.w["owners"]["alice"]}, now=self.now)
        K.write_lines(self.d, "alice", [K.canonical(e)])
        K.set_allowed_key(self.d, "alice", pub)
        write_index(self.d)
        self.red("rotation not signed by the new key")

    def test_allowed_signers_disagreeing_with_chain_head_red(self):
        self.rotate_owner()
        K.set_allowed_key(self.d, "alice", self.w["pubkeys"]["alice"])
        sign(map_path(self.d, "alice"), self.w["owners"]["alice"], self.d, quiet=True)
        write_index(self.d)
        self.red("allowed_signers has key")

    def test_key_reuse_refused(self):
        self.rotate_owner()
        with self.assertRaisesRegex(K.KeyChainError, "used before"):
            K.rotate(self.d, "alice", "owner", self.w["pubkeys"]["alice"],
                     [os.path.join(self.d, "keys", "alice2"), self.w["owners"]["alice"]])


class Recovery(KeyWorld):
    def test_lost_owner_key_recovered(self):
        kr, rpub = self.recovery()
        self.green()
        # the owner key is stolen: recovery revokes it, then recovery + new key rotate
        K.revoke(self.d, "alice", "owner", self.w["pubkeys"]["alice"], "recovery", kr, now=self.tick())
        write_index(self.d)
        self.red("is REVOKED")
        k2, pub = self.key("alice2")
        with self.assertRaisesRegex(K.KeyChainError, "needs the recovery key"):
            K.rotate(self.d, "alice", "owner", pub, [self.w["owners"]["alice"], k2])   # the thief tries
        K.rotate(self.d, "alice", "owner", pub, [kr, k2], now=self.tick())
        write_index(self.d)
        self.green()
        st = K.state(self.d, "alice")
        self.assertEqual(st.owner.current, pub)
        self.assertEqual(st.owner.id, "key " + K.fp(self.w["pubkeys"]["alice"]))   # same lineage
        self.assertEqual([e["type"] for e in st.events], ["recovery", "revoke", "rotate"])

    def test_revoked_owner_key_cannot_sign_events(self):
        kr, _ = self.recovery()
        K.revoke(self.d, "alice", "owner", self.w["pubkeys"]["alice"], "recovery", kr, now=self.tick())
        k2, pub = self.key("alice_cody2")
        with self.assertRaisesRegex(K.KeyChainError, "REVOKED"):
            K.rotate(self.d, "alice", "agent:cody", pub, [self.w["owners"]["alice"]])

    def test_thief_with_owner_key_cannot_replace_recovery(self):
        kr, _ = self.recovery()
        km, mpub = self.key("mallory_rec")
        with self.assertRaisesRegex(K.KeyChainError, "old recovery key"):
            K.recovery(self.d, "alice", self.w["owners"]["alice"], mpub)
        kr2, r2 = self.key("alice_rec2")
        K.recovery(self.d, "alice", self.w["owners"]["alice"], r2, old_recovery_key=kr, now=self.tick())
        self.assertEqual(K.state(self.d, "alice").recovery, r2)

    def test_recovery_beats_a_thief_who_rotated_first(self):
        kr, _ = self.recovery()
        kt, tpub = self.key("thief")
        K.rotate(self.d, "alice", "owner", tpub, [self.w["owners"]["alice"], kt], now=self.tick())
        K.revoke(self.d, "alice", "owner", tpub, "recovery", kr, now=self.tick())
        k2, pub = self.key("alice2")
        K.rotate(self.d, "alice", "owner", pub, [kr, k2], now=self.tick())
        write_index(self.d)
        self.green()


class ChainTampering(KeyWorld):
    def setUp(self):
        super().setUp()
        self.rotate_cody()
        self.recovery()
        self.green()
        self.p = K.keys_path(self.d, "alice")

    def rewrite(self, fn):
        K.write_lines(self.d, "alice", fn(K.read_lines(self.p)))
        write_index(self.d)

    def test_forged_line_red(self):
        def forge(ls):
            e = json.loads(ls[1])
            e["reason"] = "edited"
            return [ls[0], K.canonical(e)]
        self.rewrite(forge)
        self.red("does not verify")

    def test_reordered_lines_red(self):
        self.rewrite(lambda ls: ls[::-1])
        self.red("seq is 1, expected 0")

    def test_dropped_line_red(self):
        self.rewrite(lambda ls: ls[1:])
        self.red("expected 0")

    def test_relinked_forged_line_red(self):
        # a forged second line with a correct prev: only the signature can catch it
        def forge(ls):
            e = json.loads(ls[1])
            e["new_key"] = K.read_pub(self.w["pubkeys"]["bob"])
            return [ls[0], K.canonical(e)]
        self.rewrite(forge)
        self.red("does not verify")

    def test_bad_prev_red(self):
        def forge(ls):
            e = json.loads(ls[1])
            e["prev"] = "0" * 64
            return [ls[0], K.canonical(e)]
        self.rewrite(forge)
        self.red("prev does not match")

    def test_non_canonical_and_garbage_red(self):
        K.write_lines(self.d, "alice", [K.read_lines(self.p)[0] + b" "])
        write_index(self.d)
        self.red("not canonical")
        K.write_lines(self.d, "alice", [b"{nope"])
        write_index(self.d)
        self.red("not JSON")

    def test_chain_changes_the_top_root(self):
        top = build_index(self.d)["top_root"]
        self.assertIn("keys_sha", build_index(self.d)["maps"][0])
        K.recovery(self.d, "alice", self.w["owners"]["alice"], fresh_key(self.d, "r2")[1],
                   old_recovery_key=os.path.join(self.d, "keys", "alice_rec"), now=self.tick())
        self.red("does NOT match")                    # index not rebuilt: the chain is under top_root
        self.assertNotEqual(build_index(self.d)["top_root"], top)

    def test_proofs_and_log_still_work(self):
        p = prove(self.d, "alice", "review")
        self.assertIn("keys_sha", p["index"]["entry"])
        self.assertTrue(check_proof(p, os.path.join(self.d, "allowed_signers"))[0])
        p["index"]["entry"]["keys_sha"] = "0" * 64
        self.assertFalse(check_proof(p, os.path.join(self.d, "allowed_signers"))[0])
        append(self.d, now=0)
        self.green()
        self.rewrite(lambda ls: ls[::-1])
        with self.assertRaisesRegex(ValueError, "key chain"):
            append(self.d, now=1)


class BackwardCompat(unittest.TestCase):
    def test_shipped_maps_verify_with_same_roots(self):
        d = shipped_copy(self)
        self.assertFalse(any(os.path.exists(K.keys_path(d, o)) for o in SHIPPED_ROOTS))
        for o, r in SHIPPED_ROOTS.items():
            self.assertEqual(map_root(map_path(d, o), d), r)
        idx = build_index(d)
        self.assertEqual(idx["top_root"], SHIPPED_TOP)
        self.assertTrue(all(set(e) == {"owner", "root", "sig_sha"} for e in idx["maps"]))
        self.assertEqual(idx, read_json(os.path.join(REPO, "index.json")))
        ok, out = quietly(verify, d)
        self.assertTrue(ok, out)
        self.assertIn("note no maps/<owner>/keys.jsonl", out)

    def test_names_unchanged_without_chain(self):
        line = next(l for l in names_report(REPO) if l.startswith("'cody'"))
        self.assertIn("alice:cody [key b35d00c4]  vs  bob:cody [key a8dad593]", line)


class G1Rows(unittest.TestCase):
    def test_key_rows(self):
        for name, sabotage, want in KEY_ROWS:
            with self.subTest(name):
                self.assertEqual(run_row(REPO, sabotage, lambda d: verify(d, quiet=True)), want)

    def test_rows_red_for_the_right_reason(self):
        why = {"rotation not signed by the old key": "rotation not signed by the old key",
               "signature by a revoked agent key": "signed by REVOKED key"}
        for name, sabotage, _ in KEY_ROWS:
            if name in why:
                with self.subTest(name):
                    out = run_row(REPO, sabotage, lambda d: quietly(verify, d)[1])
                    self.assertTrue(any(x.startswith("RED") and why[name] in x for x in out.splitlines()), out)


class KeysCLI(KeyWorld):
    def test_full_cycle(self):
        b, ks = self.d, os.path.join(self.d, "keys")
        k2, pub2 = self.key("alice_cody2")
        kr, rpub = self.key("alice_rec")
        ka, apub = self.key("alice2")
        steps = [
            ("keys", "recovery", "alice", self.w["owners"]["alice"], kr + ".pub"),
            ("keys", "rotate", "alice", "agent:cody", k2 + ".pub", "--sign", self.w["owners"]["alice"],
             "--sign", self.w["agents"]["alice:cody"]),
            ("keys", "revoke", "alice", "owner", self.w["owners"]["alice"] + ".pub", "--by", "recovery",
             "--signer", kr),
            ("keys", "rotate", "alice", "owner", apub, "--sign", kr, "--sign", ka),
            ("index",),
        ]
        for s in steps:
            r = run("--base", b, *s)
            self.assertEqual(r.returncode, 0, (s, r.stdout, r.stderr))
        r = run("--base", b, "keys", "verify")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(run("--base", b, "verify").returncode, 0)
        show = run("--base", b, "keys", "show", "alice").stdout
        self.assertIn("rotated 1 time", show)
        self.assertIn("signed by new,recovery", show)
        self.assertIn("rotated 1 time", run("--base", b, "names").stdout)
        bad = run("--base", b, "keys", "rotate", "alice", "owner", pub2, "--sign", self.w["owners"]["alice"])
        self.assertEqual(bad.returncode, 1)
        self.assertIn("is none of", bad.stderr)          # a retired owner key has no role any more

    def test_keys_verify_on_shipped(self):
        r = run("keys", "verify")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("note", r.stdout)
        r = run("keys", "show", "alice")
        self.assertEqual(r.returncode, 0)
        self.assertIn("no keys.jsonl", r.stdout)


if __name__ == "__main__":
    unittest.main()
