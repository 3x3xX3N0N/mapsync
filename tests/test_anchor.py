import hashlib
import json
import os
import subprocess
import sys
import unittest

from tests.worlds import REPO, demo_world, shipped_copy, tmpdir
from mapsynclib.anchor import (anchor, anchor_checks, anchors_dir, check_receipt, filename,
                               load_witnesses, receipt_for, statement)
from mapsynclib.demo import add_witness, keygen
from mapsynclib.files import read_bytes, read_json, write_bytes, write_json
from mapsynclib.g1 import _rechain
from mapsynclib.index import verify
from mapsynclib.log import append, compare, load_log, log_path, read_lines
from mapsynclib.signing import sign
from mapsynclib.world import load, map_path, save

CLI = os.path.join(REPO, "mapsync.py")


def run(*args):
    return subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, cwd="/")


def witnessed_world(test, names=("w1",), entries=2):
    """Demo world with a log of `entries` entries and witnesses `names` (receipts on the head)."""
    w = demo_world(test)
    b = w["base"]
    append(b, now=0)
    for i in range(1, entries):
        m = load(b, "bob")
        m["nodes"][-1]["content"] = f"day {i}"
        save(b, "bob", m)
        sign(map_path(b, "bob"), w["owners"]["bob"], b, quiet=True)
        append(b, now=86400 * i)
    w["witnesses"] = {n: add_witness(b, n) for n in names}
    return w


def checks(base, k=0):
    out = []
    return anchor_checks(base, out.append, k), out


def refix(r):
    """Recompute statement_sha so only the signature can catch an edit."""
    r["statement_sha"] = hashlib.sha256(statement(r)).hexdigest()
    return r


class Receipt(unittest.TestCase):
    def test_valid_receipt_green(self):
        w = witnessed_world(self)
        p, r = anchor(w["base"], "w1", w["witnesses"]["w1"], now=1_700_000_000)
        lines, entries = load_log(log_path(w["base"]))
        self.assertEqual(os.path.basename(p), f"1-{entries[1]['top_root'][:16]}-w1.json")
        self.assertEqual(set(r), {"version", "witness", "log_seq", "entry_sha", "top_root", "witnessed_at",
                                  "statement_sha", "sig"})
        self.assertEqual((r["version"], r["log_seq"], r["witnessed_at"]), (1, 1, "2023-11-14T22:13:20Z"))
        self.assertIn("BEGIN SSH SIGNATURE", r["sig"])
        self.assertEqual(json.loads(statement(r)), {k: v for k, v in r.items() if k not in ("sig", "statement_sha")})
        ok, out = checks(w["base"])
        self.assertTrue(ok, out)
        self.assertIn("ok   log seq 1: 1 witness(es): w1", out)
        self.assertTrue(verify(w["base"], quiet=True))

    def test_anchor_past_seq(self):
        w = witnessed_world(self)
        _, r = anchor(w["base"], "w1", w["witnesses"]["w1"], seq=0)
        self.assertEqual(r["log_seq"], 0)
        ok, out = checks(w["base"])
        self.assertTrue(ok)
        self.assertTrue(any("log head seq 1 is not witnessed" in x for x in out), out)

    def assertRed(self, w, why):
        ok, out = checks(w["base"])
        self.assertFalse(ok, out)
        self.assertTrue(any(x.startswith("RED  receipt") and why in x for x in out), out)
        self.assertFalse(verify(w["base"], quiet=True))

    def test_tampered_top_root(self):
        w = witnessed_world(self)
        p, r = anchor(w["base"], "w1", w["witnesses"]["w1"])
        r["top_root"] = "0" * 64
        os.remove(p)
        write_json(os.path.join(anchors_dir(w["base"]), filename(r)), refix(r))   # consistent name + sha
        self.assertRed(w, "signature is not by w1's key")

    def test_tampered_top_root_plain_edit(self):
        w = witnessed_world(self)
        p, r = anchor(w["base"], "w1", w["witnesses"]["w1"])
        r["top_root"] = "0" * 64
        write_json(p, r)
        self.assertRed(w, "file name does not match")

    def test_tampered_witnessed_at(self):
        w = witnessed_world(self)
        p, r = anchor(w["base"], "w1", w["witnesses"]["w1"])
        r["witnessed_at"] = "2020-01-01T00:00:00Z"
        write_json(p, r)
        self.assertRed(w, "statement_sha does not match")
        write_json(p, refix(r))
        self.assertRed(w, "signature is not by w1's key")

    def test_signature_by_unlisted_key(self):
        w = witnessed_world(self)
        k = os.path.join(tmpdir(self), "mallory")
        keygen(k)
        lines, entries = load_log(log_path(w["base"]))
        r = receipt_for("w1", k, 1, lines[1], entries[1]["top_root"])
        os.makedirs(anchors_dir(w["base"]))
        write_json(os.path.join(anchors_dir(w["base"]), filename(r)), r)
        self.assertRed(w, "signature is not by w1's key")
        r2 = receipt_for("mallory", k, 1, lines[1], entries[1]["top_root"])
        os.remove(os.path.join(anchors_dir(w["base"]), filename(r)))
        write_json(os.path.join(anchors_dir(w["base"]), filename(r2)), r2)
        self.assertRed(w, "'mallory' is not a listed witness")

    def test_anchor_refuses_wrong_or_unlisted_key(self):
        w = witnessed_world(self, names=("w1", "w2"))
        with self.assertRaisesRegex(ValueError, "not w1's key"):
            anchor(w["base"], "w1", w["witnesses"]["w2"])
        with self.assertRaisesRegex(ValueError, "not listed"):
            anchor(w["base"], "carol", w["witnesses"]["w1"])
        with self.assertRaisesRegex(ValueError, "no log entry seq 5"):
            anchor(w["base"], "w1", w["witnesses"]["w1"], seq=5)
        with self.assertRaisesRegex(ValueError, "bad witness name"):
            anchor(w["base"], "verify", w["witnesses"]["w1"])
        self.assertFalse(os.path.exists(anchors_dir(w["base"])))

    def test_anchor_refuses_when_log_verify_fails(self):
        w = witnessed_world(self)
        m = load(w["base"], "alice")
        m["nodes"][0]["content"] += "!"
        save(w["base"], "alice", m)
        sign(map_path(w["base"], "alice"), w["owners"]["alice"], w["base"], quiet=True)
        from mapsynclib.index import write_index
        write_index(w["base"])                     # index ahead of the log head
        with self.assertRaisesRegex(ValueError, "log verify fails"):
            anchor(w["base"], "w1", w["witnesses"]["w1"])
        os.remove(log_path(w["base"]))
        with self.assertRaisesRegex(ValueError, "log verify fails"):
            anchor(w["base"], "w1", w["witnesses"]["w1"])

    def test_relabelled_a_as_b(self):
        w = witnessed_world(self, names=("w1", "w2"))
        p, r = anchor(w["base"], "w1", w["witnesses"]["w1"])
        os.remove(p)
        r["witness"] = "w2"
        write_json(os.path.join(anchors_dir(w["base"]), filename(r)), refix(r))
        self.assertRed(w, "signature is not by w2's key")

    def test_renamed_file_only(self):
        w = witnessed_world(self, names=("w1", "w2"))
        p, r = anchor(w["base"], "w1", w["witnesses"]["w1"])
        os.rename(p, p.replace("-w1.json", "-w2.json"))
        self.assertRed(w, "file name does not match")

    def test_rewritten_after_anchoring(self):
        w = witnessed_world(self)
        b = w["base"]
        anchor(b, "w1", w["witnesses"]["w1"], seq=0)
        anchor(b, "w1", w["witnesses"]["w1"], seq=1)
        old = os.path.join(tmpdir(self), "old.jsonl")
        write_bytes(old, read_bytes(log_path(b)))
        lines = _rechain(read_lines(log_path(b)))  # forge seq 0, re-link seq 1: chain itself is fine
        write_bytes(log_path(b), b"".join(x + b"\n" for x in lines))
        self.assertEqual(len(load_log(log_path(b))[1]), 2)
        ok, out = checks(b)
        self.assertFalse(ok)
        self.assertTrue(any("0-" in x and "history rewritten after anchoring" in x for x in out), out)
        self.assertTrue(any(x.startswith("RED  receipt 1-") for x in out), out)  # seq 1's entry_sha moved too
        self.assertFalse(verify(b, quiet=True))
        os.rename(anchors_dir(b), anchors_dir(b) + ".gone")   # without receipts the forgery verifies...
        self.assertTrue(verify(b, quiet=True))
        self.assertFalse(compare(log_path(b), old)[0])        # ...and only an old copy catches it

    def test_truncated_after_anchoring(self):
        w = witnessed_world(self)
        anchor(w["base"], "w1", w["witnesses"]["w1"])
        lines = read_lines(log_path(w["base"]))
        write_bytes(log_path(w["base"]), lines[0] + b"\n")
        self.assertRed(w, "log has no seq 1")

    def test_stray_file_and_bad_json(self):
        w = witnessed_world(self)
        os.makedirs(anchors_dir(w["base"]))
        write_bytes(os.path.join(anchors_dir(w["base"]), "x.json"), b"{")
        self.assertRed(w, "not JSON")


class MinWitnesses(unittest.TestCase):
    def test_one_vs_two(self):
        w = witnessed_world(self, names=("w1", "w2"))
        b = w["base"]
        anchor(b, "w1", w["witnesses"]["w1"])
        anchor(b, "w1", w["witnesses"]["w1"])      # same witness twice counts once
        self.assertTrue(checks(b, 1)[0])
        ok, out = checks(b, 2)
        self.assertFalse(ok)
        self.assertIn("RED  log head seq 1 has 1 witness(es), need 2", out)
        r = run("--base", b, "anchor", "verify", "--min-witnesses", "2")
        self.assertEqual(r.returncode, 1, r.stdout)
        anchor(b, "w2", w["witnesses"]["w2"])
        self.assertTrue(checks(b, 2)[0])
        r = run("--base", b, "anchor", "verify", "--min-witnesses", "2")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("log seq 1: 2 witness(es): w1, w2", r.stdout)

    def test_witnesses_on_old_entry_dont_count_for_head(self):
        w = witnessed_world(self, names=("w1",))
        anchor(w["base"], "w1", w["witnesses"]["w1"], seq=0)
        self.assertFalse(checks(w["base"], 1)[0])


class Commands(unittest.TestCase):
    def test_anchor_verify_export_compare(self):
        w = witnessed_world(self)
        b = w["base"]
        r = run("--base", b, "anchor", "verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("note no anchors/", r.stdout)
        r = run("--base", b, "anchor", "w1", w["witnesses"]["w1"], "--seq", "0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("w1 witnessed seq 0", r.stdout)
        r = run("--base", b, "anchor", "w1", w["witnesses"]["w1"], "--seq", "9")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no log entry seq 9", r.stderr)
        mine = os.path.join(tmpdir(self), "mine")
        r = run("--base", b, "anchor", "export", mine)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(os.listdir(mine)), ["anchors", "log", "witnesses"])
        self.assertEqual(run("--base", mine, "anchor", "verify").returncode, 0)
        self.assertEqual(run("--base", b, "log", "compare", os.path.join(mine, "log", "roots.jsonl")).returncode, 0)
        lines = _rechain(read_lines(log_path(b)))  # the keeper rewrites history later
        write_bytes(log_path(b), b"".join(x + b"\n" for x in lines))
        r = run("--base", b, "log", "compare", os.path.join(mine, "log", "roots.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("FORK at seq 0", r.stdout)
        self.assertEqual(run("--base", b, "anchor", "verify").returncode, 1)
        self.assertEqual(run("--base", b, "verify").returncode, 1)

    def test_usage(self):
        self.assertEqual(run("anchor", "verify", "extra").returncode, 2)


class Shipped(unittest.TestCase):
    def test_shipped_receipt_verifies_and_no_private_key(self):
        ok, out = checks(REPO)
        self.assertTrue(ok, out)
        ws = load_witnesses(REPO)
        self.assertEqual(list(ws), ["demo-witness"])
        self.assertTrue(any(x.startswith("ok   receipt 0-") for x in out), out)
        marker = b"BEGIN OPENSSH " + b"PRIVATE KEY"          # split so this file doesn't match
        tracked = subprocess.run(["git", "-C", REPO, "ls-files", "-co", "--exclude-standard"],
                                 capture_output=True, text=True, check=True).stdout.split()
        for f in tracked:
            self.assertNotIn(marker, read_bytes(os.path.join(REPO, f)), f)

    def test_shipped_copy_tamper_red(self):
        d = shipped_copy(self)
        self.assertTrue(verify(d, quiet=True))
        p = os.path.join(anchors_dir(d), os.listdir(anchors_dir(d))[0])
        r = read_json(p)
        r["witnessed_at"] = "2020-01-01T00:00:00Z"
        write_json(p, refix(r))
        self.assertFalse(verify(d, quiet=True))

    def test_check_receipt_rejects_extra_keys(self):
        w = witnessed_world(self)
        p, r = anchor(w["base"], "w1", w["witnesses"]["w1"])
        lines, entries = load_log(log_path(w["base"]))
        self.assertIsNone(check_receipt(r, os.path.basename(p), load_witnesses(w["base"]), lines, entries))
        self.assertIn("exactly the keys", check_receipt({**r, "x": 1}, os.path.basename(p),
                                                        load_witnesses(w["base"]), lines, entries))


if __name__ == "__main__":
    unittest.main()
