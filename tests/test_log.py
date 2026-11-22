import json
import os
import shutil
import subprocess
import sys
import unittest

from tests.worlds import REPO, SHIPPED_TOP, demo_world, quietly, shipped_copy, tmpdir
from mapsynclib.files import read_bytes, read_json, write_bytes
from mapsynclib.index import verify
from mapsynclib.log import ZERO, LogError, append, canonical, compare, entry_sha, load_log, log_checks, log_path
from mapsynclib.signing import sign
from mapsynclib.world import load, map_path, save

CLI = os.path.join(REPO, "mapsync.py")


def run(*args):
    return subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, cwd="/")


def change(w, owner="bob", content="Thursday"):
    """Edit one node of a demo world and have its owner re-sign (index not rebuilt)."""
    b = w["base"]
    m = load(b, owner)
    m["nodes"][-1]["content"] = content
    save(b, owner, m)
    sign(map_path(b, owner), w["owners"][owner], b, quiet=True)


def lines_of(base):
    return read_bytes(log_path(base))[:-1].split(b"\n")


def put_lines(base, lines):
    write_bytes(log_path(base), b"".join(x + b"\n" for x in lines))


def log_ok(base):
    return log_checks(base, lambda *a: None, required=True)


class Append(unittest.TestCase):
    def test_idempotent(self):
        w = demo_world(self)
        e, _ = append(w["base"], now=0)
        self.assertEqual((e["seq"], e["prev"], e["top_root"]), (0, ZERO, w["top_root"]))
        before = read_bytes(log_path(w["base"]))
        for _ in range(2):
            e2, msg = append(w["base"])
            self.assertIsNone(e2)
            self.assertIn("unchanged", msg)
        self.assertEqual(read_bytes(log_path(w["base"])), before)

    def test_two_appends_after_map_change_chain(self):
        w = demo_world(self)
        b = w["base"]
        append(b, now=0)
        change(w)
        e1, msg = append(b, now=86400)            # rebuilds the stale index itself
        self.assertIn("index.json rebuilt", msg)
        lines, entries = load_log(log_path(b))
        self.assertEqual([e["seq"] for e in entries], [0, 1])
        self.assertEqual(entries[0]["prev"], ZERO)
        self.assertEqual(entries[1]["prev"], entry_sha(lines[0]))
        self.assertEqual(entries[1]["top_root"], read_json(os.path.join(b, "index.json"))["top_root"])
        self.assertNotEqual(entries[0]["top_root"], entries[1]["top_root"])
        self.assertEqual(entries[1]["recorded_at"], "1970-01-02T00:00:00Z")
        self.assertEqual(lines[1], canonical(entries[1]))
        self.assertTrue(quietly(verify, b)[0])

    def test_refuses_unsigned_state(self):
        w = demo_world(self)
        m = load(w["base"], "alice")
        m["nodes"][0]["content"] += "!"
        save(w["base"], "alice", m)
        with self.assertRaises(ValueError):
            append(w["base"])
        self.assertFalse(os.path.exists(log_path(w["base"])))

    def test_entry_sha_is_domain_separated(self):
        import hashlib
        self.assertEqual(entry_sha(b"x"), hashlib.sha256(b"\x02x").hexdigest())


class Tamper(unittest.TestCase):
    """Three-entry log on a demo world; each edit must make `log verify` (and verify) fail."""

    def setUp(self):
        self.w = demo_world(self)
        self.b = self.w["base"]
        append(self.b, now=0)
        change(self.w, content="Thursday")
        append(self.b, now=1)
        change(self.w, content="Monday")
        append(self.b, now=2)
        self.assertTrue(log_ok(self.b))
        self.lines = lines_of(self.b)
        self.assertEqual(len(self.lines), 3)

    def assertBroken(self, lines):
        put_lines(self.b, lines)
        self.assertFalse(log_ok(self.b))
        self.assertFalse(quietly(verify, self.b)[0])
        self.assertEqual(run("--base", self.b, "log", "verify").returncode, 1)

    def edited(self, i, **kw):
        e = json.loads(self.lines[i])
        e.update(kw)
        return self.lines[:i] + [canonical(e)] + self.lines[i + 1:]

    def test_edit_past_entry(self):
        self.assertBroken(self.edited(0, recorded_at="2001-01-01T00:00:00Z"))

    def test_edit_past_entry_maps(self):
        self.assertBroken(self.edited(1, maps=json.loads(self.lines[0])["maps"]))

    def test_non_canonical_rewrite(self):
        e = json.loads(self.lines[0])
        self.assertBroken([json.dumps(e).encode()] + self.lines[1:])

    def test_delete_middle_line(self):
        self.assertBroken([self.lines[0], self.lines[2]])

    def test_reorder_lines(self):
        self.assertBroken([self.lines[1], self.lines[0], self.lines[2]])

    def test_change_past_top_root(self):
        self.assertBroken(self.edited(1, top_root="0" * 64))

    def test_change_head_top_root(self):
        self.assertBroken(self.edited(2, top_root="0" * 64))

    def test_rechained_rewrite_still_caught_by_head(self):
        # rewrite seq 1 and re-link seq 2 to it: chain is valid again, but the head check
        # (and compare against any old copy) still sees it
        old = list(self.lines)
        e1 = json.loads(self.lines[1]); e1["recorded_at"] = "2001-01-01T00:00:00Z"
        e2 = json.loads(self.lines[2]); e2["prev"] = entry_sha(canonical(e1))
        new = [self.lines[0], canonical(e1), canonical(e2)]
        put_lines(self.b, new)
        self.assertTrue(log_ok(self.b))            # a re-chained log is self-consistent...
        theirs = os.path.join(tmpdir(self), "old.jsonl")
        write_bytes(theirs, b"".join(x + b"\n" for x in old))
        ok, out = compare(log_path(self.b), theirs)
        self.assertFalse(ok)                       # ...but any old copy exposes the rewrite
        self.assertIn("FORK at seq 1", out[0])

    def test_truncated_last_line(self):
        write_bytes(log_path(self.b), read_bytes(log_path(self.b))[:-1])
        self.assertFalse(log_ok(self.b))

    def test_blank_line(self):
        self.assertBroken([self.lines[0], b"", self.lines[1], self.lines[2]])

    def test_index_not_log_head(self):
        change(self.w, content="Never")
        r = run("--base", self.b, "index")             # rebuilt, but not published
        self.assertEqual(r.returncode, 0)
        self.assertIn("log append", r.stderr)
        r = run("--base", self.b, "verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("current index is not the log head", r.stdout)
        self.assertEqual(run("--base", self.b, "log", "verify").returncode, 1)
        r = run("--base", self.b, "log", "append")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("appended seq 3", r.stdout)
        self.assertEqual(run("--base", self.b, "verify").returncode, 0)


class Compare(unittest.TestCase):
    def test_prefix_ok_and_fork_detected(self):
        w = demo_world(self)
        b = w["base"]
        append(b, now=0)
        change(w, content="Thursday")
        append(b, now=1)
        snap = os.path.join(tmpdir(self), "snap.jsonl")
        shutil.copy(log_path(b), snap)                  # someone kept a copy at seq 1
        change(w, content="Monday")
        append(b, now=2)
        mine = log_path(b)

        r = run("--base", b, "log", "compare", snap)    # their copy is a prefix of ours
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("OK", r.stdout)
        self.assertIn("prefix", r.stdout)
        r = run("--base", b, "log", "compare", mine)    # identical
        self.assertEqual(r.returncode, 0)
        self.assertIn("identical", r.stdout)

        other = os.path.join(tmpdir(self), "w2")        # the other side: same seq 0,1, then a fork
        shutil.copytree(b, other)
        shutil.copy(snap, log_path(other))
        ow = {**w, "base": other, "owners": w["owners"]}
        change(ow, content="Tuesday")
        append(other, now=3)
        r = run("--base", other, "log", "compare", snap)  # snap is still a prefix of the fork
        self.assertEqual(r.returncode, 0)
        r = run("--base", b, "log", "compare", log_path(other))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FORK at seq 2", r.stdout)
        r = run("--base", other, "log", "compare", mine)  # symmetric
        self.assertEqual(r.returncode, 1)
        self.assertIn("FORK at seq 2", r.stdout)

    def test_fork_at_seq_0_and_broken_other(self):
        a, b = demo_world(self), demo_world(self)       # two unrelated worlds
        append(a["base"], now=0)
        append(b["base"], now=0)
        r = run("--base", a["base"], "log", "compare", log_path(b["base"]))
        self.assertEqual(r.returncode, 1)
        self.assertIn("FORK at seq 0", r.stdout)
        bad = os.path.join(tmpdir(self), "bad.jsonl")
        write_bytes(bad, b"{}\n")
        r = run("--base", a["base"], "log", "compare", bad)
        self.assertEqual(r.returncode, 1)
        self.assertIn("BROKEN", r.stdout)


class Shipped(unittest.TestCase):
    def test_shipped_log_head_is_shipped_top(self):
        lines, entries = load_log(log_path(REPO))
        self.assertEqual(entries[0]["seq"], 0)
        self.assertEqual(entries[-1]["top_root"], SHIPPED_TOP)
        self.assertTrue(log_ok(REPO))

    def test_no_log_is_a_green_note(self):
        d = shipped_copy(self)
        shutil.rmtree(os.path.join(d, "log"))
        ok, out = quietly(verify, d)
        self.assertTrue(ok)
        self.assertIn("note", out)
        r = run("--base", d, "log", "verify")
        self.assertEqual(r.returncode, 1)

    def test_show(self):
        r = run("log", "show")
        self.assertEqual(r.returncode, 0)
        self.assertIn(SHIPPED_TOP[:16], r.stdout)

    def test_parse_error_type(self):
        d = shipped_copy(self)
        write_bytes(log_path(d), b"not json\n")
        with self.assertRaises(LogError):
            load_log(log_path(d))


if __name__ == "__main__":
    unittest.main()
