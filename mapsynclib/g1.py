"""g1: every green must be able to go red. Break one thing per row in a sandbox."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile

from .anchor import ANCHORS, WITNESSES, anchor, anchors_dir, receipt_for, statement
from .demo import add_witness, keygen
from .files import append_text, read_json, write_json
from .identity import names_report
from .hashing import merkle
from .index import entry_hash, verify, write_index
from .log import ZERO, canonical, entry_for, entry_sha, log_path, read_lines
from .proofs import check_proof, prove
from .sync import sync_report
from .vocab import TERMS
from .world import load, save


def sandbox(base: str, d: str | None = None) -> str:
    """Copy the verifiable parts of the world at `base` into a fresh dir (no keys)."""
    d = d or tempfile.mkdtemp(prefix="mapsync-g1-")
    for x in ("maps", "sumo"):
        shutil.copytree(os.path.join(base, x), os.path.join(d, x))
    for x in ("index.json", "allowed_signers"):
        shutil.copy(os.path.join(base, x), d)
    for x in ("log", ANCHORS):
        if os.path.isdir(os.path.join(base, x)):
            shutil.copytree(os.path.join(base, x), os.path.join(d, x))
    if os.path.exists(os.path.join(base, WITNESSES)):
        shutil.copy(os.path.join(base, WITNESSES), d)
    return d


def edit_map(owner, fn):
    def go(d):
        m = load(d, owner)
        fn(m)
        save(d, owner, m)
    return go


def _first(m):
    return m["nodes"][0]


def _swap_sigs(d):
    a, b, t = (os.path.join(d, "maps", "alice", "root.sig"), os.path.join(d, "maps", "bob", "root.sig"),
               os.path.join(d, "maps", "t"))
    shutil.move(a, t); shutil.move(b, a); shutil.move(t, b)


def _rewrite_top(d):
    p = os.path.join(d, "index.json")
    j = read_json(p)
    write_json(p, {**j, "top_root": "0" * 64})


def _sig(d, owner, node):
    return os.path.join(d, "maps", owner, "agent_sigs", f"{node}.sig")


# (name, sabotage(dir), verify should be green?)
VERIFY_ROWS = [
    ("baseline (no sabotage) stays green", lambda d: None, True),
    ("change one word of content", edit_map("alice", lambda m: _first(m).update(content=_first(m)["content"] + "!")), False),
    ("retag a node with a different SUMO term", edit_map("bob", lambda m: _first(m).update(sumo="Proposition")), False),
    ("tag a node with a term not in the pinned list", edit_map("bob", lambda m: _first(m).update(sumo="Unicorn")), False),
    ("change the salt only", edit_map("alice", lambda m: _first(m).update(salt="00")), False),
    ("claim alice's map is bob's", edit_map("alice", lambda m: m.update(owner="bob")), False),
    ("swap the two signatures", _swap_sigs, False),
    ("delete an agent's signature on its node", lambda d: os.remove(_sig(d, "alice", "notes")), False),
    ("move an agent signature onto another node", lambda d: shutil.copy(_sig(d, "alice", "notes"), _sig(d, "alice", "review")), False),
    ("point same_as at a node that doesn't exist", edit_map("bob", lambda m: _first(m).update(same_as=["alice:nope"])), False),
    ("edit the pinned SUMO term list", lambda d: append_text(os.path.join(d, TERMS), "Unicorn\n"), False),
    ("rewrite index.json top_root", _rewrite_top, False),
]


def _with_history(d):
    """Fixture: a two-entry log. seq 0 = the state before bob joined (alice's map only),
    seq 1 = the current index. Built without keys: a log records roots, it signs nothing."""
    idx = read_json(os.path.join(d, "index.json"))
    early = {**idx, "maps": idx["maps"][:1]}
    early["top_root"] = merkle([entry_hash(e) for e in early["maps"]] + [idx["sumo_terms_sha"]])
    e0 = entry_for(early, 0, ZERO, now=1_700_000_000)
    e1 = entry_for(idx, 1, entry_sha(canonical(e0)), now=1_700_086_400)
    shutil.rmtree(anchors_dir(d), ignore_errors=True)   # receipts belonged to the replaced history
    os.makedirs(os.path.dirname(log_path(d)), exist_ok=True)
    with open(log_path(d), "wb") as f:
        f.write(canonical(e0) + b"\n" + canonical(e1) + b"\n")


def _edit_log(fn):
    """Install the history fixture, then rewrite the log's lines with fn(lines) -> lines."""
    def go(d):
        _with_history(d)
        lines = fn(read_lines(log_path(d)))
        with open(log_path(d), "wb") as f:
            f.write(b"".join(x + b"\n" for x in lines))
    return go


def _restamp_first(lines):
    e = json.loads(lines[0])
    e["recorded_at"] = "2023-11-15T00:00:00Z"   # backdate seq 0, re-serialized canonically
    return [canonical(e)] + lines[1:]


# (name, sabotage(dir), verify should be green?) -- on top of a two-entry log
LOG_ROWS = [
    ("log: a two-entry history stays green", _with_history, True),
    ("rewrite a past log entry", _edit_log(_restamp_first), False),
    ("drop a log entry", _edit_log(lambda ls: ls[1:]), False),
    ("reorder the log's lines", _edit_log(lambda ls: ls[::-1]), False),
    ("index newer than the log head", _edit_log(lambda ls: ls[:-1]), False),
]


def _rechain(lines):
    """Rewrite seq 0 and re-link every later prev: a self-consistent forged history."""
    out, prev = [], ZERO
    for line in _restamp_first(lines):
        e = {**json.loads(line), "prev": prev}
        out.append(canonical(e))
        prev = entry_sha(out[-1])
    return out


def _witnessed(d):
    """Fixture: the two-entry history, witnessed by w1 and w2 (fresh keys in d/keys; the
    sandbox's own witness list replaces any shipped one). Returns the private key paths."""
    _with_history(d)
    if os.path.exists(os.path.join(d, WITNESSES)):
        os.remove(os.path.join(d, WITNESSES))
    keys = {w: add_witness(d, w) for w in ("w1", "w2")}
    for w, k in keys.items():
        for seq in (0, 1):
            anchor(d, w, k, seq, now=1_700_100_000)
    return keys


def _receipt(d, seq=1, witness="w1"):
    p = next(os.path.join(anchors_dir(d), f) for f in os.listdir(anchors_dir(d))
             if f.startswith(f"{seq}-") and f.endswith(f"-{witness}.json"))
    return p, read_json(p)


def _tamper_receipt(d):
    _witnessed(d)
    p, r = _receipt(d)
    r["witnessed_at"] = "2023-01-01T00:00:00Z"          # backdate it, and fix up statement_sha
    r["statement_sha"] = hashlib.sha256(statement(r)).hexdigest()
    write_json(p, r)


def _rewrite_after_anchor(d):
    _witnessed(d)
    lines = _rechain(read_lines(log_path(d)))
    with open(log_path(d), "wb") as f:
        f.write(b"".join(x + b"\n" for x in lines))


def _relabel(d):
    _witnessed(d)
    p, r = _receipt(d, witness="w1")
    os.remove(p)
    r["witness"] = "w2"                                # w1's signature, now claiming to be w2's
    r["statement_sha"] = hashlib.sha256(statement(r)).hexdigest()
    os.remove(_receipt(d, witness="w2")[0])
    write_json(os.path.join(anchors_dir(d), f"1-{r['top_root'][:16]}-w2.json"), r)


def _unlisted_key(d):
    _witnessed(d)
    k = os.path.join(d, "keys", "mallory")             # a key nobody listed in witnesses
    keygen(k, "mallory")
    lines = read_lines(log_path(d))
    r = receipt_for("w1", k, 1, lines[1], json.loads(lines[1])["top_root"], now=1_700_100_000)
    write_json(_receipt(d, witness="w1")[0], r)


# (name, sabotage(dir), verify should be green?) -- on a witnessed two-entry log (fresh keys)
ANCHOR_ROWS = [
    ("anchor: a witnessed history stays green", _witnessed, True),
    ("tamper an anchor receipt", _tamper_receipt, False),
    ("rewrite log entry after it was anchored", _rewrite_after_anchor, False),
    ("relabel w1's receipt as w2's", _relabel, False),
    ("anchor receipt signed by an unlisted key", _unlisted_key, False),
]


def _link_codys(d):
    for o, other in (("alice", "bob"), ("bob", "alice")):
        edit_map(o, lambda m, other=other: next(n for n in m["nodes"] if n["id"] == "cody")
                 .update(same_as=[f"{other}:cody"]))(d)


# (name, sabotage(dir), collision between the Codys should be shown?)
NAMES_ROWS = [
    ("names: two Codys reported as COLLISION", lambda d: None, True),
    ("names: mutual same_as turns it into LINKED", _link_codys, False),
]


def cody_collision(d: str) -> bool:
    top = "\n".join(names_report(d)).split("-- same_as")[0]
    return "'cody'" in top and "COLLISION" in top


def _step(p, k=0):
    return p["map"]["path"][k]


def _flip(side):
    return "L" if side == "R" else "R"


# (name, sabotage(proof of alice:review), check_proof should say valid?)
PROOF_ROWS = [
    ("proof: alice:review proves on its own", lambda p: None, True),
    ("tamper a revealed node in a proof", lambda p: p["node"].update(content=p["node"]["content"] + "!"), False),
    ("tamper a proof's audit path", lambda p: _step(p).update(hash=_step(p)["hash"][::-1]), False),
    ("flip a left/right flag in a proof's path", lambda p: _step(p, 1).update(side=_flip(_step(p, 1)["side"])), False),
    ("claim the proven node is bob's", lambda p: p.update(owner="bob"), False),
]


def proof_valid(d: str, sabotage) -> bool:
    p = prove(d, "alice", "review")
    sabotage(p)
    return check_proof(p, os.path.join(d, "allowed_signers"))[0]


def _change_review(d):
    edit_map("alice", lambda m: next(n for n in m["nodes"] if n["id"] == "review")
             .update(content="Changed after the fact"))(d)
    write_index(d)


# (name, sabotage(the other world), sync-check should report IN SYNC?)
SYNC_ROWS = [
    ("sync: an identical copy is IN SYNC", lambda d: None, True),
    ("sync: change one node in the other world", _change_review, False),
]


def sync_finds(base: str, sabotage) -> bool:
    d = sandbox(base)
    try:
        sabotage(d)
        same, lines = sync_report(base, d)
        if not same and "    ~ alice:review  differs" not in lines:
            return True                           # out of sync but the walk-down missed it: BAD
        return same
    finally:
        shutil.rmtree(d)


def run_row(base: str, sabotage, check) -> bool:
    d = sandbox(base)
    try:
        sabotage(d)
        return check(d)
    finally:
        shutil.rmtree(d)


def g1(base: str) -> bool:
    all_ok = True
    for name, sabotage, want in VERIFY_ROWS:
        got = run_row(base, sabotage, lambda d: verify(d, quiet=True))
        good = got == want
        all_ok &= good
        print(f"{'ok ' if good else 'BAD'}  {name:48} -> {'green' if got else 'red'} (expected {'green' if want else 'red'})")
    for name, sabotage, want in LOG_ROWS:
        got = run_row(base, sabotage, lambda d: verify(d, quiet=True))
        good = got == want
        all_ok &= good
        print(f"{'ok ' if good else 'BAD'}  {name:48} -> {'green' if got else 'red'} (expected {'green' if want else 'red'})")
    for name, sabotage, want in ANCHOR_ROWS:
        got = run_row(base, sabotage, lambda d: verify(d, quiet=True))
        good = got == want
        all_ok &= good
        print(f"{'ok ' if good else 'BAD'}  {name:48} -> {'green' if got else 'red'} (expected {'green' if want else 'red'})")
    for name, sabotage, want in NAMES_ROWS:
        got = run_row(base, sabotage, cody_collision)
        good = got == want
        all_ok &= good
        print(f"{'ok ' if good else 'BAD'}  {name:48} -> collision {'shown' if got else 'not shown'} (expected {'shown' if want else 'not shown'})")
    for name, sabotage, want in PROOF_ROWS:
        got = run_row(base, lambda d: None, lambda d: proof_valid(d, sabotage))
        good = got == want
        all_ok &= good
        print(f"{'ok ' if good else 'BAD'}  {name:48} -> {'green' if got else 'red'} (expected {'green' if want else 'red'})")
    for name, sabotage, want in SYNC_ROWS:
        got = sync_finds(base, sabotage)
        good = got == want
        all_ok &= good
        print(f"{'ok ' if good else 'BAD'}  {name:48} -> {'green' if got else 'red'} (expected {'green' if want else 'red'})")
    print("G1: every sabotage went red, baseline green" if all_ok else "G1 FAILED: a check cannot go red")
    return all_ok
