"""g1: every green must be able to go red. Break one thing per row in a sandbox."""
from __future__ import annotations

import os
import shutil
import tempfile

from .files import append_text, read_json, write_json
from .identity import names_report
from .index import verify, write_index
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
