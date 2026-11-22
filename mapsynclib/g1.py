"""g1: every green must be able to go red. Break one thing per row in a sandbox."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile

from .anchor import ANCHORS, WITNESSES, anchor, anchors_dir, receipt_for, statement
from .demo import add_witness, fresh_key, keygen, make_world
from . import keys as keychain
from .files import append_text, read_json, write_json
from .identity import names_report
from .hashing import merkle
from .index import top_leaves, verify, write_index
from .log import ZERO, canonical, entry_for, entry_sha, log_path, read_lines
from .proofs import check_proof, prove
from .sync import sync_report
from . import REPO
from .vocab import HIERARCHY, LOCAL, TERMS, VOCAB_FILES, load_vocab
from .world import load, save
from .claims import CONTRADICTION, gather as gather_claims
from .suggest import LEXICON, tag
from .anchor import NAMESPACE as ANCHOR_NAMESPACE, anchor_checks
from .files import read_text, write_bytes
from .hashing import leaf
from .log import compare as compare_logs
from .signing import AGENT_NAMESPACE, NAMESPACE as OWNER_NAMESPACE, agent_sign, sign, ssh_sign
from .world import map_path


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
    ("edit the pinned lexicon", lambda d: append_text(os.path.join(d, LEXICON), "gizmo ComputerProgram\n"), False),
    ("lexicon maps a word to an unknown term", lambda d: append_text(os.path.join(d, LEXICON), "gizmo Gadget\n"), False),
]


def _with_history(d):
    """Fixture: a two-entry log. seq 0 = the state before bob joined (alice's map only),
    seq 1 = the current index. Built without keys: a log records roots, it signs nothing."""
    idx = read_json(os.path.join(d, "index.json"))
    early = {**idx, "maps": idx["maps"][:1]}
    early["top_root"] = merkle(top_leaves(early))
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


def _keyed(d):
    """Fixture: replace the sandbox's world with a freshly keyed demo world (keys in
    d/keyworld/keys), rotate alice's Cody (signed by owner + old agent key) and register a
    recovery key for alice. No log/anchors: they recorded the replaced world.
    Returns the world dict plus "cody2", "alice_rec"."""
    for x in ("maps", "log", ANCHORS):
        shutil.rmtree(os.path.join(d, x), ignore_errors=True)
    for x in ("index.json", "allowed_signers", WITNESSES):
        if os.path.exists(os.path.join(d, x)):
            os.remove(os.path.join(d, x))
    kw = os.path.join(d, "keyworld")
    w = make_world(kw, terms_from=d)
    shutil.copytree(os.path.join(kw, "maps"), os.path.join(d, "maps"))
    shutil.copy(os.path.join(kw, "allowed_signers"), d)
    w["cody2"], pub = fresh_key(kw, "alice_cody2")
    keychain.rotate(d, "alice", "agent:cody", pub, [w["owners"]["alice"], w["agents"]["alice:cody"]],
                    now=1_700_000_000)
    w["alice_rec"], rpub = fresh_key(kw, "alice_rec")
    keychain.recovery(d, "alice", w["owners"]["alice"], rpub, now=1_700_000_100)
    write_index(d)
    return w


def _owner_rotation_new_only(d):
    w = _keyed(d)
    k2, pub = fresh_key(os.path.join(d, "keyworld"), "alice2")
    lines = keychain.read_lines(keychain.keys_path(d, "alice"))
    e = keychain.event(lines, "rotate", "owner", w["pubkeys"]["alice"], pub, "takeover", {"new": k2},
                       now=1_700_000_200)
    keychain.write_lines(d, "alice", lines + [keychain.canonical(e)])
    keychain.set_allowed_key(d, "alice", pub)       # everything else made consistent with the forgery
    from .signing import sign
    from .world import map_path
    sign(map_path(d, "alice"), k2, d, quiet=True)
    write_index(d)


def _revoke_old_cody(d):
    w = _keyed(d)                                   # review/notes still carry the old key's signatures
    keychain.revoke(d, "alice", "agent:cody", w["pubkeys"]["alice:cody"], "owner", w["owners"]["alice"],
                    now=1_700_000_200)
    write_index(d)


def _keys_lines(fn):
    def go(d):
        _keyed(d)
        p = keychain.keys_path(d, "alice")
        keychain.write_lines(d, "alice", fn(keychain.read_lines(p)))
        write_index(d)
    return go


def _forge_reason(lines):
    e = json.loads(lines[0])
    e["reason"] = "nothing to see here"
    return [keychain.canonical(e)] + lines[1:]


def _stale_allowed_signers(d):
    w = _keyed(d)
    k2, pub = fresh_key(os.path.join(d, "keyworld"), "alice2")
    keychain.rotate(d, "alice", "owner", pub, [w["owners"]["alice"], k2], now=1_700_000_200)
    keychain.set_allowed_key(d, "alice", w["pubkeys"]["alice"])   # old key back, map re-signed by it
    from .signing import sign
    from .world import map_path
    sign(map_path(d, "alice"), w["owners"]["alice"], d, quiet=True)
    write_index(d)


# (name, sabotage(dir), verify should be green?) -- on a freshly keyed world with keys.jsonl
KEY_ROWS = [
    ("keys: rotated agent key, old sigs stay green", _keyed, True),
    ("rotation not signed by the old key", _owner_rotation_new_only, False),
    ("signature by a revoked agent key", _revoke_old_cody, False),
    ("forge a key chain line (edit reason)", _keys_lines(_forge_reason), False),
    ("reorder the key chain's lines", _keys_lines(lambda ls: ls[::-1]), False),
    ("allowed_signers disagrees with key chain", _stale_allowed_signers, False),
]


def _local_world(local_terms: bool = True):
    """Fixture: replace the sandbox's world with a freshly keyed demo world whose Codys are
    CodingAgent and routers RoutingAgent (local terms, so both maps pin vocab_sha), or with
    base terms only (local_terms=False). Same vocabulary files as the sandbox. No log/anchors."""
    def go(d):
        for x in ("maps", "log", ANCHORS):
            shutil.rmtree(os.path.join(d, x), ignore_errors=True)
        for x in ("index.json", "allowed_signers", WITNESSES):
            if os.path.exists(os.path.join(d, x)):
                os.remove(os.path.join(d, x))
        if local_terms and not all(load_vocab(d).is_local(t) for t in ("CodingAgent", "RoutingAgent")):
            for f in VOCAB_FILES:                 # an older world: borrow this repo's hierarchy
                shutil.copy(os.path.join(REPO, f), os.path.join(d, f))
        kw = os.path.join(d, "vocabworld")
        make_world(kw, terms_from=d, local_terms=local_terms)
        shutil.copytree(os.path.join(kw, "maps"), os.path.join(d, "maps"))
        for x in ("allowed_signers", "index.json"):
            shutil.copy(os.path.join(kw, x), d)
    return go


def _then(*steps):
    def go(d):
        for f in steps:
            f(d)
    return go


def _edit_local(d):
    append_text(os.path.join(d, LOCAL), "\nTestingAgent ComputerProgram\n")


# (name, sabotage(dir), verify should be green?) -- the pinned hierarchy (sumo/*.txt)
VOCAB_ROWS = [
    ("vocab: maps tagged with local terms stay green", _local_world(), True),
    ("vocab: edit local.txt, no map uses it: green", _then(_local_world(False), _edit_local, write_index), True),
    ("edit sumo/local.txt under a map that uses it", _then(_local_world(), _edit_local, write_index), False),
    ("introduce a subclass cycle", lambda d: append_text(os.path.join(d, HIERARCHY), "IntentionalProcess Planning\n"), False),
    ("local term under an unknown parent", lambda d: append_text(os.path.join(d, LOCAL), "Gadget Gizmo\n"), False),
    ("redefine a base term in local.txt", lambda d: append_text(os.path.join(d, LOCAL), "Text Proposition\n"), False),
    ("a class under two disjoint classes", lambda d: append_text(os.path.join(d, HIERARCHY), "Text Proposition\n"), False),
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


def _retag(owner, node, term):
    return edit_map(owner, lambda m: next(n for n in m["nodes"] if n["id"] == node).update(sumo=term))


# (name, sabotage(dir), a CONTRADICTION should be shown?) -- claims reads tags, not signatures
CLAIMS_ROWS = [
    ("claims: shipped clusters show no CONTRADICTION", lambda d: None, False),
    ("disjoint linked tags must show CONTRADICTION", _then(_retag("alice", "review", "Human"),
                                                           _retag("bob", "prcheck", "ComputerProgram")), True),
]


def contradiction_shown(d: str) -> bool:
    return any(p["verdict"] == CONTRADICTION for c in gather_claims(d)["clusters"] for p in c["pairs"])


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
    ("tamper the lexicon sha in a proof", lambda p: p["index"].update(lexicon_sha="0" * 64), False),
    ("tamper the hierarchy files in a proof", lambda p: p.setdefault("vocab", {}).update(
        {LOCAL: p.get("vocab", {}).get(LOCAL, "") + "Gadget ComputerProgram\n"}), False),
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


# ------------------------------------------------ cross-key forgery and namespace confusion

def _fresh(d: str) -> dict:
    """Fixture: replace the sandbox's world with a freshly keyed demo world (make_world; keys
    in d/forgeworld/keys, never in a repo). Same vocabulary as the sandbox. No log/anchors/keys.jsonl.
    Returns the make_world dict (owners, agents, pubkeys)."""
    for x in ("maps", "log", ANCHORS):
        shutil.rmtree(os.path.join(d, x), ignore_errors=True)
    for x in ("index.json", "allowed_signers", WITNESSES):
        if os.path.exists(os.path.join(d, x)):
            os.remove(os.path.join(d, x))
    kw = os.path.join(d, "forgeworld")
    w = make_world(kw, terms_from=d)
    shutil.copytree(os.path.join(kw, "maps"), os.path.join(d, "maps"))
    for x in ("allowed_signers", "index.json"):
        shutil.copy(os.path.join(kw, x), d)
    return w


def _root_sig(d: str, owner: str, key: str, namespace: str) -> None:
    """Write maps/<owner>/root.sig = a signature over the owner's current root by `key` in
    `namespace`, then rebuild the index so only the signature itself can be wrong."""
    root = map_path_root(d, owner)
    write_bytes(os.path.join(d, "maps", owner, "root.sig"), ssh_sign(key, root, namespace))
    write_index(d)


def map_path_root(d: str, owner: str) -> str:
    from .hashing import map_root
    return map_root(map_path(d, owner), d)


def _cross_agent(d):
    w = _fresh(d)                                   # bob:changelog is by bob's Cody
    agent_sign(map_path(d, "bob"), "changelog", w["agents"]["alice:cody"], quiet=True)


def _cross_owner(d):
    w = _fresh(d)
    sign(map_path(d, "alice"), w["owners"]["bob"], d, quiet=True)
    write_index(d)


def _agent_as_owner(d):
    w = _fresh(d)                                   # the agent's key, the agent's namespace
    _root_sig(d, "alice", w["agents"]["alice:cody"], AGENT_NAMESPACE)


def _owner_wrong_ns(d):
    w = _fresh(d)                                   # right key, right bytes, wrong namespace only
    _root_sig(d, "alice", w["owners"]["alice"], AGENT_NAMESPACE)


def _agent_sig_owner_ns(d):
    w = _fresh(d)                                   # Cody's key over its own node, owner namespace
    node = next(n for n in load(d, "alice")["nodes"] if n["id"] == "review")
    write_bytes(_sig(d, "alice", "review"), ssh_sign(w["agents"]["alice:cody"], leaf(node), OWNER_NAMESPACE))


def _owner_witness(namespace: str):
    """Fixture: a fresh world whose log head is witnessed by "alice" -- alice's OWNER key listed
    in `witnesses` -- with the receipt signed in `namespace`. With mapsync-anchor that is a
    legitimate receipt (green control); with mapsync it is an owner signature passed off as a
    receipt (namespace confusion: red)."""
    def go(d):
        w = _fresh(d)
        from .log import append as log_append
        log_append(d)
        with open(os.path.join(d, WITNESSES), "w") as f:
            f.write(f"alice {w['pubkeys']['alice']}\n")
        anchor(d, "alice", w["owners"]["alice"], now=1_700_100_000)
        if namespace != ANCHOR_NAMESPACE:
            p, r = _receipt(d, seq=0, witness="alice")
            r["sig"] = ssh_sign(w["owners"]["alice"], statement(r).decode(), namespace).decode()
            write_json(p, r, indent=2, sort_keys=True)
    return go


def _key_event_owner_ns(d):
    """A rotation of alice's Cody exactly as `keys rotate` writes it (event, node pubkey updated,
    map re-signed by the owner) except that its signatures are made in the owner namespace
    (mapsync) instead of mapsync-keys. `rotate` itself would refuse it, so it is written raw."""
    w = _fresh(d)
    _, pub = fresh_key(os.path.join(d, "forgeworld"), "alice_cody2")
    saved = keychain.NAMESPACE
    keychain.NAMESPACE = OWNER_NAMESPACE             # event() reads the module constant at call time
    try:
        e = keychain.event([], "rotate", "agent:cody", w["pubkeys"]["alice:cody"], pub, "rotate",
                           {"owner": w["owners"]["alice"], "old": w["agents"]["alice:cody"]},
                           now=1_700_000_000)
    finally:
        keychain.NAMESPACE = saved
    keychain.write_lines(d, "alice", [keychain.canonical(e)])
    edit_map("alice", lambda m: next(n for n in m["nodes"] if n["id"] == "cody").update(pubkey=pub))(d)
    sign(map_path(d, "alice"), w["owners"]["alice"], d, quiet=True)
    write_index(d)


def _key_event_right_ns(d):
    """Control for the row above: the same rotation through `keys rotate` (mapsync-keys)."""
    w = _fresh(d)
    _, pub = fresh_key(os.path.join(d, "forgeworld"), "alice_cody2")
    keychain.rotate(d, "alice", "agent:cody", pub, [w["owners"]["alice"], w["agents"]["alice:cody"]],
                    now=1_700_000_000)
    write_index(d)


# (name, sabotage(dir), verify should be green?) -- on a freshly keyed world (make_world)
FORGERY_ROWS = [
    ("forgery: fresh-key world stays green", _fresh, True),
    ("Alice's Cody signs Bob's node (cross-key forgery)", _cross_agent, False),
    ("Bob's owner key signs Alice's root", _cross_owner, False),
    ("an agent signs as the owner (namespace confusion: mapsync-agent sig used as root.sig)",
     _agent_as_owner, False),
    ("owner's own key signs her root in mapsync-agent (namespace only)", _owner_wrong_ns, False),
    ("agent signs its node in the owner namespace (mapsync)", _agent_sig_owner_ns, False),
    ("keys: the same rotation in mapsync-keys: green", _key_event_right_ns, True),
    ("key-chain event signed in the owner namespace", _key_event_owner_ns, False),
    ("anchor: owner key as listed witness, mapsync-anchor: green", _owner_witness(ANCHOR_NAMESPACE), True),
    ("an owner sig reused as an anchor receipt sig (namespace confusion)", _owner_witness(OWNER_NAMESPACE), False),
]

NAMESPACES = {"owner root": OWNER_NAMESPACE, "agent node": AGENT_NAMESPACE,
              "key chain": keychain.NAMESPACE, "anchor receipt": ANCHOR_NAMESPACE}


def namespaces_distinct() -> bool:
    return (sorted(NAMESPACES.values()) == ["mapsync", "mapsync-agent", "mapsync-anchor", "mapsync-keys"]
            and len(set(NAMESPACES.values())) == len(NAMESPACES))


# ------------------------------------------------ audit rows for checks of C2-C7 not yet covered

def _fork_copy(prefix_only: bool):
    """`log compare` against a copy of the two-entry history: its first line only (a prefix:
    consistent), or with seq 0 rewritten and re-chained (a FORK at seq 0)."""
    def check(d):
        _with_history(d)
        lines = read_lines(log_path(d))
        other = lines[:1] if prefix_only else _rechain(lines)
        op = os.path.join(d, "other-roots.jsonl")
        with open(op, "wb") as f:
            f.write(b"".join(x + b"\n" for x in other))
        return compare_logs(log_path(d), op)[0]
    return check


def _witnesses_at_least(k: int):
    def check(d):
        _witnessed(d)
        return anchor_checks(d, lambda *a: None, k)
    return check


def _lexicon_weight_zero(d):
    append_text(os.path.join(d, LEXICON), "gizmo ComputerProgram 0\n")


def _lexicon_duplicate(d):
    append_text(os.path.join(d, LEXICON), "gizmo ComputerProgram\ngizmo ComputerProgram\n")


def _tag_yes(d):
    tag(d, "bob", "deadline", "Proposition", yes=True)


def _proof_top_root(want_top):
    def check(d):
        p = prove(d, "alice", "review")
        top = read_json(os.path.join(d, "index.json"))["top_root"] if want_top else "0" * 64
        return check_proof(p, os.path.join(d, "allowed_signers"), top)[0]
    return check


def _remove_signer(d):
    lines = [x for x in read_text(os.path.join(d, "allowed_signers")).splitlines() if not x.startswith("alice ")]
    write_bytes(os.path.join(d, "allowed_signers"), ("\n".join(lines) + "\n").encode())


def _verify(d):
    return verify(d, quiet=True)


# (name, check(dir) -> bool after the sabotage, want)
AUDIT_ROWS = [
    ("log compare: a prefix copy is consistent", _fork_copy(True), True),
    ("log compare: a re-chained copy reports FORK", _fork_copy(False), False),
    ("anchor verify --min-witnesses 2 with 2: green", _witnesses_at_least(2), True),
    ("anchor verify --min-witnesses 3 with 2 witnesses", _witnesses_at_least(3), False),
    ("lexicon entry with weight 0", lambda d: (_lexicon_weight_zero(d), _verify(d))[1], False),
    ("lexicon lists the same (word, term) twice", lambda d: (_lexicon_duplicate(d), _verify(d))[1], False),
    ("`tag --yes` retags without re-signing", lambda d: (_tag_yes(d), _verify(d))[1], False),
    ("check-proof --top-root = the real top_root: green", _proof_top_root(True), True),
    ("check-proof --top-root = some other top_root", _proof_top_root(False), False),
    ("check-proof with alice missing from allowed_signers",
     lambda d: (_remove_signer(d), proof_valid(d, lambda p: None))[1], False),
    ("drop alice from allowed_signers (verify)", lambda d: (_remove_signer(d), _verify(d))[1], False),
]


# ------------------------------------------------ the table and the runner

GREEN, SHOWN, CONSISTENT = ("green", "red"), ("shown", "not shown"), ("consistent", "FORK/red")


def rows() -> list[tuple[str, str, object, bool, tuple[str, str]]]:
    """Every g1 row: (group, name, run(base) -> got, want, (word if got, word if not))."""
    out = []
    def verify_rows(group, table):
        for name, sab, want in table:
            out.append((group, name, lambda b, s=sab: run_row(b, s, _verify), want, GREEN))
    verify_rows("verify", VERIFY_ROWS)
    verify_rows("log", LOG_ROWS)
    verify_rows("anchor", ANCHOR_ROWS)
    verify_rows("keys", KEY_ROWS)
    verify_rows("vocab", VOCAB_ROWS)
    verify_rows("forgery", FORGERY_ROWS)
    out.append(("forgery", "namespaces mapsync/-agent/-keys/-anchor distinct", lambda b: namespaces_distinct(),
                True, ("distinct", "NOT distinct")))
    for name, sab, want in NAMES_ROWS:
        out.append(("names", name, lambda b, s=sab: run_row(b, s, cody_collision), want,
                    ("collision shown", "collision not shown")))
    for name, sab, want in CLAIMS_ROWS:
        out.append(("claims", name, lambda b, s=sab: run_row(b, s, contradiction_shown), want,
                    ("CONTRADICTION shown", "CONTRADICTION not shown")))
    for name, sab, want in PROOF_ROWS:
        out.append(("proof", name, lambda b, s=sab: run_row(b, lambda d: None, lambda d: proof_valid(d, s)),
                    want, GREEN))
    for name, sab, want in SYNC_ROWS:
        out.append(("sync", name, lambda b, s=sab: sync_finds(b, s), want, GREEN))
    for name, check, want in AUDIT_ROWS:
        out.append(("audit", name, lambda b, c=check: run_row(b, lambda d: None, c), want, GREEN))
    return out


def list_rows() -> None:
    table = rows()
    for group, name, _, want, words in table:
        print(f"{group:8} {name}  (expect {words[0] if want else words[1]})")
    print(f"{len(table)} rows")


def g1(base: str, list_only: bool = False) -> bool:
    if list_only:
        list_rows()
        return True
    table = rows()
    bad = 0
    for group, name, run, want, words in table:
        try:
            got = bool(run(base))
        except Exception as e:                       # a crash is a failed row, not a traceback
            print(f"BAD  {name:48} -> crashed: {type(e).__name__}: {e}")
            bad += 1
            continue
        good = got == want
        bad += not good
        print(f"{'ok ' if good else 'BAD'}  {name:48} -> {words[0] if got else words[1]} "
              f"(expected {words[0] if want else words[1]})")
    reds = sum(1 for r in table if not r[3])
    print(f"G1: {len(table)} rows ({reds} sabotages, {len(table) - reds} green controls), "
          + ("every sabotage went red, baseline green" if not bad else f"{bad} FAILED: a check cannot go red"))
    return not bad
