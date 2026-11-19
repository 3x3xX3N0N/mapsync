"""mapsync: sync many people's mental maps without merging them into one.

Each person owns one map (maps/<name>/map.json). Every node is tagged with a SUMO
term from a pinned list. A map hashes to a Merkle root, the owner signs that root
with an ssh key, and index.json collects every (owner, root, signature) into one
top root. Compare top roots to check sync; walk down to find what differs.

Stdlib only, plus `ssh-keygen` for signatures.

    python3 mapsync.py root maps/alice/map.json     print a map's root
    python3 mapsync.py sign maps/alice/map.json KEY write maps/alice/root.sig
    python3 mapsync.py index                        rebuild index.json
    python3 mapsync.py verify                       check everything; exit 0 if green
    python3 mapsync.py diff A.json B.json           which nodes differ between two maps
    python3 mapsync.py concepts                     line maps up by SUMO term, not label
    python3 mapsync.py g1                           sabotage each check; each must go red
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TERMS = os.path.join("sumo", "terms.txt")
NAMESPACE = "mapsync"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_terms(base: str) -> tuple[set[str], str]:
    raw = open(os.path.join(base, TERMS), "rb").read()
    terms = {ln.strip() for ln in raw.decode().splitlines() if ln.strip() and not ln.startswith("#")}
    return terms, sha(raw)


def leaf(node: dict) -> str:
    """A node's leaf hash. The salt stops anyone guessing short hidden content."""
    canon = json.dumps({k: node[k] for k in ("id", "label", "sumo", "content", "salt")},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha(b"\x00" + canon.encode())          # 0x00 = leaf, 0x01 = inner (no 2nd-preimage mixups)


def merkle(hashes: list[str]) -> str:
    if not hashes:
        return sha(b"")
    level = hashes
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [sha(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b)) for a, b in zip(level[::2], level[1::2])]
    return level[0]


def map_root(path: str, base: str) -> str:
    m = json.load(open(path, encoding="utf-8"))
    terms, terms_sha = load_terms(base)
    for n in m["nodes"]:
        if n["sumo"] not in terms:
            raise ValueError(f"{path}: node {n['id']!r} tagged {n['sumo']!r}, not in pinned {TERMS}")
    nodes = sorted(m["nodes"], key=lambda n: n["id"])
    # the owner and the vocabulary version are part of what gets signed
    head = sha(json.dumps({"owner": m["owner"], "sumo_terms_sha": terms_sha}, sort_keys=True).encode())
    return merkle([head] + [leaf(n) for n in nodes])


def owners(base: str) -> list[str]:
    d = os.path.join(base, "maps")
    return sorted(p for p in os.listdir(d) if os.path.isfile(os.path.join(d, p, "map.json")))


def sign(path: str, key: str) -> None:
    root = map_root(path, HERE)
    sig = os.path.join(os.path.dirname(path), "root.sig")
    r = subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", key, "-n", NAMESPACE],
                       input=root.encode(), capture_output=True, check=True)
    open(sig, "wb").write(r.stdout)
    print(f"signed {root[:16]}… -> {sig}")


def sig_ok(base: str, owner: str, root: str) -> bool:
    sig = os.path.join(base, "maps", owner, "root.sig")
    if not os.path.exists(sig):
        return False
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", os.path.join(base, "allowed_signers"),
                        "-I", owner, "-n", NAMESPACE, "-s", sig],
                       input=root.encode(), capture_output=True)
    return r.returncode == 0


def build_index(base: str) -> dict:
    _, terms_sha = load_terms(base)
    entries = []
    for o in owners(base):
        root = map_root(os.path.join(base, "maps", o, "map.json"), base)
        sig = open(os.path.join(base, "maps", o, "root.sig"), "rb").read().decode()
        entries.append({"owner": o, "root": root, "sig_sha": sha(sig.encode())})
    top = merkle([sha(json.dumps(e, sort_keys=True).encode()) for e in entries] + [terms_sha])
    return {"sumo_terms_sha": terms_sha, "maps": entries, "top_root": top}


def verify(base: str, quiet: bool = False) -> bool:
    say = (lambda *a: None) if quiet else print
    ok = True
    try:
        fresh = build_index(base)
    except (ValueError, FileNotFoundError, KeyError) as e:
        say(f"RED  {e}")
        return False
    for e in fresh["maps"]:
        good = sig_ok(base, e["owner"], e["root"])
        say(f"{'ok ' if good else 'RED'}  {e['owner']}: root {e['root'][:16]}… signature {'valid' if good else 'INVALID'}")
        ok &= good
    stored = json.load(open(os.path.join(base, "index.json")))
    same = stored == fresh
    say(f"{'ok ' if same else 'RED'}  index.json top_root {stored.get('top_root', '?')[:16]}… "
        f"{'matches' if same else 'does NOT match'} a rebuild from the maps")
    ok &= same
    say("GREEN: every map signed by its owner, index matches" if ok else "RED")
    return ok


def diff(a: str, b: str) -> None:
    na = {n["id"]: leaf(n) for n in json.load(open(a, encoding="utf-8"))["nodes"]}
    nb = {n["id"]: leaf(n) for n in json.load(open(b, encoding="utf-8"))["nodes"]}
    for i in sorted(na.keys() | nb.keys()):
        if i not in nb:
            print(f"- {i}  only in {a}")
        elif i not in na:
            print(f"+ {i}  only in {b}")
        elif na[i] != nb[i]:
            print(f"~ {i}  differs")


def concepts(base: str) -> None:
    """Same meaning under different words: group every node by its SUMO term."""
    by: dict[str, list[str]] = {}
    for o in owners(base):
        for n in json.load(open(os.path.join(base, "maps", o, "map.json"), encoding="utf-8"))["nodes"]:
            by.setdefault(n["sumo"], []).append(f"{o}:{n['label']!r}")
    for term in sorted(by):
        print(f"{term:20} {', '.join(by[term])}")


def g1() -> bool:
    """Every green must be able to go red. Break one thing per row in a sandbox."""
    def edit_map(owner, fn):
        def go(d):
            p = os.path.join(d, "maps", owner, "map.json")
            m = json.load(open(p, encoding="utf-8")); fn(m)
            json.dump(m, open(p, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        return go

    def first(m): return m["nodes"][0]
    rows = [
        ("baseline (no sabotage) stays green", lambda d: None, True),
        ("change one word of content", edit_map("alice", lambda m: first(m).update(content=first(m)["content"] + "!")), False),
        ("retag a node with a different SUMO term", edit_map("bob", lambda m: first(m).update(sumo="Proposition")), False),
        ("tag a node with a term not in the pinned list", edit_map("bob", lambda m: first(m).update(sumo="Unicorn")), False),
        ("change the salt only", edit_map("alice", lambda m: first(m).update(salt="00")), False),
        ("claim alice's map is bob's", edit_map("alice", lambda m: m.update(owner="bob")), False),
        ("swap the two signatures", lambda d: [shutil.move(os.path.join(d, "maps", *x), os.path.join(d, "maps", *y))
                                               for x, y in ((("alice", "root.sig"), ("t",)), (("bob", "root.sig"), ("alice", "root.sig")),
                                                            (("t",), ("bob", "root.sig")))], False),
        ("edit the pinned SUMO term list", lambda d: open(os.path.join(d, TERMS), "a").write("Unicorn\n"), False),
        ("rewrite index.json top_root", lambda d: (lambda p, j: json.dump({**j, "top_root": "0" * 64}, open(p, "w")))(
            os.path.join(d, "index.json"), json.load(open(os.path.join(d, "index.json")))), False),
    ]
    all_ok = True
    for name, sabotage, want in rows:
        d = tempfile.mkdtemp()
        try:
            for x in ("maps", "sumo"):
                shutil.copytree(os.path.join(HERE, x), os.path.join(d, x))
            for x in ("index.json", "allowed_signers"):
                shutil.copy(os.path.join(HERE, x), d)
            sabotage(d)
            got = verify(d, quiet=True)
        finally:
            shutil.rmtree(d)
        good = got == want
        all_ok &= good
        print(f"{'ok ' if good else 'BAD'}  {name:48} -> {'green' if got else 'red'} (expected {'green' if want else 'red'})")
    print("G1: every sabotage went red, baseline green" if all_ok else "G1 FAILED: a check cannot go red")
    return all_ok


if __name__ == "__main__":
    a = sys.argv[1:]
    cmd = a[0] if a else "verify"
    if cmd == "root":
        print(map_root(a[1], HERE))
    elif cmd == "sign":
        sign(a[1], a[2])
    elif cmd == "index":
        idx = build_index(HERE)
        json.dump(idx, open(os.path.join(HERE, "index.json"), "w"), indent=2)
        print(f"top_root {idx['top_root']}")
    elif cmd == "verify":
        sys.exit(0 if verify(HERE) else 1)
    elif cmd == "diff":
        diff(a[1], a[2])
    elif cmd == "concepts":
        concepts(HERE)
    elif cmd == "g1":
        sys.exit(0 if g1() else 1)
    else:
        print(__doc__)
        sys.exit(2)
