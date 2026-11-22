"""Hashing: what exactly gets signed. Changing anything here breaks every shipped root."""
from __future__ import annotations

import hashlib
import json

from .files import read_json
from .vocab import TERMS, load_terms

OPTIONAL = ("pubkey", "by", "same_as")
# pubkey  : this node IS an agent; its own ssh public key. Identity = this key, not the label.
# by      : id of the agent (in this map) that wrote this node; needs agent_sigs/<id>.sig
# same_as : ["owner:id", ...] this node is the same thing as that node. One side = claimed,
#           both sides = linked. Never inferred from matching labels or SUMO terms.


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def leaf(node: dict) -> str:
    """A node's leaf hash. The salt stops anyone guessing short hidden content."""
    fields = {k: node[k] for k in ("id", "label", "sumo", "content", "salt")}
    for k in OPTIONAL:                            # agent key, author, identity links: all owner-signed
        if k in node:
            fields[k] = node[k]
    canon = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha(b"\x00" + canon.encode())          # 0x00 = leaf, 0x01 = inner (no 2nd-preimage mixups)


def merkle(hashes: list[str]) -> str:
    if not hashes:
        return sha(b"")
    level = hashes
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [inner(a, b) for a, b in zip(level[::2], level[1::2])]
    return level[0]


def inner(a: str, b: str) -> str:
    return sha(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b))


def path_sides(i: int, n: int) -> list[str]:
    """Where the sibling sits at each level for leaf i of n, under merkle()'s rule that an
    odd level duplicates its last hash. "L" = sibling on the left, "R" = on the right."""
    if not 0 <= i < n:
        raise ValueError(f"leaf index {i} out of range for {n} leaves")
    out = []
    while n > 1:
        n += n % 2
        out.append("L" if i % 2 else "R")
        i, n = i // 2, n // 2
    return out


def merkle_path(hashes: list[str], i: int) -> list[dict]:
    """Audit path for hashes[i]: [{"hash": sibling, "side": "L"|"R"}, ...] bottom-up.
    Climbing it from hashes[i] gives merkle(hashes). A duplicated last hash is its own sibling."""
    path, level = [], list(hashes)
    path_sides(i, len(level))                     # range check
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        j = i ^ 1
        path.append({"hash": level[j], "side": "L" if j < i else "R"})
        level = [inner(a, b) for a, b in zip(level[::2], level[1::2])]
        i //= 2
    return path


def climb(h: str, path: list[dict], i: int, n: int) -> str:
    """Recompute the root from leaf hash h at index i of n along `path`. Raises ValueError if
    the path's shape or flags don't match what merkle() would have built for (i, n)."""
    sides = path_sides(i, n)
    if len(path) != len(sides):
        raise ValueError(f"audit path has {len(path)} steps, {len(sides)} expected for leaf {i} of {n}")
    for k, (step, want) in enumerate(zip(path, sides)):
        if step.get("side") != want:
            raise ValueError(f"audit path step {k}: side {step.get('side')!r}, expected {want!r}")
        sib = step["hash"]
        if len(sib) != 64 or bytes.fromhex(sib).hex() != sib:
            raise ValueError(f"audit path step {k}: not a sha256 hex digest")
        if n % 2 and i == n - 1 and sib != h:     # lone last hash: paired with itself
            raise ValueError(f"audit path step {k}: odd level must duplicate the last hash")
        h = inner(sib, h) if want == "L" else inner(h, sib)
        n = (n + n % 2) // 2
        i //= 2
    return h


def head(owner: str, terms_sha: str) -> str:
    """The owner and the vocabulary version are part of what gets signed."""
    return sha(json.dumps({"owner": owner, "sumo_terms_sha": terms_sha}, sort_keys=True).encode())


def map_root_of(m: dict, base: str, where: str = "map") -> str:
    terms, terms_sha = load_terms(base)
    for n in m["nodes"]:
        if n["sumo"] not in terms:
            raise ValueError(f"{where}: node {n['id']!r} tagged {n['sumo']!r}, not in pinned {TERMS}")
    nodes = sorted(m["nodes"], key=lambda n: n["id"])
    return merkle([head(m["owner"], terms_sha)] + [leaf(n) for n in nodes])


def map_root(path: str, base: str) -> str:
    m = read_json(path)
    return map_root_of(m, base, path)
