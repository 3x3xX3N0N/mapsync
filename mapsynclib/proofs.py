"""Inclusion proofs: show one node of one map, and nothing else.

A proof carries the revealed node, the Merkle audit path from its leaf to the owner's map
root (sibling hashes + which side they sit on), a second path for the map head (owner +
vocabulary sha), the owner's root.sig, the pinned term list, and the path from the owner's
index entry up to top_root. `check_proof` recomputes all of it from the proof alone: the
other nodes appear only as hashes, and their salts keep them unguessable.
"""
from __future__ import annotations

import os
import tempfile

from .files import read_bytes, read_json
from .hashing import OPTIONAL, climb, head, leaf, merkle_path, sha
from .index import build_index, entry_hash, top_leaves
from .signing import NAMESPACE, ssh_verify
from .vocab import TERMS, load_terms
from .world import load

FORMAT = "mapsync-proof/1"
REQUIRED = ("id", "label", "sumo", "content", "salt")


def prove(base: str, owner: str, node_id: str) -> dict:
    """A self-contained proof that `owner`'s signed map contains node `node_id`."""
    m = load(base, owner)
    if m["owner"] != owner:
        raise ValueError(f"maps/{owner}/map.json says owner {m['owner']!r}")
    terms_raw = read_bytes(os.path.join(base, TERMS))
    terms, terms_sha = load_terms(base)
    nodes = sorted(m["nodes"], key=lambda n: n["id"])
    ids = [n["id"] for n in nodes]
    if node_id not in ids:
        raise KeyError(f"{owner} has no node {node_id!r} (has: {', '.join(ids)})")
    for n in nodes:
        if n["sumo"] not in terms:
            raise ValueError(f"{owner}:{n['id']} tagged {n['sumo']!r}, not in the pinned terms")
    leaves = [head(owner, terms_sha)] + [leaf(n) for n in nodes]
    i = ids.index(node_id) + 1                    # leaf 0 is the head
    idx = build_index(base)
    stored = read_json(os.path.join(base, "index.json"))
    if stored.get("top_root") != idx["top_root"]:
        raise ValueError("index.json does not match the maps; run `index` first")
    j = [e["owner"] for e in idx["maps"]].index(owner)
    top = top_leaves(idx)
    return {
        "format": FORMAT,
        "owner": owner,
        "node": nodes[i - 1],
        "leaf": leaves[i],
        "map": {
            "head": {"owner": owner, "sumo_terms_sha": terms_sha},
            "head_hash": leaves[0],
            "leaf_count": len(leaves),
            "leaf_index": i,
            "path": merkle_path(leaves, i),
            "head_path": merkle_path(leaves, 0),
            "root": idx["maps"][j]["root"],
            "root_sig": read_bytes(os.path.join(base, "maps", owner, "root.sig")).decode(),
        },
        "sumo_terms": terms_raw.decode(),
        "index": {
            "entry": idx["maps"][j],
            "entry_index": j,
            "leaf_count": len(top),
            "path": merkle_path(top, j),
            "terms_path": merkle_path(top, len(top) - 1),
            "top_root": idx["top_root"],
        },
    }


def _sig_ok(allowed_signers: str, owner: str, sig: str, root: str) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".sig", delete=False) as f:
        f.write(sig)
    try:
        return ssh_verify(allowed_signers, owner, NAMESPACE, f.name, root)
    finally:
        os.unlink(f.name)


def _check(p: dict, allowed_signers: str, top_root: str | None) -> str | None:
    if p.get("format") != FORMAT:
        return f"unknown proof format {p.get('format')!r}"
    owner, node, mp, ix = p["owner"], p["node"], p["map"], p["index"]
    # 1. the revealed node is exactly what was hashed
    extra = set(node) - set(REQUIRED) - set(OPTIONAL)
    if extra or not set(REQUIRED) <= set(node):
        return f"revealed node has unexpected or missing fields: {sorted(extra) or sorted(set(REQUIRED) - set(node))}"
    if leaf(node) != p["leaf"]:
        return "revealed node does not hash to the claimed leaf"
    # 2. vocabulary and head: who owns this map, under which term list
    terms_sha = sha(p["sumo_terms"].encode())
    if mp["head"] != {"owner": owner, "sumo_terms_sha": terms_sha}:
        return "map head does not match the claimed owner and the included term list"
    terms = {ln.strip() for ln in p["sumo_terms"].splitlines() if ln.strip() and not ln.startswith("#")}
    if node["sumo"] not in terms:
        return f"node tagged {node['sumo']!r}, not in the pinned term list"
    if head(owner, terms_sha) != mp["head_hash"]:
        return "head hash does not match the head inputs"
    # 3. both audit paths climb to the same map root
    n, i = mp["leaf_count"], mp["leaf_index"]
    if not 1 <= i < n:
        return f"leaf index {i} is not a node position (1..{n - 1})"
    try:
        r_node = climb(p["leaf"], mp["path"], i, n)
        r_head = climb(mp["head_hash"], mp["head_path"], 0, n)
    except ValueError as e:
        return f"map audit path: {e}"
    if r_node != mp["root"]:
        return "node audit path does not reach the map root"
    if r_head != mp["root"]:
        return "head audit path does not reach the map root"
    # 4. the owner signed that root
    if not _sig_ok(allowed_signers, owner, mp["root_sig"], mp["root"]):
        return f"root.sig is not {owner}'s signature on the map root"
    # 5. the owner's entry and the term list sit under top_root
    e = ix["entry"]
    want = {"owner": owner, "root": mp["root"], "sig_sha": sha(mp["root_sig"].encode())}
    if isinstance(e, dict) and isinstance(e.get("keys_sha"), str) and len(e["keys_sha"]) == 64:
        want["keys_sha"] = e["keys_sha"]          # the owner's key chain, committed (not revealed)
    if e != want:
        return "index entry does not match the owner, map root and signature"
    m, j = ix["leaf_count"], ix["entry_index"]
    if not 0 <= j < m - 1:
        return f"entry index {j} is not a map position (0..{m - 2})"
    try:
        t_entry = climb(entry_hash(e), ix["path"], j, m)
        t_terms = climb(terms_sha, ix["terms_path"], m - 1, m)
    except ValueError as err:
        return f"index audit path: {err}"
    if t_entry != ix["top_root"] or t_terms != ix["top_root"]:
        return "index audit paths do not reach top_root"
    if top_root is not None and ix["top_root"] != top_root:
        return f"top_root {ix['top_root'][:16]}… is not the expected {top_root[:16]}…"
    return None


def check_proof(proof: dict, allowed_signers_path: str, top_root: str | None = None) -> tuple[bool, str]:
    """(True, summary) if the proof holds on its own, else (False, reason). Needs only the
    proof and an allowed_signers file; `top_root` pins the expected index top."""
    try:
        why = _check(proof, allowed_signers_path, top_root)
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        why = f"malformed proof: {type(e).__name__} {e}"
    if why:
        return False, why
    n = proof["node"]
    return True, (f"{proof['owner']}:{n['id']} ({n['label']!r}, {n['sumo']}) is in {proof['owner']}'s signed map "
                  f"{proof['map']['root'][:16]}…, under top_root {proof['index']['top_root'][:16]}…")
