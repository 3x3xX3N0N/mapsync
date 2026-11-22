"""sync-check: are two worlds in sync? Compare top roots; if not, walk down.

Level 1: top_root. Level 2: which owners were added, removed, or have a different map root
(or the same root re-signed). Level 3: for a changed owner, which node ids differ, when both
sides have the maps. A world is a directory (with index.json and maps/) or an index.json path.
"""
from __future__ import annotations

import os

from .files import read_json
from .index import build_index
from .world import load, node_diff


def resolve(p: str) -> tuple[str, str]:
    """(base dir, index.json path) for a world dir or an index.json file."""
    p = os.path.abspath(p)
    if os.path.isdir(p):
        return p, os.path.join(p, "index.json")
    return os.path.dirname(p), p


def _maps_of(base: str, owner: str) -> dict | None:
    try:
        return load(base, owner)
    except (FileNotFoundError, ValueError):
        return None


def _stale(base: str, idx: dict) -> bool:
    try:
        return build_index(base) != idx
    except (FileNotFoundError, ValueError, KeyError):
        return True


def sync_report(a: str, b: str) -> tuple[bool, list[str]]:
    """(in_sync, lines) comparing world/index `a` (here) with `b` (there)."""
    (ba, ia), (bb, ib) = resolve(a), resolve(b)
    A, B = read_json(ia), read_json(ib)
    out = []
    for name, base, idx in (("here", ba, A), ("there", bb, B)):
        if os.path.isdir(os.path.join(base, "maps")) and _stale(base, idx):
            out.append(f"warning: {name} ({base}) index.json does not match its maps; run `index` and `verify`")
    if A["top_root"] == B["top_root"]:
        return True, out + [f"IN SYNC  top_root {A['top_root'][:16]}…"]
    out.append(f"OUT OF SYNC  top_root here {A['top_root'][:16]}… vs there {B['top_root'][:16]}…")
    if A["sumo_terms_sha"] != B["sumo_terms_sha"]:
        out.append(f"! vocabulary differs: sumo_terms_sha {A['sumo_terms_sha'][:16]}… vs "
                   f"{B['sumo_terms_sha'][:16]}… (every root changes with it)")
    if A.get("vocab_sha") != B.get("vocab_sha"):
        out.append(f"! vocabulary hierarchy differs: vocab_sha {str(A.get('vocab_sha'))[:16]}… vs "
                   f"{str(B.get('vocab_sha'))[:16]}… (only maps using local terms change root with it)")
    ea = {e["owner"]: e for e in A["maps"]}
    eb = {e["owner"]: e for e in B["maps"]}
    for o in sorted(ea.keys() | eb.keys()):
        if o not in eb:
            out.append(f"- {o}  only here")
        elif o not in ea:
            out.append(f"+ {o}  only there")
        elif ea[o]["root"] != eb[o]["root"]:
            out.append(f"~ {o}  root {ea[o]['root'][:16]}… vs {eb[o]['root'][:16]}…")
            ma, mb = _maps_of(ba, o), _maps_of(bb, o)
            if ma is None or mb is None:
                out.append(f"    (node level unavailable: {o}'s map.json is missing on one side)")
                continue
            what = {"-": "only here", "+": "only there", "~": "differs"}
            nodes = node_diff(ma, mb)
            out += [f"    {mark} {o}:{i}  {what[mark]}" for mark, i in nodes]
            if not nodes:
                out.append("    (no node differs: the map head changed — owner name or vocabulary)")
        elif ea[o]["sig_sha"] != eb[o]["sig_sha"]:
            out.append(f"~ {o}  same root, different signature (re-signed)")
        elif ea[o].get("keys_sha") != eb[o].get("keys_sha"):
            out.append(f"~ {o}  same root and signature, different key chain (maps/{o}/keys.jsonl)")
    return False, out
