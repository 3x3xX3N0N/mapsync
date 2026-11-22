"""index.json: every (owner, root, sig) folded into one top_root; and `verify`."""
from __future__ import annotations

import json
import os

from .files import read_bytes, read_json, write_json
from .hashing import map_root, merkle, sha
from .identity import identity_checks
from .signing import sig_ok
from .vocab import load_terms
from .world import map_path, owners


def entry_hash(e: dict) -> str:
    """An index entry's leaf in the top tree (no 0x00 prefix: kept as shipped)."""
    return sha(json.dumps(e, sort_keys=True).encode())


def top_leaves(idx: dict) -> list[str]:
    """The top tree's leaves: one per map entry (sorted by owner), then the terms sha."""
    return [entry_hash(e) for e in idx["maps"]] + [idx["sumo_terms_sha"]]


def build_index(base: str) -> dict:
    _, terms_sha = load_terms(base)
    entries = []
    for o in owners(base):
        root = map_root(map_path(base, o), base)
        sig = read_bytes(os.path.join(base, "maps", o, "root.sig")).decode()
        entries.append({"owner": o, "root": root, "sig_sha": sha(sig.encode())})
    top = merkle(top_leaves({"maps": entries, "sumo_terms_sha": terms_sha}))
    return {"sumo_terms_sha": terms_sha, "maps": entries, "top_root": top}


def write_index(base: str) -> dict:
    idx = build_index(base)
    write_json(os.path.join(base, "index.json"), idx, indent=2)
    return idx


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
    ok &= identity_checks(base, say)
    stored = read_json(os.path.join(base, "index.json"))
    same = stored == fresh
    say(f"{'ok ' if same else 'RED'}  index.json top_root {stored.get('top_root', '?')[:16]}… "
        f"{'matches' if same else 'does NOT match'} a rebuild from the maps")
    ok &= same
    say("GREEN: every map signed by its owner, index matches" if ok else "RED")
    return ok
