"""index.json: every (owner, root, sig) folded into one top_root; and `verify`."""
from __future__ import annotations

import json
import os

from .files import read_bytes, read_json, write_json
from .hashing import map_root, merkle, sha
from .identity import identity_checks
from .signing import sig_ok
from .vocab import load_terms, load_vocab
from .world import map_path, owners


def entry_hash(e: dict) -> str:
    """An index entry's leaf in the top tree (no 0x00 prefix: kept as shipped)."""
    return sha(json.dumps(e, sort_keys=True).encode())


def top_leaves(idx: dict) -> list[str]:
    """The top tree's leaves: one per map entry (sorted by owner), then the terms sha, then
    the vocab sha (hierarchy + local + disjoint) if the world has those files."""
    return ([entry_hash(e) for e in idx["maps"]] + [idx["sumo_terms_sha"]]
            + ([idx["vocab_sha"]] if "vocab_sha" in idx else []))


def build_index(base: str) -> dict:
    _, terms_sha = load_terms(base)
    vocab = load_vocab(base)                      # validates the hierarchy: invalid = ValueError
    entries = []
    for o in owners(base):
        root = map_root(map_path(base, o), base)
        sig = read_bytes(os.path.join(base, "maps", o, "root.sig")).decode()
        e = {"owner": o, "root": root, "sig_sha": sha(sig.encode())}
        kp = os.path.join(base, "maps", o, "keys.jsonl")
        if os.path.exists(kp):                    # only when present: old worlds hash as before
            e["keys_sha"] = sha(read_bytes(kp))
        entries.append(e)
    idx = {"sumo_terms_sha": terms_sha}
    if vocab.present:                             # only when the files exist: old worlds hash as before
        idx["vocab_sha"] = vocab.sha
    idx["maps"] = entries
    idx["top_root"] = merkle(top_leaves(idx))
    return idx


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
    from .keys import key_checks
    ok &= key_checks(base, say)                   # no keys.jsonl anywhere: a note, green
    stored = read_json(os.path.join(base, "index.json"))
    same = stored == fresh
    say(f"{'ok ' if same else 'RED'}  index.json top_root {stored.get('top_root', '?')[:16]}… "
        f"{'matches' if same else 'does NOT match'} a rebuild from the maps")
    ok &= same
    from .log import log_checks                   # log imports index; import late
    ok &= log_checks(base, say)
    from .anchor import anchor_checks, anchors_dir
    if os.path.isdir(anchors_dir(base)):          # receipts: invalid = RED, unwitnessed head = note
        ok &= anchor_checks(base, say)
    say("GREEN: every map signed by its owner, index matches" if ok else "RED")
    return ok
