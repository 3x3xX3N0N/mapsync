"""The pinned SUMO vocabulary. Its sha256 is part of every map root and the top root."""
from __future__ import annotations

import hashlib
import os

from .files import read_bytes

TERMS = os.path.join("sumo", "terms.txt")


def load_terms(base: str) -> tuple[set[str], str]:
    raw = read_bytes(os.path.join(base, TERMS))
    terms = {ln.strip() for ln in raw.decode().splitlines() if ln.strip() and not ln.startswith("#")}
    return terms, hashlib.sha256(raw).hexdigest()


def concepts_report(base: str) -> list[str]:
    """Same meaning under different words: group every node by its SUMO term."""
    from .world import load, owners
    by: dict[str, list[str]] = {}
    for o in owners(base):
        for n in load(base, o)["nodes"]:
            by.setdefault(n["sumo"], []).append(f"{o}:{n['label']!r}")
    return [f"{term:20} {', '.join(by[term])}" for term in sorted(by)]


def concepts(base: str) -> None:
    for line in concepts_report(base):
        print(line)
