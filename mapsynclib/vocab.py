"""The pinned SUMO vocabulary: the base term list, plus a pinned hierarchy on top of it.

    sumo/terms.txt      base SUMO term names. Its sha256 is in every map head and the top root.
    sumo/hierarchy.txt  `Child Parent`: SUMO subclass edges among base terms (several parents ok)
    sumo/local.txt      `NewTerm Parent`: local subclasses (one parent each; parent = base or local)
    sumo/disjoint.txt   `A B`: nothing is both an A and a B; inherited by every subclass

`#` starts a comment; blank lines are ignored. The three hierarchy files are validated
together (cycle, unknown term, duplicate, redefined base term, a class under two disjoint
classes: all errors) and hashed together into `vocab_sha`:

    vocab_sha = sha256(b"mapsync-vocab/1\\n" + for f in (hierarchy, local, disjoint):
                       b"<f>.txt <len>\\n" + raw bytes of f)     (a missing file = 0 bytes)

A map head pins vocab_sha only if the map tags a node with a local term, so maps that use
base terms only hash exactly as before. The index commits to vocab_sha whenever any of the
three files exists.
"""
from __future__ import annotations

import hashlib
import os
import re

from . import REPO
from .files import read_bytes

TERMS = os.path.join("sumo", "terms.txt")
HIERARCHY = os.path.join("sumo", "hierarchy.txt")
LOCAL = os.path.join("sumo", "local.txt")
DISJOINT = os.path.join("sumo", "disjoint.txt")
VOCAB_FILES = (HIERARCHY, LOCAL, DISJOINT)
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")


class VocabError(ValueError):
    """A vocabulary file is malformed or inconsistent."""


def load_terms(base: str) -> tuple[set[str], str]:
    raw = read_bytes(os.path.join(base, TERMS))
    return parse_terms(raw.decode()), hashlib.sha256(raw).hexdigest()


def parse_terms(text: str) -> set[str]:
    return {ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")}


def vocab_sha_of(raws: dict[str, bytes]) -> str:
    """sha256 over the framed concatenation of hierarchy + local + disjoint (see module doc)."""
    h = hashlib.sha256(b"mapsync-vocab/1\n")
    for f in VOCAB_FILES:
        raw = raws.get(f, b"")
        h.update(f"{os.path.basename(f)} {len(raw)}\n".encode() + raw)
    return h.hexdigest()


def _pairs(text: str, where: str) -> list[tuple[int, str, str]]:
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        ln = ln.split("#", 1)[0].strip()
        if not ln:
            continue
        parts = ln.split()
        if len(parts) != 2 or not all(NAME.match(p) for p in parts):
            raise VocabError(f"{where}:{i}: expected two term names `A B`, got {ln!r}")
        out.append((i, parts[0], parts[1]))
    return out


class Vocab:
    """Base terms + local terms, their parents, and the disjointness axioms."""

    def __init__(self, base_terms: set[str], raws: dict[str, bytes]):
        self.base = set(base_terms)
        self.present = bool(raws)
        self.sha = vocab_sha_of(raws)
        self.parents: dict[str, list[str]] = {t: [] for t in self.base}
        self.local: list[str] = []                # declaration order
        self.pairs: list[tuple[str, str]] = []
        text = {f: raws.get(f, b"").decode("utf-8") for f in VOCAB_FILES}
        local = _pairs(text[LOCAL], LOCAL)
        declared: dict[str, int] = {}
        for i, t, _ in local:                     # declare first: a parent may come later
            if t in self.base:
                raise VocabError(f"{LOCAL}:{i}: {t!r} is a base term; local.txt may not redefine it")
            if t in declared:
                raise VocabError(f"{LOCAL}:{i}: duplicate: {t!r} already declared on line {declared[t]}")
            declared[t] = i
            self.local.append(t)
            self.parents[t] = []
        for i, t, p in local:
            if p not in self.parents:
                raise VocabError(f"{LOCAL}:{i}: {t!r} has unknown parent {p!r}")
            self.parents[t].append(p)
        seen = set()
        for i, c, p in _pairs(text[HIERARCHY], HIERARCHY):
            for x in (c, p):
                if x not in self.base:
                    raise VocabError(f"{HIERARCHY}:{i}: {x!r} is not a base term in {TERMS}")
            if (c, p) in seen:
                raise VocabError(f"{HIERARCHY}:{i}: duplicate edge {c} {p}")
            seen.add((c, p))
            self.parents[c].append(p)
        self._check_acyclic()
        seen_pairs = set()
        for i, a, b in _pairs(text[DISJOINT], DISJOINT):
            for x in (a, b):
                if x not in self.parents:
                    raise VocabError(f"{DISJOINT}:{i}: unknown term {x!r}")
            if a == b:
                raise VocabError(f"{DISJOINT}:{i}: a class can't be disjoint from itself ({a})")
            if frozenset((a, b)) in seen_pairs:
                raise VocabError(f"{DISJOINT}:{i}: duplicate pair {a} {b}")
            seen_pairs.add(frozenset((a, b)))
            self.pairs.append((a, b))
        for t in self.parents:                    # nothing may be under two disjoint classes
            up = [t] + self.ancestors(t)
            for a, b in self.pairs:
                if a in up and b in up:
                    raise VocabError(f"inconsistent: {t} is a {a} and a {b}, declared disjoint in {DISJOINT}")

    def _check_acyclic(self) -> None:
        state: dict[str, int] = {}                # 1 = on the stack, 2 = done

        def visit(t: str, path: list[str]) -> None:
            if state.get(t) == 2:
                return
            if state.get(t) == 1:
                cyc = path[path.index(t):] + [t]
                raise VocabError(f"subclass cycle: {' -> '.join(cyc)}")
            state[t] = 1
            for p in self.parents[t]:
                visit(p, path + [t])
            state[t] = 2
        for t in sorted(self.parents):
            visit(t, [])

    # -- queries ---------------------------------------------------------------------
    def known(self, term: str) -> bool:
        return term in self.parents

    def is_local(self, term: str) -> bool:
        return term in self.parents and term not in self.base

    def _need(self, term: str) -> None:
        if term not in self.parents:
            raise KeyError(f"unknown term {term!r}")

    def ancestors(self, term: str) -> list[str]:
        """Every strict superclass of term, nearest first (breadth-first, no repeats)."""
        self._need(term)
        out, frontier = [], list(self.parents[term])
        while frontier:
            nxt = []
            for p in frontier:
                if p not in out:
                    out.append(p)
                    nxt += self.parents[p]
            frontier = nxt
        return out

    def is_a(self, a: str, b: str) -> bool:
        """a is b or a subclass (direct or inherited) of b."""
        self._need(b)
        return a == b or b in self.ancestors(a)

    def disjoint(self, a: str, b: str) -> bool:
        """Nothing can be both an a and a b: some superclass of each (or itself) is declared disjoint."""
        ua, ub = {a, *self.ancestors(a)}, {b, *self.ancestors(b)}
        return any((x in ua and y in ub) or (x in ub and y in ua) for x, y in self.pairs)

    def children(self, term: str) -> list[str]:
        return sorted(t for t, ps in self.parents.items() if term in ps)


def parse_vocab(terms_text: str, raws: dict[str, bytes]) -> Vocab:
    """A Vocab from file contents (as in a proof): raws maps VOCAB_FILES paths to bytes."""
    return Vocab(parse_terms(terms_text), raws)


def vocab_raws(base: str) -> dict[str, bytes]:
    """The vocabulary files that exist under base (missing ones are absent from the dict)."""
    return {f: read_bytes(os.path.join(base, f)) for f in VOCAB_FILES if os.path.exists(os.path.join(base, f))}


def load_vocab(base: str = REPO) -> Vocab:
    """Load and validate every vocabulary file under base. Raises VocabError (a ValueError)."""
    terms, _ = load_terms(base)
    return Vocab(terms, vocab_raws(base))


def ancestors(term: str, base: str = REPO) -> list[str]:
    return load_vocab(base).ancestors(term)


def is_a(a: str, b: str, base: str = REPO) -> bool:
    return load_vocab(base).is_a(a, b)


def disjoint(a: str, b: str, base: str = REPO) -> bool:
    return load_vocab(base).disjoint(a, b)


# -- concepts ------------------------------------------------------------------------

def _tagged(base: str) -> dict[str, list[str]]:
    from .world import load, owners
    by: dict[str, list[str]] = {}
    for o in owners(base):
        for n in load(base, o)["nodes"]:
            by.setdefault(n["sumo"], []).append(f"{o}:{n['label']!r}")
    return by


def concepts_report(base: str) -> list[str]:
    """Same meaning under different words: group every node by its SUMO term (flat)."""
    by = _tagged(base)
    return [f"{term:20} {', '.join(by[term])}" for term in sorted(by)]


def concepts_tree(base: str) -> list[str]:
    """The used terms under their ancestors, each with the labels tagged with exactly it.
    `*` marks a local term, `?` a tag the vocabulary doesn't know; `[N in all]` counts the
    nodes at or below a term when its subtree holds more than its own nodes. A term with
    several parents appears under each."""
    by = _tagged(base)
    v = load_vocab(base)
    shown = set()
    for t in by:
        if v.known(t):
            shown |= {t, *v.ancestors(t)}
    under: dict[str, list[str]] = {}
    for t in shown:
        for p in v.parents[t]:
            under.setdefault(p, []).append(t)
    roots = sorted(t for t in shown if not v.parents[t]) + sorted(t for t in by if not v.known(t))

    def total(t: str) -> int:
        return len({x for s in [t] + [d for d in shown if t in v.ancestors(d)] for x in by.get(s, [])})

    rows: list[tuple[str, str]] = []

    def walk(t: str, depth: int) -> None:
        name = "  " * depth + t + ("*" if v.is_local(t) else "") + ("?" if not v.known(t) else "")
        mine = by.get(t, [])
        line = ', '.join(mine) if mine else '-'
        n = total(t) if v.known(t) else len(mine)
        if n != len(mine):
            line += f"  [{n} in all]"
        rows.append((name, line))
        for c in sorted(under.get(t, [])):
            walk(c, depth + 1)
    for r in roots:
        walk(r, 0)
    w = max([20] + [len(nm) for nm, _ in rows])
    return [f"{nm:{w}} {line}" for nm, line in rows]


def concepts(base: str, flat: bool = False) -> None:
    for line in (concepts_report(base) if flat else concepts_tree(base)):
        print(line)


def vocab_report(base: str, term: str | None = None) -> tuple[bool, list[str]]:
    """`vocab`: validate the files and summarise; `vocab TERM`: its ancestors and disjoint classes."""
    try:
        v = load_vocab(base)
    except (VocabError, OSError, UnicodeDecodeError) as e:
        return False, [f"RED  vocabulary: {e}"]
    if term is None:
        return True, [f"ok   vocabulary: {len(v.base)} base terms, {len(v.local)} local terms, "
                      f"{sum(len(v.parents[t]) for t in v.base)} hierarchy edges, {len(v.pairs)} disjoint pairs",
                      f"     vocab_sha {v.sha}" + ("" if v.present else " (no hierarchy files: not committed)")]
    if not v.known(term):
        return False, [f"unknown term {term!r}"]
    no = sorted(t for t in v.parents if v.disjoint(term, t))
    return True, [f"{term} ({'local' if v.is_local(term) else 'base'})",
                  f"  is a:          {' -> '.join(v.ancestors(term)) or '(top)'}",
                  f"  subclasses:    {', '.join(t for t in sorted(v.parents) if t != term and v.is_a(t, term)) or '-'}",
                  f"  disjoint with: {', '.join(no) or '-'}"]
