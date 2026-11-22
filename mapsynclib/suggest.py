"""Offline tag suggester: a pinned word -> SUMO term lexicon, and a human who confirms.

    sumo/lexicon.txt   `word Term [weight]` (weight defaults to 1; `#` starts a comment)

No LLM, no network, no randomness: the same text and lexicon always give the same ranking.
Text is split into words, each word is stemmed (`stem`), and every lexicon hit adds its
weight to its term. Ties go to the more specific term (more ancestors in the pinned
hierarchy), then alphabetically. The lexicon is validated against the vocabulary (every
Term must be a base or local term) and its sha256 is a leaf under top_root (`lexicon_sha`
in index.json), so everyone suggests from the same lexicon.

`tag` writes a tag only with an explicit yes, and never signs anything: the owner (and the
agent named in `by`, if any) must re-sign afterwards.
"""
from __future__ import annotations

import os
import re

from . import REPO
from .files import read_bytes
from .hashing import sha
from .vocab import Vocab, load_vocab
from .world import load, owners, save

LEXICON = os.path.join("sumo", "lexicon.txt")
WORD = re.compile(r"[a-z0-9]+")


class LexiconError(ValueError):
    """sumo/lexicon.txt is malformed or names a term the vocabulary doesn't know."""


def stem(word: str) -> str:
    """Deliberately simple: lowercase; strip -ing, -ed, -es or plural -s; then a trailing e
    and a doubled final consonant, so note/notes, plan/planning, ship/shipped meet."""
    w = word.lower()
    for suf, keep in (("ing", 3), ("ed", 3), ("es", 3), ("s", 3)):
        if w.endswith(suf) and len(w) - len(suf) >= keep and not (suf == "s" and w.endswith("ss")):
            w = w[: -len(suf)]
            break
    if len(w) > 3 and w.endswith("e"):
        w = w[:-1]
    if len(w) > 3 and w[-1] == w[-2] and w[-1] not in "aeiou":
        w = w[:-1]
    return w


def words(text: str) -> list[str]:
    """The distinct stems of text, in order of first appearance."""
    out = []
    for w in WORD.findall(text.lower()):
        s = stem(w)
        if s not in out:
            out.append(s)
    return out


class Lexicon:
    def __init__(self, raw: bytes, vocab: Vocab, where: str = LEXICON):
        self.sha = sha(raw)
        self.vocab = vocab
        self.entries: dict[str, dict[str, float]] = {}   # stem -> {term: weight}
        self.count = 0
        seen: dict[tuple[str, str], int] = {}
        for i, ln in enumerate(raw.decode("utf-8").splitlines(), 1):
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            parts = ln.split()
            if len(parts) not in (2, 3) or not WORD.fullmatch(parts[0].lower()):
                raise LexiconError(f"{where}:{i}: expected `word Term [weight]`, got {ln!r}")
            word, term = parts[0], parts[1]
            if not vocab.known(term):
                raise LexiconError(f"{where}:{i}: {term!r} is not a base or local term")
            try:
                weight = float(parts[2]) if len(parts) == 3 else 1.0
            except ValueError:
                raise LexiconError(f"{where}:{i}: weight {parts[2]!r} is not a number") from None
            if not weight > 0:
                raise LexiconError(f"{where}:{i}: weight must be positive")
            s = stem(word)
            if (s, term) in seen:
                raise LexiconError(f"{where}:{i}: duplicate: {word!r} -> {term} (stem {s!r}) "
                                   f"already on line {seen[(s, term)]}")
            seen[(s, term)] = i
            self.entries.setdefault(s, {})[term] = weight
            self.count += 1

    def terms(self) -> set[str]:
        return {t for ts in self.entries.values() for t in ts}

    def score(self, text: str) -> list[tuple[str, float]]:
        """[(term, score)] best first; ties: deeper in the hierarchy first, then by name."""
        sc: dict[str, float] = {}
        for w in words(text):
            for t, wt in self.entries.get(w, {}).items():
                sc[t] = sc.get(t, 0.0) + wt
        return sorted(sc.items(), key=lambda kv: (-kv[1], -len(self.vocab.ancestors(kv[0])), kv[0]))


def lexicon_path(base: str) -> str:
    return os.path.join(base, LEXICON)


def load_lexicon(base: str = REPO, vocab: Vocab | None = None) -> Lexicon | None:
    """The validated lexicon, or None if the world has no sumo/lexicon.txt."""
    p = lexicon_path(base)
    if not os.path.exists(p):
        return None
    return Lexicon(read_bytes(p), vocab or load_vocab(base))


def _need(base: str) -> Lexicon:
    lx = load_lexicon(base)
    if lx is None:
        raise ValueError(f"no {LEXICON} in {base}")
    return lx


def _fmt(score: float) -> str:
    return f"{score:g}"


def suggest_text(base: str, text: str, n: int = 5) -> list[str]:
    lx = _need(base)
    ranked = lx.score(text)[:n]
    if not ranked:
        return [f"no suggestion: no word of {text!r} is in {LEXICON}"]
    v = lx.vocab
    return [f"{t:22} {_fmt(s):>4}  ({' -> '.join(v.ancestors(t)) or 'top'})" for t, s in ranked]


def related(v: Vocab, a: str, b: str) -> bool:
    """Neither unknown, and one is_a the other."""
    return v.known(a) and v.known(b) and (v.is_a(a, b) or v.is_a(b, a))


def resolve_map(base: str, m: str) -> tuple[str, str]:
    """MAP as an owner name or a path to a map.json -> (owner, path)."""
    if os.sep not in m and not m.endswith(".json") and m in owners(base):
        return m, os.path.join(base, "maps", m, "map.json")
    p = m if os.path.isabs(m) or os.path.exists(m) else os.path.join(base, m)
    if not os.path.exists(p):
        raise ValueError(f"no map {m!r} (an owner name under {base}/maps, or a map.json path)")
    owner = os.path.basename(os.path.dirname(os.path.abspath(p)))
    return owner, p


def suggest_map(base: str, m: str) -> list[str]:
    """Each node: current tag, top suggestion, and MISMATCH? when the two are unrelated."""
    lx = _need(base)
    owner, _ = resolve_map(base, m)
    rows = []
    for nd in load(base, owner)["nodes"]:
        ranked = lx.score(f"{nd['label']} {nd['content']}")
        top, s = ranked[0] if ranked else ("-", 0)
        flag = ""
        if top == "-":
            flag = "(no suggestion)"
        elif top == nd["sumo"]:
            flag = "same"
        elif related(lx.vocab, top, nd["sumo"]):
            flag = "related"
        else:
            flag = "MISMATCH?"
        rows.append((f"{owner}:{nd['id']}", nd["sumo"], f"{top} {_fmt(s)}" if top != "-" else "-", flag))
    w = [max(len(r[k]) for r in rows) if rows else 0 for k in range(3)]
    return [f"{a:{w[0]}}  tag {b:{w[1]}}  suggest {c:{w[2]}}  {d}" for a, b, c, d in rows]


def tag(base: str, m: str, node_id: str, term: str, yes: bool = False) -> list[str]:
    """Retag one node. Without yes: only say what would happen. Never signs anything."""
    v = load_vocab(base)
    if not v.known(term):
        raise ValueError(f"unknown term {term!r} (not in sumo/terms.txt nor sumo/local.txt)")
    owner, path = resolve_map(base, m)
    mp = load(base, owner)
    nd = next((n for n in mp["nodes"] if n["id"] == node_id), None)
    if nd is None:
        raise KeyError(f"{owner} has no node {node_id!r}")
    ref = f"{owner}:{node_id}"
    if nd["sumo"] == term:
        return [f"{ref} is already tagged {term}; nothing to do"]
    if not yes:
        return [f"would retag {ref} ({nd['label']!r}): {nd['sumo']} -> {term}",
                "nothing written: pass --yes to write it"]
    old = nd["sumo"]
    nd["sumo"] = term
    save(base, owner, mp)
    out = [f"retagged {ref}: {old} -> {term}  ({path})",
           f"verify is now RED until {owner} re-signs: python3 mapsync.py sign {path} {owner.upper()}_KEY"]
    if "by" in nd:
        out.append(f"and agent {owner}:{nd['by']} must re-sign its node first: "
                   f"python3 mapsync.py agent-sign {path} {node_id} AGENT_KEY")
    out.append("then: python3 mapsync.py index && python3 mapsync.py log append")
    return out
