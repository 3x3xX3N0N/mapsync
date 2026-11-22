"""claims: everyone's signed claims about the same thing, side by side and attributed.

Nodes joined by same_as (LINKED = both sides say so, CLAIMED = one side; either way an
edge) form identity clusters: the connected components. For each cluster `claims` shows
every member's owner:id, label, SUMO tag, content, author and the signed map root it sits
in, then compares each pair's tags under the pinned hierarchy (sumo/*.txt):

    AGREE           same term
    REFINES         one is_a the other (one claim is more specific)
    CONTRADICTION   the terms are disjoint (sumo/disjoint.txt, inherited)
    DIFFERENT KIND  none of the above (or a term the vocabulary doesn't know)

A contradiction is a finding, not an error: nothing is merged, no side wins, and `verify`
is unaffected. `claims --strict` exits 1 on any CONTRADICTION, for CI-style gates. This
is a disjointness check over a small pinned hierarchy, not a SUMO reasoner.
"""
from __future__ import annotations

import json

from .hashing import map_root, sha
from .keys import agent_lineages
from .signing import sig_ok
from .vocab import VocabError, load_vocab
from .world import load, map_path, owners

AGREE, REFINES, CONTRADICTION, DIFFERENT = "AGREE", "REFINES", "CONTRADICTION", "DIFFERENT KIND"
VERDICTS = (AGREE, REFINES, CONTRADICTION, DIFFERENT)


def compare(v, a: str, b: str) -> tuple[str, str]:
    """(verdict, why) for two SUMO tags."""
    if a == b:
        return AGREE, f"both {a}"
    if v is None or not (v.known(a) and v.known(b)):
        unk = [t for t in (a, b) if v is None or not v.known(t)]
        return DIFFERENT, f"{', '.join(unk)} not in the vocabulary"
    if v.is_a(a, b):
        return REFINES, f"{a} is a {b}"
    if v.is_a(b, a):
        return REFINES, f"{b} is a {a}"
    if v.disjoint(a, b):
        ua, ub = {a, *v.ancestors(a)}, {b, *v.ancestors(b)}
        pair = next(f"{x} / {y}" for x, y in v.pairs
                    if (x in ua and y in ub) or (x in ub and y in ua))
        return CONTRADICTION, f"{a} and {b} are disjoint ({pair})"
    return DIFFERENT, f"{a} and {b} are unrelated"


def _author(base: str, owner: str, n: dict, lineages: dict, agents: dict) -> dict:
    if "by" not in n:
        return {"by": None, "text": f"owner {owner}"}
    a = n["by"]
    if a in lineages:
        lin = lineages[a].id
    elif a in agents:
        lin = "key " + sha(agents[a]["pubkey"].encode())[:8]
    else:
        lin = "no key"
    return {"by": f"{owner}:{a}", "lineage": lin, "text": f"agent {owner}:{a} [{lin}]"}


def gather(base: str) -> dict:
    """{"clusters": [...], "counts": {verdict: n}} over every map under base."""
    try:
        v = load_vocab(base)
    except (VocabError, OSError):
        v = None
    nodes, links, roots = {}, {}, {}
    for o in owners(base):
        try:
            root = map_root(map_path(base, o), base)
            roots[o] = {"root": root, "signed": sig_ok(base, o, root)}
        except (ValueError, KeyError, OSError):
            roots[o] = {"root": None, "signed": False}
        nl = load(base, o)["nodes"]
        agents = {n["id"]: n for n in nl if "pubkey" in n}
        lineages = agent_lineages(base, o)
        for n in nl:
            ref = f"{o}:{n['id']}"
            nodes[ref] = {"ref": ref, "owner": o, "id": n["id"], "label": n["label"], "sumo": n["sumo"],
                          "content": n["content"], "author": _author(base, o, n, lineages, agents),
                          "root": roots[o]["root"], "signed": roots[o]["signed"]}
            links[ref] = [t for t in n.get("same_as", [])]
    adj: dict[str, set[str]] = {r: set() for r in nodes}
    for a, ts in links.items():
        for b in ts:
            if b in nodes:                        # a dangling target is verify's business
                adj[a].add(b)
                adj[b].add(a)
    seen, clusters = set(), []
    for r in sorted(nodes):
        if r in seen or not adj[r]:
            continue
        comp, stack = [], [r]
        seen.add(r)
        while stack:
            x = stack.pop()
            comp.append(x)
            for y in adj[x] - seen:
                seen.add(y)
                stack.append(y)
        comp.sort()
        pairs = []
        for i, a in enumerate(comp):
            for b in comp[i + 1:]:
                ab, ba = b in links[a], a in links[b]
                link = "LINKED" if ab and ba else "CLAIMED" if ab or ba else "via cluster"
                verdict, why = compare(v, nodes[a]["sumo"], nodes[b]["sumo"])
                pairs.append({"a": a, "b": b, "link": link, "verdict": verdict, "why": why})
        clusters.append({"members": [nodes[x] for x in comp], "pairs": pairs})
    counts = {k: sum(p["verdict"] == k for c in clusters for p in c["pairs"]) for k in VERDICTS}
    return {"clusters": clusters, "counts": counts,
            "vocabulary": "ok" if v is not None else "invalid (tags compared by name only)"}


def redacted(data: dict) -> dict:
    out = json.loads(json.dumps(data))
    for c in out["clusters"]:
        for m in c["members"]:
            m["content"] = "<hidden>"
    return out


def report(data: dict) -> list[str]:
    out = []
    for k, c in enumerate(data["clusters"], 1):
        ms = c["members"]
        out.append(f"cluster {k}: {', '.join(m['ref'] for m in ms)}")
        w = [max(len(f(m)) for m in ms) for f in (lambda m: m["ref"], lambda m: repr(m["label"]),
                                                  lambda m: m["sumo"])]
        for m in ms:
            root = (m["root"][:16] + "…") if m["root"] else "?"
            content = m["content"] if m["content"] == "<hidden>" else repr(m["content"])
            out.append(f"  {m['ref']:{w[0]}}  {m['label']!r:{w[1]}}  {m['sumo']:{w[2]}}  {content}")
            out.append(f"  {'':{w[0]}}  by {m['author']['text']}; in {m['owner']}'s root {root} "
                       f"({'signed' if m['signed'] else 'NOT validly signed'})")
        for p in c["pairs"]:
            out.append(f"  {p['a']} ~ {p['b']}  {p['link']}: {p['verdict']}  ({p['why']})")
    n = data["counts"]
    out.append(f"{len(data['clusters'])} cluster(s): " + ", ".join(f"{n[k]} {k}" for k in VERDICTS))
    if data["vocabulary"] != "ok":
        out.append(f"note: vocabulary {data['vocabulary']}")
    if n[CONTRADICTION]:
        out.append("contradictions are reported side by side, never merged; they don't affect verify")
    return out


def claims(base: str, as_json: bool = False, redact: bool = False, strict: bool = False) -> int:
    data = gather(base)
    if redact:
        data = redacted(data)
    if as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print("\n".join(report(data)))
    return 1 if strict and data["counts"][CONTRADICTION] else 0
