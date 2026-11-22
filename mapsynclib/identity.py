"""Identity: agent-authored nodes carry the agent's signature; same_as links; `names`."""
from __future__ import annotations

from .hashing import sha
from .keys import agent_lineages
from .signing import agent_sig_ok
from .world import load, owners


def identity_checks(base: str, say) -> bool:
    """Agent-authored nodes carry the agent's own signature; same_as targets exist."""
    ok = True
    exists = {f"{o}:{n['id']}" for o in owners(base) for n in load(base, o)["nodes"]}
    for o in owners(base):
        nodes = load(base, o)["nodes"]
        agents = {n["id"]: n for n in nodes if "pubkey" in n}
        lineages = agent_lineages(base, o)        # {} without keys.jsonl: the map's pubkey only
        for n in nodes:
            if "by" in n:
                why = agent_sig_ok(base, o, n, agents, lineages.get(n["by"]))
                say(f"{'ok ' if why is None else 'RED'}  {o}:{n['id']} written by agent {o}:{n['by']}"
                    + ("" if why is None else f": {why}"))
                ok &= why is None
            for t in n.get("same_as", []):
                if t not in exists:
                    say(f"RED  {o}:{n['id']} same_as {t}: no such node")
                    ok = False
    return ok


def name_pairs(base: str) -> list[tuple[str, str, str, str]]:
    """(label, a, b, status) for each same-label pair across owners.
    status is LINKED (mutual same_as), CLAIMED (one side) or COLLISION."""
    by_label, links, _ = _gather(base)
    out = []
    for label, refs in sorted(by_label.items()):
        if len({r.split(":")[0] for r in refs}) < 2:
            continue
        for i, a in enumerate(refs):
            for b in refs[i + 1:]:
                mutual = b in links[a] and a in links[b]
                st = "LINKED" if mutual else "CLAIMED" if (b in links[a] or a in links[b]) else "COLLISION"
                out.append((label, a, b, st))
    return out


def _gather(base: str):
    by_label: dict[str, list[str]] = {}
    links: dict[str, set[str]] = {}
    keys: dict[str, str] = {}
    for o in owners(base):
        lineages = agent_lineages(base, o)
        for n in load(base, o)["nodes"]:
            ref = f"{o}:{n['id']}"
            by_label.setdefault(n["label"].casefold(), []).append(ref)
            links[ref] = set(n.get("same_as", []))
            if n["id"] in lineages:               # stable id = first key of the lineage
                lin = lineages[n["id"]]
                keys[ref] = lin.id + (f", rotated {lin.rotations} time{'s' if lin.rotations != 1 else ''}"
                                      if lin.rotations else "")
            elif "pubkey" in n:
                keys[ref] = "key " + sha(n["pubkey"].encode())[:8]
    return by_label, links, keys


TAGS = {"LINKED": "LINKED (both sides signed same_as)",
        "CLAIMED": "CLAIMED (one side only)",
        "COLLISION": "COLLISION: same name, different identities"}


def names_report(base: str) -> list[str]:
    """Same label, different identities = collision. Same thing only if same_as says so."""
    _, links, keys = _gather(base)
    out = []
    for label, a, b, st in name_pairs(base):
        ka, kb = keys.get(a, "no key"), keys.get(b, "no key")
        out.append(f"{label!r:12} {a} [{ka}]  vs  {b} [{kb}]  -> {TAGS[st]}")
    out.append("-- same_as links across different labels:")
    for a, ts in sorted(links.items()):
        for b in sorted(ts):
            mutual = a in links.get(b, set())
            out.append(f"   {a} -> {b}  {'LINKED' if mutual else 'CLAIMED (one side only)'}")
    return out


def names(base: str) -> None:
    for line in names_report(base):
        print(line)
