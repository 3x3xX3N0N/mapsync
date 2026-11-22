"""Layout of a world under a base dir: maps/<owner>/map.json, root.sig, agent_sigs/."""
from __future__ import annotations

import os

from .files import read_json, write_json


def owners(base: str) -> list[str]:
    d = os.path.join(base, "maps")
    return sorted(p for p in os.listdir(d) if os.path.isfile(os.path.join(d, p, "map.json")))


def map_path(base: str, owner: str) -> str:
    return os.path.join(base, "maps", owner, "map.json")


def load(base: str, owner: str) -> dict:
    return read_json(map_path(base, owner))


def save(base: str, owner: str, m: dict) -> None:
    write_json(map_path(base, owner), m, indent=2, ensure_ascii=False)


def diff_report(a: str, b: str) -> list[str]:
    from .hashing import leaf
    na = {n["id"]: leaf(n) for n in read_json(a)["nodes"]}
    nb = {n["id"]: leaf(n) for n in read_json(b)["nodes"]}
    out = []
    for i in sorted(na.keys() | nb.keys()):
        if i not in nb:
            out.append(f"- {i}  only in {a}")
        elif i not in na:
            out.append(f"+ {i}  only in {b}")
        elif na[i] != nb[i]:
            out.append(f"~ {i}  differs")
    return out


def diff(a: str, b: str) -> None:
    for line in diff_report(a, b):
        print(line)
