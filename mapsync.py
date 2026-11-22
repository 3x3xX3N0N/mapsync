"""mapsync: sync many people's mental maps without merging them into one.

Each person owns one map (maps/<name>/map.json). Every node is tagged with a SUMO
term from a pinned list. A map hashes to a Merkle root, the owner signs that root
with an ssh key, and index.json collects every (owner, root, signature) into one
top root. Compare top roots to check sync; walk down to find what differs.

Stdlib only, plus `ssh-keygen` for signatures. Logic lives in mapsynclib/.

    python3 mapsync.py root maps/alice/map.json     print a map's root
    python3 mapsync.py sign maps/alice/map.json KEY write maps/alice/root.sig
    python3 mapsync.py index                        rebuild index.json
    python3 mapsync.py verify                       check everything; exit 0 if green
    python3 mapsync.py diff A.json B.json           which nodes differ between two maps
    python3 mapsync.py agent-sign MAP NODE AGENTKEY the agent itself signs a node it wrote
    python3 mapsync.py names                        same name, different identity? (the two-Codys problem)
    python3 mapsync.py concepts                     line maps up by SUMO term, not label
    python3 mapsync.py g1                           sabotage each check; each must go red
    python3 mapsync.py demo DIR                     build a fresh signed example world in DIR

Global option: --base DIR (default: this repo) = the world to work on. A relative map
path is looked up under --base when one is given (else relative to the current dir).
"""
from __future__ import annotations

import argparse
import os
import sys

from mapsynclib import REPO
from mapsynclib.demo import make_world
from mapsynclib.g1 import g1
from mapsynclib.hashing import map_root
from mapsynclib.identity import names
from mapsynclib.index import verify, write_index
from mapsynclib.signing import agent_sign, sign
from mapsynclib.vocab import concepts
from mapsynclib.world import diff


def _path(base: str, p: str, explicit: bool) -> str:
    """Relative map paths: under --base if one was given and the file is there, else as given."""
    q = os.path.join(base, p)
    if os.path.isabs(p) or not os.path.exists(q) or (not explicit and os.path.exists(p)):
        return p
    return q


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--base", default=argparse.SUPPRESS, help="world directory (default: the repo)")
    p = argparse.ArgumentParser(prog="mapsync.py", description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter, parents=[common])
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    def add(name, help, *args):
        s = sub.add_parser(name, help=help, parents=[common])
        for a in args:
            s.add_argument(a)
        return s
    add("root", "print a map's root", "map")
    add("sign", "owner signs a map root -> root.sig", "map", "key")
    add("index", "rebuild index.json")
    add("verify", "check everything; exit 0 if green")
    add("diff", "which nodes differ between two maps", "a", "b")
    add("agent-sign", "the agent itself signs a node it wrote", "map", "node", "key")
    add("names", "same name, different identity? (two-Codys problem)")
    add("concepts", "line maps up by SUMO term, not label")
    add("g1", "sabotage each check; each must go red")
    add("demo", "build a fresh signed example world (ephemeral keys in DIR/keys)", "dir")
    return p


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    base = os.path.abspath(getattr(a, "base", REPO))
    cmd = a.cmd or "verify"
    P = lambda p: _path(base, p, hasattr(a, "base"))
    if cmd == "root":
        print(map_root(P(a.map), base))
    elif cmd == "sign":
        sign(P(a.map), a.key, base)
    elif cmd == "index":
        print(f"top_root {write_index(base)['top_root']}")
    elif cmd == "verify":
        return 0 if verify(base) else 1
    elif cmd == "diff":
        diff(P(a.a), P(a.b))
    elif cmd == "agent-sign":
        agent_sign(P(a.map), a.node, a.key)
    elif cmd == "names":
        names(base)
    elif cmd == "concepts":
        concepts(base)
    elif cmd == "g1":
        return 0 if g1(base) else 1
    elif cmd == "demo":
        w = make_world(os.path.abspath(a.dir))
        print(f"world in {w['base']}  top_root {w['top_root']}")
        for k, v in {**w["owners"], **w["agents"]}.items():
            print(f"  key {k:10} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
