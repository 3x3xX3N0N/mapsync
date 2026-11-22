"""make_world(dir): build a complete signed world with fresh ephemeral keys.

Same shape as the shipped example (alice and bob, two unrelated Codys, agent-written
nodes with agent_sigs, one mutual and one one-sided same_as) but every key is new, so
tests and g1 can sign things. Private keys live in <dir>/keys/ and never in the repo.
"""
from __future__ import annotations

import os
import secrets
import shutil
import subprocess

from . import REPO
from .files import read_text
from .index import write_index
from .signing import agent_sign, sign
from .vocab import TERMS
from .world import map_path, save


def keygen(path: str, comment: str = "") -> str:
    """Fresh ed25519 key pair at path / path.pub (no passphrase). Returns the public key line."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-C", comment, "-f", path],
                   check=True, capture_output=True)
    return " ".join(read_text(path + ".pub").split()[:2])


def _node(id, label, sumo, content, **extra) -> dict:
    return {"id": id, "label": label, "sumo": sumo, "content": content, "salt": secrets.token_hex(16), **extra}


def demo_maps(pub: dict) -> dict:
    """The shipped example's maps, with the given agent public keys and fresh salts."""
    return {
        "alice": {"owner": "alice", "nodes": [
            _node("coordinator", "Psyche", "ComputerProgram", "Central agent that routes work to leads"),
            _node("cody", "Cody", "ComputerProgram", "Alice's coding agent", pubkey=pub["alice:cody"]),
            _node("review", "Review readiness", "IntentionalProcess", "Check a change is ready for review",
                  by="cody", same_as=["bob:prcheck"]),
            _node("notes", "Release note", "Text", "Draft of what shipped this week",
                  by="cody", same_as=["bob:changelog"]),
        ]},
        "bob": {"owner": "bob", "nodes": [
            _node("cody", "Cody", "ComputerProgram", "Bob's coding agent, unrelated to Alice's",
                  pubkey=pub["bob:cody"]),
            _node("orchestrator", "the router", "ComputerProgram", "Thing that hands tasks to agents"),
            _node("prcheck", "PR check", "IntentionalProcess", "Make sure a pull request is good to go",
                  same_as=["alice:review"]),
            _node("changelog", "Changelog", "Text", "Draft of what shipped this week", by="cody"),
            _node("deadline", "Ship date", "TimeInterval", "Friday"),
        ]},
    }


def add_witness(base: str, name: str, keydir: str | None = None) -> str:
    """Fresh ephemeral witness key in keydir (default BASE/keys); its public key is appended
    to BASE/witnesses. Returns the private key path."""
    key = os.path.join(keydir or os.path.join(base, "keys"), f"witness_{name}")
    pub = keygen(key, f"witness:{name}")
    with open(os.path.join(base, "witnesses"), "a") as f:
        f.write(f"{name} {pub}\n")
    return key


def make_world(dir: str, terms_from: str = REPO) -> dict:
    """Build a full signed world in `dir`. Returns
    {"base": dir, "owners": {owner: private_key_path}, "agents": {"owner:agent": private_key_path},
     "pubkeys": {name: "ssh-ed25519 AAAA..."}, "top_root": ...}."""
    os.makedirs(os.path.join(dir, "sumo"), exist_ok=True)
    shutil.copy(os.path.join(terms_from, TERMS), os.path.join(dir, TERMS))
    kd = os.path.join(dir, "keys")
    keys = {"owners": {}, "agents": {}}
    pub = {}
    for o in ("alice", "bob"):
        keys["owners"][o] = os.path.join(kd, o)
        pub[o] = keygen(keys["owners"][o], o)
        a = f"{o}:cody"
        keys["agents"][a] = os.path.join(kd, f"{o}_cody")
        pub[a] = keygen(keys["agents"][a], a)
    with open(os.path.join(dir, "allowed_signers"), "w") as f:
        for o in keys["owners"]:
            f.write(f"{o} {pub[o]}\n")
    for o, m in demo_maps(pub).items():
        os.makedirs(os.path.join(dir, "maps", o), exist_ok=True)
        save(dir, o, m)
        for n in m["nodes"]:
            if "by" in n:
                agent_sign(map_path(dir, o), n["id"], keys["agents"][f"{o}:{n['by']}"], quiet=True)
        sign(map_path(dir, o), keys["owners"][o], dir, quiet=True)
    idx = write_index(dir)
    return {"base": dir, **keys, "pubkeys": pub, "top_root": idx["top_root"]}
