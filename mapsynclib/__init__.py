"""mapsynclib: the logic behind mapsync.py, split by concern.

    hashing   sha, leaf, merkle, map_root (the bytes that get signed)
    vocab     the pinned SUMO term list; `concepts`
    world     where things live under a base dir: owners, maps
    signing   ssh-keygen wrappers: owner root sigs, agent node sigs
    index     index.json (top_root) and `verify`
    identity  agent-signature and same_as checks; `names`
    proofs    prove / check_proof: one node's inclusion proof (selective disclosure)
    sync      sync-check: compare two worlds' top roots, walk down to owner and node
    demo      make_world(dir): a complete signed world with fresh keys
    g1        sabotage each check; each must go red
"""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # default --base
