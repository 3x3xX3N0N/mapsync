"""mapsynclib: the logic behind mapsync.py, split by concern.

    hashing   sha, leaf, merkle, map_root (the bytes that get signed)
    vocab     the pinned SUMO terms + hierarchy/local/disjoint; is_a, disjoint; `concepts`, `vocab`
    world     where things live under a base dir: owners, maps
    signing   ssh-keygen wrappers: owner root sigs, agent node sigs
    index     index.json (top_root) and `verify`
    identity  agent-signature and same_as checks; `names`
    proofs    prove / check_proof: one node's inclusion proof (selective disclosure)
    sync      sync-check: compare two worlds' top roots, walk down to owner and node
    log       log/roots.jsonl: append-only hash-chained log of top roots; fork detection
    keys      maps/<owner>/keys.jsonl: key rotation, revocation, recovery; stable key lineages
    anchor    anchors/: witness-signed receipts for log entries (local anchoring)
    suggest   offline tag suggester (sumo/lexicon.txt, pinned); `suggest`, `tag`
    claims    same_as clusters side by side; AGREE / REFINES / CONTRADICTION; `claims`
    demo      make_world(dir): a complete signed world with fresh keys
    g1        sabotage each check; each must go red
"""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # default --base
