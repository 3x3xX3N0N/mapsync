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
    python3 mapsync.py prove OWNER NODE [-o FILE]   inclusion proof revealing just that node
    python3 mapsync.py check-proof FILE             check a proof alone; exit 0 if valid
    python3 mapsync.py sync-check OTHER [SECOND]    same top root? else walk down to owner, node
    python3 mapsync.py log append                   publish the current state: append top_root to log/roots.jsonl
    python3 mapsync.py log show | log verify        list / check the hash-chained log of past top roots
    python3 mapsync.py log compare OTHER_LOG        prefix = consistent history; else FORK at seq N (exit 1)
    python3 mapsync.py anchor WITNESS KEY [--seq N] witness signs a receipt for a log entry (default: head)
    python3 mapsync.py anchor verify [--min-witnesses K]  check receipts; exit 1 if any invalid or head has < K
    python3 mapsync.py anchor export DIR            copy log + receipts + witnesses: a participant's own copy
    python3 mapsync.py keys show OWNER              the owner's key chain (maps/OWNER/keys.jsonl) and lineages
    python3 mapsync.py keys recovery OWNER OWNER_KEY RECOVERY_PUB   pre-register a recovery key
    python3 mapsync.py keys rotate OWNER owner|agent:ID NEW_PUB --sign KEY [--sign KEY]  rotate a key
    python3 mapsync.py keys revoke OWNER owner|agent:ID KEY --by owner|recovery --signer KEY  revoke a key
    python3 mapsync.py keys verify                  check every key chain; exit 0 if green

Global option: --base DIR (default: this repo) = the world to work on. A relative map
path is looked up under --base when one is given (else relative to the current dir).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from mapsynclib import REPO
from mapsynclib.demo import make_world
from mapsynclib.g1 import g1
from mapsynclib.hashing import map_root
from mapsynclib.identity import names
from mapsynclib.index import verify, write_index
from mapsynclib import anchor as anchors
from mapsynclib import keys as keychain
from mapsynclib import log as rootlog
from mapsynclib.files import read_json, write_json
from mapsynclib.proofs import check_proof, prove
from mapsynclib.signing import agent_sign, sign
from mapsynclib.sync import sync_report
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
    add("prove", "inclusion proof for one node (others only as hashes)", "owner", "node") \
        .add_argument("-o", "--out", help="write the proof here (default: stdout)")
    c = add("check-proof", "check a proof on its own; exit 0 if valid", "file")
    c.add_argument("--signers", help="allowed_signers file to trust (default: BASE/allowed_signers)")
    c.add_argument("--top-root", help="also require this top_root")
    s = add("sync-check", "compare with another world (dir or index.json); exit 0 if in sync", "other")
    s.add_argument("second", nargs="?", help="compare OTHER with this instead of with --base")
    lg = add("log", "append-only hash-chained log of past top roots (log/roots.jsonl)")
    lsub = lg.add_subparsers(dest="log_cmd", metavar="LOGCOMMAND", required=True)
    lsub.add_parser("append", help="rebuild index if needed; append top_root if it changed", parents=[common])
    lsub.add_parser("show", help="list the log entries", parents=[common])
    lsub.add_parser("verify", help="chain intact and head == index.json; exit 0 if so", parents=[common])
    lsub.add_parser("compare", help="is one log a prefix of the other? exit 1 on fork",
                    parents=[common]).add_argument("other", help="the other roots.jsonl")
    an = add("anchor", "witness receipts for log entries: anchor WITNESS KEY | anchor verify | anchor export DIR")
    an.add_argument("args", nargs="+", metavar="WITNESS KEY | verify | export DIR")
    an.add_argument("--seq", type=int, help="log entry to witness (default: the head)")
    an.add_argument("--min-witnesses", type=int, default=0, metavar="K",
                    help="anchor verify: the log head needs K distinct witnesses (default 0)")
    ks = add("keys", "key lifecycle: keys show|recovery|rotate|revoke|verify (maps/OWNER/keys.jsonl)")
    ksub = ks.add_subparsers(dest="keys_cmd", metavar="KEYSCOMMAND", required=True)
    ksub.add_parser("show", help="list OWNER's key events and current lineages", parents=[common]) \
        .add_argument("owner")
    r = ksub.add_parser("recovery", help="owner pre-registers a recovery public key", parents=[common])
    for x in ("owner", "owner_key", "recovery_pub"):
        r.add_argument(x)
    r.add_argument("--sign", dest="old_recovery", metavar="OLD_RECOVERY_KEY",
                   help="replacing a recovery key: the old recovery private key must sign too")
    r.add_argument("--reason", default="register recovery key")
    r = ksub.add_parser("rotate", help="rotate the owner's or an agent's key", parents=[common])
    for x in ("owner", "subject", "new_pub"):
        r.add_argument(x)
    r.add_argument("--sign", action="append", required=True, metavar="KEY",
                   help="private key(s): owner rotation = old (or recovery) + new; agent = owner [+ old agent]")
    r.add_argument("--reason", default="rotate")
    r = ksub.add_parser("revoke", help="revoke a key (compromised): its signatures go red", parents=[common])
    for x in ("owner", "subject", "key"):
        r.add_argument(x)
    r.add_argument("--by", choices=("owner", "recovery"), required=True)
    r.add_argument("--signer", required=True, metavar="KEY", help="the owner's or recovery private key")
    r.add_argument("--reason", default="revoke")
    ksub.add_parser("verify", help="every key chain intact and agreeing with maps/allowed_signers",
                    parents=[common])
    return p


def keys_cmd(a, base: str) -> int:
    try:
        if a.keys_cmd == "show":
            print("\n".join(keychain.show(base, a.owner)))
            return 0
        if a.keys_cmd == "verify":
            return 0 if keychain.key_checks(base, print) else 1
        if a.keys_cmd == "recovery":
            st = keychain.recovery(base, a.owner, a.owner_key, a.recovery_pub, a.old_recovery, a.reason)
            print(f"{a.owner}: recovery key {keychain.fp(st.recovery)} registered")
        elif a.keys_cmd == "rotate":
            st = keychain.rotate(base, a.owner, a.subject, a.new_pub, a.sign, a.reason)
            lin = st.owner if a.subject == "owner" else st.agents[a.subject.split(":", 1)[1]]
            print(f"{a.owner}:{a.subject}: rotated to {keychain.fp(lin.current)} ({lin.describe()}); map re-signed")
        elif a.keys_cmd == "revoke":
            keychain.revoke(base, a.owner, a.subject, a.key, a.by, a.signer, a.reason)
            print(f"{a.owner}:{a.subject}: key {keychain.fp(keychain.read_pub(a.key))} REVOKED")
        print("next: `index` (and `log append`) to publish the new key chain", file=sys.stderr)
        return 0
    except (ValueError, OSError, KeyError) as e:
        print(f"keys {a.keys_cmd}: {e}", file=sys.stderr)
        return 1


def anchor_cmd(a, base: str) -> int:
    args = a.args
    try:
        if args == ["verify"]:
            return 0 if anchors.anchor_checks(base, print, a.min_witnesses) else 1
        if len(args) == 2 and args[0] == "export":
            copied = anchors.export(base, os.path.abspath(args[1]))
            print(f"exported {len(copied)} files to {args[1]}: {', '.join(copied)}")
            print(f"later: python3 mapsync.py log compare {os.path.join(args[1], rootlog.LOG)}")
            return 0
        if len(args) == 2 and args[0] not in anchors.RESERVED:
            p, r = anchors.anchor(base, args[0], args[1], a.seq)
            print(f"{r['witness']} witnessed seq {r['log_seq']} top_root {r['top_root'][:16]}… -> {p}")
            return 0
    except (ValueError, OSError, KeyError) as e:
        print(f"anchor: {e}", file=sys.stderr)
        return 1
    print("usage: anchor WITNESS KEY [--seq N] | anchor verify [--min-witnesses K] | anchor export DIR",
          file=sys.stderr)
    return 2


def log_cmd(a, base: str) -> int:
    try:
        if a.log_cmd == "append":
            _, msg = rootlog.append(base)
            print(msg)
        elif a.log_cmd == "show":
            print("\n".join(rootlog.show(base)))
        elif a.log_cmd == "verify":
            return 0 if rootlog.log_checks(base, print, required=True) else 1
        elif a.log_cmd == "compare":
            ok, lines = rootlog.compare(rootlog.log_path(base), a.other)
            print("\n".join(lines))
            return 0 if ok else 1
    except (ValueError, OSError, KeyError) as e:
        print(f"log {a.log_cmd}: {e}", file=sys.stderr)
        return 1
    return 0


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
        if os.path.exists(rootlog.log_path(base)):
            print("note: index.json is not published until `log append` records it", file=sys.stderr)
    elif cmd == "log":
        return log_cmd(a, base)
    elif cmd == "anchor":
        return anchor_cmd(a, base)
    elif cmd == "keys":
        return keys_cmd(a, base)
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
    elif cmd == "prove":
        try:
            proof = prove(base, a.owner, a.node)
        except (KeyError, ValueError, FileNotFoundError) as e:
            print(f"cannot prove: {e.args[0] if e.args else e}", file=sys.stderr)
            return 1
        if a.out:
            write_json(a.out, proof, indent=2, ensure_ascii=False)
            print(f"proof of {a.owner}:{a.node} -> {a.out}")
        else:
            print(json.dumps(proof, indent=2, ensure_ascii=False))
    elif cmd == "check-proof":
        try:
            proof = read_json(a.file)
        except (OSError, ValueError) as e:
            print(f"INVALID  cannot read proof: {e}")
            return 1
        good, why = check_proof(proof, a.signers or os.path.join(base, "allowed_signers"), a.top_root)
        print(f"{'VALID' if good else 'INVALID'}  {why}")
        return 0 if good else 1
    elif cmd == "sync-check":
        here, there = (a.other, a.second) if a.second else (base, a.other)
        same, lines = sync_report(here, there)
        print("\n".join(lines))
        return 0 if same else 1
    elif cmd == "demo":
        w = make_world(os.path.abspath(a.dir))
        print(f"world in {w['base']}  top_root {w['top_root']}")
        for k, v in {**w["owners"], **w["agents"]}.items():
            print(f"  key {k:10} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
