"""ssh-keygen signatures: owners sign map roots, agents sign the node leaves they wrote."""
from __future__ import annotations

import os
import subprocess
import tempfile

from .files import read_json, write_bytes
from .hashing import leaf, map_root

NAMESPACE = "mapsync"
AGENT_NAMESPACE = "mapsync-agent"


def ssh_sign(key: str, data: str, namespace: str) -> bytes:
    r = subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", key, "-n", namespace],
                       input=data.encode(), capture_output=True, check=True)
    return r.stdout


def ssh_verify(allowed_signers: str, identity: str, namespace: str, sig: str, data: str) -> bool:
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", allowed_signers,
                        "-I", identity, "-n", namespace, "-s", sig],
                       input=data.encode(), capture_output=True)
    return r.returncode == 0


def sign(path: str, key: str, base: str, quiet: bool = False) -> str:
    """Owner signs the root of map `path`; writes root.sig next to it."""
    root = map_root(path, base)
    sig = os.path.join(os.path.dirname(path), "root.sig")
    write_bytes(sig, ssh_sign(key, root, NAMESPACE))
    if not quiet:
        print(f"signed {root[:16]}… -> {sig}")
    return root


def sig_ok(base: str, owner: str, root: str) -> bool:
    sig = os.path.join(base, "maps", owner, "root.sig")
    if not os.path.exists(sig):
        return False
    return ssh_verify(os.path.join(base, "allowed_signers"), owner, NAMESPACE, sig, root)


def agent_sign(path: str, node_id: str, key: str, quiet: bool = False) -> None:
    """The agent (not its owner) signs a node it wrote."""
    node = next(n for n in read_json(path)["nodes"] if n["id"] == node_id)
    d = os.path.join(os.path.dirname(path), "agent_sigs")
    os.makedirs(d, exist_ok=True)
    write_bytes(os.path.join(d, f"{node_id}.sig"), ssh_sign(key, leaf(node), AGENT_NAMESPACE))
    if not quiet:
        print(f"{node['by']} signed {node_id}")


def agent_sig_ok(base: str, owner: str, node: dict, agents: dict) -> str | None:
    """None if good, else the reason it isn't."""
    a = agents.get(node["by"])
    if a is None:
        return f"by={node['by']!r} is not an agent node (no pubkey) in {owner}'s map"
    sig = os.path.join(base, "maps", owner, "agent_sigs", f"{node['id']}.sig")
    if not os.path.exists(sig):
        return "no agent signature"
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(f"agent {a['pubkey']}\n")
    try:
        good = ssh_verify(f.name, "agent", AGENT_NAMESPACE, sig, leaf(node))
    finally:
        os.unlink(f.name)
    return None if good else f"signature is not by {owner}:{node['by']}'s key"
