"""maps/<owner>/keys.jsonl: key lifecycle (recovery, rotation, revocation) and key lineages.

An optional, per-owner, append-only hash-chained event log. No file = keys are exactly
what allowed_signers and the map's `pubkey` fields say (the behaviour before this module).
One canonical JSON object per line (sort_keys, separators (",",":")):

    {"seq": int, "prev": <entry_sha of the previous line, or 64 zeros>,
     "type": "recovery" | "rotate" | "revoke", "subject": "owner" | "agent:<node id>",
     "old_key": "ssh-ed25519 AAAA..." | null, "new_key": "ssh-ed25519 AAAA..." | null,
     "reason": str, "at": "YYYY-MM-DDTHH:MM:SSZ", "sigs": {role: "<armored ssh sig>"}}

entry_sha(line) = sha256(0x03 || line bytes). Every signature in `sigs` is an ssh signature
(namespace mapsync-keys) over the line minus `sigs` (canonical JSON). Roles name the key
that made it: "owner" = the owner's current key, "old" = old_key, "new" = new_key,
"recovery" = the registered recovery key.

    recovery  subject owner; new_key = recovery public key, old_key = the one it replaces
              (null for the first). Signed by owner; replacing one also needs the old
              recovery key, so a thief holding only the owner key can't swap it.
    rotate    owner: old_key must be the current owner key; signed by new AND (old, or
              recovery). Once the owner key is revoked, only recovery + new will do.
              agent:<id>: old_key must be the agent's current key; signed by owner
              (optionally also old and/or new). The map's node `pubkey` becomes new_key
              and the owner re-signs the map.
    revoke    old_key = a key in the subject's lineage (current or retired), new_key null.
              Signed by owner (current, unrevoked owner key) or by recovery.

Identity is the lineage: the stable id is the fingerprint of the FIRST key (`key <first8>`,
the same fingerprint `names` always showed). Retired (rotated) keys stay honest: their old
signatures still count. Revoked keys are treated as compromised: anything they signed is red.

The owner's first key is the old_key of the first owner rotate/revoke line; if there is
none, the key in allowed_signers. An agent's first key is the old_key of its first line.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time

from .files import read_bytes, read_text, write_bytes
from .hashing import sha
from .signing import NAMESPACE as OWNER_NAMESPACE, sign, ssh_sign, ssh_verify
from .world import load, map_path, owners, save

FILE = "keys.jsonl"
NAMESPACE = "mapsync-keys"
ZERO = "0" * 64
FIELDS = {"seq", "prev", "type", "subject", "old_key", "new_key", "reason", "at", "sigs"}
TYPES = ("recovery", "rotate", "revoke")
ROLES = ("owner", "old", "new", "recovery")
SUBJECT = re.compile(r"(owner|agent:[A-Za-z0-9_.-]+)\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")


class KeyChainError(ValueError):
    """keys.jsonl is malformed, or an event in it is not properly authorised."""


# ---------------------------------------------------------------- keys and signatures

def norm_key(s: str) -> str:
    """'ssh-ed25519 AAAA... comment' -> 'ssh-ed25519 AAAA...'. ValueError if not a public key."""
    parts = s.split() if isinstance(s, str) else []
    if len(parts) < 2 or not re.match(r"(ssh-|ecdsa-|sk-)[a-z0-9@.-]+\Z", parts[0]):
        raise ValueError(f"not an ssh public key: {str(s)[:40]!r}")
    try:
        base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"not an ssh public key (bad base64): {str(s)[:40]!r}") from None
    return f"{parts[0]} {parts[1]}"


def read_pub(arg: str) -> str:
    """A public key given as a literal, a .pub file, or a private key with KEY.pub beside it."""
    if os.path.isfile(arg):
        text = read_text(arg)
        if "PRIVATE KEY" in text:
            if os.path.isfile(arg + ".pub"):
                return norm_key(read_text(arg + ".pub"))
            return pub_of(arg)
        return norm_key(text)
    return norm_key(arg)


def pub_of(private_key: str) -> str:
    """The public key of a private key file (ssh-keygen -y, no network, no agent)."""
    r = subprocess.run(["ssh-keygen", "-y", "-f", private_key], capture_output=True, text=True)
    if r.returncode != 0:
        raise ValueError(f"cannot read private key {private_key}: {r.stderr.strip()}")
    return norm_key(r.stdout)


def fp(key: str | None) -> str:
    """Short fingerprint, as shown by `names`: first 8 hex of sha256 of the key line."""
    return "none" if key is None else sha(key.encode())[:8]


def key_verifies(pub: str, sig: str, data: str, namespace: str = NAMESPACE) -> bool:
    """Does armored ssh signature `sig` over `data` verify under public key `pub`?"""
    with tempfile.TemporaryDirectory(prefix="mapsync-keys-") as t:
        signers, sf = os.path.join(t, "signers"), os.path.join(t, "sig")
        with open(signers, "w") as f:
            f.write(f"k {pub}\n")
        write_bytes(sf, sig.encode() if isinstance(sig, str) else sig)
        return ssh_verify(signers, "k", namespace, sf, data)


def allowed_key(base: str, owner: str) -> str | None:
    """The owner's key line in BASE/allowed_signers (None if absent)."""
    p = os.path.join(base, "allowed_signers")
    if not os.path.exists(p):
        return None
    for line in read_text(p).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == owner:
            try:
                return norm_key(" ".join(parts[1:3]))
            except ValueError:
                return None
    return None


def set_allowed_key(base: str, owner: str, key: str) -> None:
    p = os.path.join(base, "allowed_signers")
    lines = read_text(p).splitlines() if os.path.exists(p) else []
    out, done = [], False
    for line in lines:
        if line.split()[:1] == [owner]:
            out.append(f"{owner} {key}")
            done = True
        else:
            out.append(line)
    if not done:
        out.append(f"{owner} {key}")
    with open(p, "w") as f:
        f.write("\n".join(out) + "\n")


# ---------------------------------------------------------------- the chain

def keys_path(base: str, owner: str) -> str:
    return os.path.join(base, "maps", owner, FILE)


def canonical(e: dict) -> bytes:
    return json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entry_sha(line: bytes) -> str:
    return hashlib.sha256(b"\x03" + line).hexdigest()


def statement(e: dict) -> str:
    """The signed bytes: the line minus `sigs`."""
    return canonical({k: v for k, v in e.items() if k != "sigs"}).decode()


def read_lines(path: str) -> list[bytes]:
    raw = read_bytes(path)
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise KeyChainError("last line is not terminated by a newline (truncated write?)")
    return raw[:-1].split(b"\n")


class Lineage:
    """One identity's keys in order. status: current | rotated (retired, honest) | revoked."""

    def __init__(self, first: str):
        self.keys = [first]
        self.status = {first: "current"}
        self.current = first
        self.rotations = 0

    @property
    def id(self) -> str:
        return "key " + fp(self.keys[0])

    def rotate(self, new: str) -> None:
        if self.status[self.current] == "current":
            self.status[self.current] = "rotated"
        self.keys.append(new)
        self.status[new] = "current"
        self.current = new
        self.rotations += 1

    def revoke(self, key: str) -> None:
        self.status[key] = "revoked"

    def current_revoked(self) -> bool:
        return self.status[self.current] == "revoked"

    def describe(self) -> str:
        s = f"{self.id}, current {fp(self.current)}"
        if self.rotations:
            s += f", rotated {self.rotations} time{'s' if self.rotations != 1 else ''}"
        rev = [fp(k) for k in self.keys if self.status[k] == "revoked"]
        if rev:
            s += f", revoked {' '.join(rev)}"
        return s


class KeyState:
    def __init__(self, owner_first: str):
        self.owner = Lineage(owner_first)
        self.recovery: str | None = None
        self.agents: dict[str, Lineage] = {}
        self.events: list[dict] = []
        self.head = ZERO


def _check_shape(e, i: int) -> None:
    if not isinstance(e, dict) or set(e) != FIELDS:
        raise KeyChainError(f"line {i}: entry must have exactly the keys {sorted(FIELDS)}")
    if type(e["seq"]) is not int or e["seq"] != i:
        raise KeyChainError(f"line {i}: seq is {e['seq']!r}, expected {i} (line dropped, inserted or reordered)")
    if not isinstance(e["prev"], str) or not HEX64.match(e["prev"]):
        raise KeyChainError(f"seq {i}: prev is not 64 lowercase hex")
    if e["type"] not in TYPES:
        raise KeyChainError(f"seq {i}: type {e['type']!r} is not one of {TYPES}")
    if not isinstance(e["subject"], str) or not SUBJECT.match(e["subject"]):
        raise KeyChainError(f"seq {i}: subject {e['subject']!r} is not 'owner' or 'agent:<id>'")
    for k in ("old_key", "new_key"):
        if e[k] is not None:
            try:
                ok = norm_key(e[k]) == e[k]
            except ValueError:
                ok = False
            if not ok:
                raise KeyChainError(f"seq {i}: {k} is not a normalised ssh public key ('type base64')")
    if not isinstance(e["reason"], str):
        raise KeyChainError(f"seq {i}: reason is not a string")
    if not isinstance(e["at"], str) or not STAMP.match(e["at"]):
        raise KeyChainError(f"seq {i}: at is not YYYY-MM-DDTHH:MM:SSZ")
    if not isinstance(e["sigs"], dict) or not e["sigs"] or not all(
            r in ROLES and isinstance(s, str) for r, s in e["sigs"].items()):
        raise KeyChainError(f"seq {i}: sigs must be a non-empty {{role: signature}} with roles in {ROLES}")


def _owner_first(entries: list[dict], fallback: str | None) -> str:
    for e in entries:
        if e["subject"] == "owner" and e["type"] in ("rotate", "revoke") and e["old_key"]:
            return e["old_key"]
    if fallback is None:
        raise KeyChainError("no owner key: allowed_signers has none and no owner rotate/revoke line names one")
    return fallback


def _role_key(st: KeyState, e: dict, role: str) -> str | None:
    if role == "owner":
        return st.owner.current
    if role == "old":
        return e["old_key"]
    if role == "new":
        return e["new_key"]
    return st.recovery


def _apply(st: KeyState, e: dict) -> None:
    """Check that event e is authorised in state st, then apply it. Raises KeyChainError."""
    i, t, subj, old, new, sigs = e["seq"], e["type"], e["subject"], e["old_key"], e["new_key"], e["sigs"]
    where = f"seq {i} ({t} {subj})"
    data = statement(e)
    for role, sig in sorted(sigs.items()):
        k = _role_key(st, e, role)
        if k is None:
            raise KeyChainError(f"{where}: signed as {role!r} but there is no {role} key")
        if role == "owner" and st.owner.current_revoked():
            raise KeyChainError(f"{where}: signed by the owner key {fp(k)}, which is REVOKED")
        if role == "recovery" and k in (old, new) and t != "recovery":
            raise KeyChainError(f"{where}: recovery key cannot also be old_key/new_key")
        if not key_verifies(k, sig, data):
            raise KeyChainError(f"{where}: sigs.{role} does not verify under key {fp(k)} (forged or edited line)")
    roles = set(sigs)

    def allow(*ok):
        extra = roles - set(ok)
        if extra:
            raise KeyChainError(f"{where}: unexpected signature role(s) {sorted(extra)}")

    if t == "recovery":
        if subj != "owner":
            raise KeyChainError(f"{where}: a recovery key is registered for the owner only")
        if new is None:
            raise KeyChainError(f"{where}: new_key (the recovery public key) is missing")
        if old != st.recovery:
            raise KeyChainError(f"{where}: old_key must be the registered recovery key {fp(st.recovery)}")
        if new in st.owner.keys:
            raise KeyChainError(f"{where}: the recovery key must not be an owner key")
        allow("owner", "recovery")
        if "owner" not in roles:
            raise KeyChainError(f"{where}: not signed by the owner key")
        if st.recovery is not None and "recovery" not in roles:
            raise KeyChainError(f"{where}: replacing a recovery key needs the old recovery key's signature")
        st.recovery = new
    elif t == "rotate":
        if new is None or old is None:
            raise KeyChainError(f"{where}: rotate needs old_key and new_key")
        if subj == "owner":
            lin = st.owner
            if old != lin.current:
                raise KeyChainError(f"{where}: old_key {fp(old)} is not the current owner key {fp(lin.current)}")
            if new in lin.keys or new == st.recovery:
                raise KeyChainError(f"{where}: new_key was used before (keys are never reused)")
            allow("old", "new", "recovery")
            if "new" not in roles:
                raise KeyChainError(f"{where}: rotation not signed by the new key")
            if "recovery" not in roles:
                if "old" not in roles:
                    raise KeyChainError(f"{where}: rotation not signed by the old key")
                if lin.current_revoked():
                    raise KeyChainError(f"{where}: the old owner key is revoked; rotation needs the recovery key")
            lin.rotate(new)
        else:
            aid = subj.split(":", 1)[1]
            lin = st.agents.setdefault(aid, Lineage(old))
            if old != lin.current:
                raise KeyChainError(f"{where}: old_key {fp(old)} is not the agent's current key {fp(lin.current)}")
            if new in lin.keys:
                raise KeyChainError(f"{where}: new_key was used before (keys are never reused)")
            allow("owner", "old", "new")
            if "owner" not in roles:
                raise KeyChainError(f"{where}: agent rotation not signed by the owner key")
            lin.rotate(new)
    else:  # revoke
        if old is None or new is not None:
            raise KeyChainError(f"{where}: revoke names old_key (the key revoked) and no new_key")
        lin = st.owner if subj == "owner" else st.agents.setdefault(subj.split(":", 1)[1], Lineage(old))
        if old not in lin.keys:
            raise KeyChainError(f"{where}: key {fp(old)} is not in this lineage")
        if lin.status[old] == "revoked":
            raise KeyChainError(f"{where}: key {fp(old)} is already revoked")
        allow("owner", "recovery")
        lin.revoke(old)


def replay(lines: list[bytes], owner_key: str | None) -> KeyState:
    """Check the whole chain; return the state at its head. owner_key = allowed_signers' key."""
    entries, prev = [], ZERO
    for i, line in enumerate(lines):
        try:
            e = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as x:
            raise KeyChainError(f"line {i}: not JSON ({x})") from None
        _check_shape(e, i)
        if canonical(e) != line:
            raise KeyChainError(f"seq {i}: line is not canonical JSON (edited by hand?)")
        if e["prev"] != prev:
            raise KeyChainError(f"seq {i}: prev does not match entry_sha of seq {i - 1} "
                                "(a line was rewritten, dropped or reordered)")
        entries.append(e)
        prev = entry_sha(line)
    st = KeyState(_owner_first(entries, owner_key))
    for e in entries:
        _apply(st, e)
        st.events.append(e)
    st.head = prev
    return st


def state(base: str, owner: str) -> KeyState | None:
    """The owner's key state, None if there is no keys.jsonl. Raises KeyChainError if broken."""
    p = keys_path(base, owner)
    if not os.path.exists(p):
        return None
    return replay(read_lines(p), allowed_key(base, owner))


def agent_lineages(base: str, owner: str) -> dict[str, Lineage]:
    """{agent id: Lineage} from a valid chain; {} if none or broken (key_checks reports it)."""
    try:
        st = state(base, owner)
    except (KeyChainError, OSError, ValueError):
        return {}
    return st.agents if st else {}


# ---------------------------------------------------------------- writing events

def event(prev_lines: list[bytes], type: str, subject: str, old: str | None, new: str | None,
          reason: str, signers: dict[str, str], now: float | None = None) -> dict:
    """Build the next line, signed by {role: private key path}. No authorisation check."""
    prev = entry_sha(prev_lines[-1]) if prev_lines else ZERO
    e = {"seq": len(prev_lines), "prev": prev, "type": type, "subject": subject, "old_key": old,
         "new_key": new, "reason": reason, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
         "sigs": {}}
    data = statement(e)
    e["sigs"] = {r: ssh_sign(k, data, NAMESPACE).decode() for r, k in sorted(signers.items())}
    return e


def write_lines(base: str, owner: str, lines: list[bytes]) -> None:
    write_bytes(keys_path(base, owner), b"".join(x + b"\n" for x in lines))


def _current(base: str, owner: str) -> tuple[list[bytes], KeyState]:
    p = keys_path(base, owner)
    lines = read_lines(p) if os.path.exists(p) else []
    return lines, replay(lines, allowed_key(base, owner))


def _commit(base: str, owner: str, lines: list[bytes], e: dict) -> KeyState:
    """Append e only if the whole chain still replays (refuse otherwise)."""
    new = lines + [canonical(e)]
    st = replay(new, allowed_key(base, owner))
    write_lines(base, owner, new)
    return st


def _agent_node(m: dict, aid: str) -> dict:
    n = next((n for n in m["nodes"] if n["id"] == aid), None)
    if n is None or "pubkey" not in n:
        raise ValueError(f"no agent node {aid!r} (with a pubkey) in this map")
    return n


def _subject(s: str) -> str:
    if not SUBJECT.match(s):
        raise ValueError(f"subject must be 'owner' or 'agent:<id>', not {s!r}")
    return s


def recovery(base: str, owner: str, owner_key: str, recovery_pub: str, old_recovery_key: str | None = None,
             reason: str = "register recovery key", now: float | None = None) -> KeyState:
    lines, st = _current(base, owner)
    signers = {"owner": owner_key}
    if old_recovery_key:
        signers["recovery"] = old_recovery_key
    e = event(lines, "recovery", "owner", st.recovery, read_pub(recovery_pub), reason, signers, now)
    return _commit(base, owner, lines, e)


def _roles_for(keys: list[str], wanted: dict[str, str | None]) -> dict[str, str]:
    """Map each private key to the role whose public key it matches."""
    out = {}
    for k in keys:
        pub = pub_of(k)
        roles = [r for r, p in wanted.items() if p == pub]
        if not roles:
            raise ValueError(f"key {k} ({fp(pub)}) is none of: "
                             + ", ".join(f"{r} {fp(p)}" for r, p in wanted.items() if p))
        out[roles[0]] = k
    return out


def rotate(base: str, owner: str, subject: str, new_pub: str, sign_keys: list[str],
           reason: str = "rotate", now: float | None = None) -> KeyState:
    """Rotate the owner's or an agent's key. Owner: allowed_signers gets the new key and the map
    is re-signed with it. Agent: the node's pubkey becomes the new key, the owner re-signs."""
    lines, st = _current(base, owner)
    new = read_pub(new_pub)
    subject = _subject(subject)
    if subject == "owner":
        old = st.owner.current
        roles = _roles_for(sign_keys, {"old": old, "new": new, "recovery": st.recovery})
    else:
        aid = subject.split(":", 1)[1]
        node = _agent_node(load(base, owner), aid)
        old = st.agents[aid].current if aid in st.agents else norm_key(node["pubkey"])
        roles = _roles_for(sign_keys, {"owner": st.owner.current, "old": old, "new": new})
    e = event(lines, "rotate", subject, old, new, reason, roles, now)
    st2 = _commit(base, owner, lines, e)
    if subject == "owner":
        set_allowed_key(base, owner, new)
        if "new" in roles:
            sign(map_path(base, owner), roles["new"], base, quiet=True)
    else:
        m = load(base, owner)
        _agent_node(m, aid)["pubkey"] = new
        save(base, owner, m)
        sign(map_path(base, owner), roles["owner"], base, quiet=True)
    return st2


def revoke(base: str, owner: str, subject: str, key: str, by: str, signer: str,
           reason: str = "revoke", now: float | None = None) -> KeyState:
    if by not in ("owner", "recovery"):
        raise ValueError("--by must be owner or recovery")
    lines, st = _current(base, owner)
    e = event(lines, "revoke", _subject(subject), read_pub(key), None, reason, {by: signer}, now)
    return _commit(base, owner, lines, e)


# ---------------------------------------------------------------- checks and reports

def key_checks(base: str, say, required: bool = False) -> bool:
    """Every keys.jsonl intact and authorised; allowed_signers and agent pubkeys agree with
    the chain heads; root.sig is by the current, unrevoked owner key."""
    ok, any_chain = True, False
    for o in owners(base):
        p = keys_path(base, o)
        if not os.path.exists(p):
            continue
        any_chain = True
        try:
            st = state(base, o)
        except (KeyChainError, OSError) as x:
            say(f"RED  {o}: {FILE}: {x}")
            ok = False
            continue
        say(f"ok   {o}: {FILE}: {len(st.events)} events, chain intact; owner {st.owner.describe()}; "
            f"recovery {fp(st.recovery)}")
        cur = st.owner.current
        if st.owner.current_revoked():
            say(f"RED  {o}: the current owner key {fp(cur)} is REVOKED (rotate with the recovery key)")
            ok = False
        a = allowed_key(base, o)
        if a != cur:
            say(f"RED  {o}: allowed_signers has key {fp(a)}, but {FILE} says the current owner key is {fp(cur)}")
            ok = False
        else:
            from .hashing import map_root
            sig = os.path.join(base, "maps", o, "root.sig")
            good = os.path.exists(sig) and key_verifies(cur, read_text(sig), map_root(map_path(base, o), base),
                                                        OWNER_NAMESPACE)
            if not good:
                say(f"RED  {o}: root.sig is not by the current owner key {fp(cur)}")
                ok = False
        nodes = {n["id"]: n for n in load(base, o)["nodes"] if "pubkey" in n}
        for aid, lin in sorted(st.agents.items()):
            n = nodes.get(aid)
            if n is None:
                say(f"note {o}:{aid}: has key events but is no longer an agent node in the map")
                continue
            if norm_key(n["pubkey"]) != lin.current:
                say(f"RED  {o}:{aid}: map pubkey {fp(norm_key(n['pubkey']))} is not the lineage's current key "
                    f"{fp(lin.current)}")
                ok = False
            elif lin.current_revoked():
                say(f"RED  {o}:{aid}: its current key {fp(lin.current)} is REVOKED (rotate it)")
                ok = False
            else:
                say(f"ok   {o}:{aid}: {lin.describe()}")
    if not any_chain:
        say(f"{'RED' if required else 'note'} no maps/<owner>/{FILE}: keys are as in allowed_signers "
            "and the maps' pubkeys")
        return not required
    return ok


def show(base: str, owner: str) -> list[str]:
    st = state(base, owner)
    if st is None:
        return [f"{owner}: no {FILE}; owner key {fp(allowed_key(base, owner))} from allowed_signers"]
    out = []
    for e in st.events:
        out.append(f"{e['seq']:>3}  {e['at']}  {e['type']:8} {e['subject']:16} old {fp(e['old_key'])} "
                   f"new {fp(e['new_key'])}  signed by {','.join(sorted(e['sigs']))}  {e['reason']}")
    out.append(f"owner     {st.owner.describe()}")
    out.append(f"recovery  {fp(st.recovery)}")
    for aid, lin in sorted(st.agents.items()):
        out.append(f"agent {aid:4} {lin.describe()}")
    out.append(f"head entry_sha {st.head[:16]}…")
    return out
