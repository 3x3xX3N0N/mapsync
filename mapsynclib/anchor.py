"""anchors/: witness-signed receipts for log entries ("this was our map at time X").

A witness is a key listed in `witnesses` (same format as allowed_signers:
`name ssh-ed25519 AAAA...`). Anchoring a log entry writes one receipt per witness:

    anchors/<seq>-<top_root[:16]>-<witness>.json
    {"version": 1, "witness": name, "log_seq": int, "entry_sha": hex, "top_root": hex,
     "witnessed_at": "YYYY-MM-DDTHH:MM:SSZ", "statement_sha": hex, "sig": "<armored ssh sig>"}

The signed statement is the canonical JSON (sort_keys, no spaces) of every field except
`sig` and `statement_sha`; statement_sha = sha256(statement), signed with namespace
mapsync-anchor. A receipt is valid when its signature is by that witness's listed key and
its entry_sha/top_root are what the log holds at log_seq. Rewriting history after an
entry was witnessed (even re-chaining every later line) therefore leaves a receipt that
points at something no longer in the log: red. Local only: nothing is published.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time

from .files import read_json, read_text, write_bytes, write_json
from .log import HEX64, LOG, STAMP, LogError, canonical, entry_sha, load_log, log_checks, log_path
from .signing import ssh_sign

WITNESSES = "witnesses"
ANCHORS = "anchors"
NAMESPACE = "mapsync-anchor"
VERSION = 1
FIELDS = {"version", "witness", "log_seq", "entry_sha", "top_root", "witnessed_at", "statement_sha", "sig"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
RESERVED = {"verify", "export"}                   # CLI subcommand words


def witnesses_path(base: str) -> str:
    return os.path.join(base, WITNESSES)


def anchors_dir(base: str) -> str:
    return os.path.join(base, ANCHORS)


def load_witnesses(base: str) -> dict[str, str]:
    """{name: "ssh-ed25519 AAAA..."} from BASE/witnesses ({} if absent). Blank and # lines skipped."""
    p = witnesses_path(base)
    out = {}
    if not os.path.exists(p):
        return out
    for i, line in enumerate(read_text(p).splitlines(), 1):
        parts = line.split()
        if not parts or parts[0].startswith("#"):
            continue
        if len(parts) < 3 or not NAME.match(parts[0]):
            raise ValueError(f"{WITNESSES} line {i}: expected `name keytype base64key`")
        if parts[0] in out:
            raise ValueError(f"{WITNESSES} line {i}: witness {parts[0]!r} listed twice")
        out[parts[0]] = f"{parts[1]} {parts[2]}"
    return out


def statement(r: dict) -> bytes:
    """The bytes a witness signs: canonical JSON of the receipt minus sig and statement_sha."""
    return canonical({k: v for k, v in r.items() if k not in ("sig", "statement_sha")})


def filename(r: dict) -> str:
    return f"{r['log_seq']}-{r['top_root'][:16]}-{r['witness']}.json"


def receipt_for(witness: str, key: str, seq: int, line: bytes, top_root: str, now: float | None = None) -> dict:
    """Sign a receipt for log line `line` (seq, top_root) with private key `key`. No checks."""
    r = {"version": VERSION, "witness": witness, "log_seq": seq, "entry_sha": entry_sha(line),
         "top_root": top_root, "witnessed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))}
    st = statement(r)
    r["statement_sha"] = hashlib.sha256(st).hexdigest()
    r["sig"] = ssh_sign(key, st.decode(), NAMESPACE).decode()
    return r


def public_key(key: str) -> str:
    r = subprocess.run(["ssh-keygen", "-y", "-f", key], capture_output=True, text=True)
    if r.returncode != 0:
        raise ValueError(f"cannot read private key {key}: {r.stderr.strip()}")
    return " ".join(r.stdout.split()[:2])


def anchor(base: str, witness: str, key: str, seq: int | None = None, now: float | None = None) -> tuple[str, dict]:
    """Witness `witness` (listed in BASE/witnesses, key = its private key) signs a receipt for
    log entry `seq` (default: the head). Refuses (ValueError) if log verify fails, the entry
    doesn't exist, or the key isn't that witness's. Returns (path, receipt)."""
    if witness in RESERVED or not NAME.match(witness):
        raise ValueError(f"bad witness name {witness!r}")
    listed = load_witnesses(base)
    if witness not in listed:
        raise ValueError(f"{witness!r} is not listed in {WITNESSES}")
    if public_key(key) != listed[witness]:
        raise ValueError(f"{key} is not {witness}'s key in {WITNESSES}")
    msgs = []
    if not log_checks(base, msgs.append, required=True):
        raise ValueError("refusing to anchor: log verify fails: " + "; ".join(m for m in msgs if m.startswith("RED")))
    lines, entries = load_log(log_path(base))
    seq = len(entries) - 1 if seq is None else seq
    if not 0 <= seq < len(entries):
        raise ValueError(f"no log entry seq {seq} (log has {len(entries)})")
    r = receipt_for(witness, key, seq, lines[seq], entries[seq]["top_root"], now)
    p = os.path.join(anchors_dir(base), filename(r))
    os.makedirs(anchors_dir(base), exist_ok=True)
    write_json(p, r, indent=2, sort_keys=True)
    return p, r


def _sig_ok(name: str, pubkey: str, sig: str, data: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="mapsync-anchor-") as t:
        signers, sf = os.path.join(t, "signers"), os.path.join(t, "sig")
        write_bytes(signers, f"{name} {pubkey}\n".encode())
        write_bytes(sf, sig.encode())
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", signers, "-I", name, "-n", NAMESPACE, "-s", sf],
                           input=data, capture_output=True)
    return r.returncode == 0


def check_receipt(r, fname: str, witnesses: dict, lines: list[bytes], entries: list[dict]) -> str | None:
    """None if the receipt is valid against this witness list and log, else why not."""
    if not isinstance(r, dict) or set(r) != FIELDS:
        return f"must have exactly the keys {sorted(FIELDS)}"
    if r["version"] != VERSION:
        return f"unknown version {r['version']!r}"
    if not isinstance(r["witness"], str) or not NAME.match(r["witness"]):
        return "bad witness name"
    if type(r["log_seq"]) is not int or r["log_seq"] < 0:
        return "log_seq is not a non-negative int"
    for k in ("entry_sha", "top_root", "statement_sha"):
        if not isinstance(r[k], str) or not HEX64.match(r[k]):
            return f"{k} is not 64 lowercase hex"
    if not isinstance(r["witnessed_at"], str) or not STAMP.match(r["witnessed_at"]):
        return "witnessed_at is not YYYY-MM-DDTHH:MM:SSZ"
    if not isinstance(r["sig"], str):
        return "sig is not a string"
    if fname != filename(r):
        return f"file name does not match its contents (expected {filename(r)})"
    st = statement(r)
    if hashlib.sha256(st).hexdigest() != r["statement_sha"]:
        return "statement_sha does not match the receipt's fields (receipt edited)"
    if r["witness"] not in witnesses:
        return f"{r['witness']!r} is not a listed witness"
    if not _sig_ok(r["witness"], witnesses[r["witness"]], r["sig"], st):
        return f"signature is not by {r['witness']}'s key"
    seq = r["log_seq"]
    if seq >= len(entries):
        return f"log has no seq {seq} (history truncated after it was witnessed)"
    if entries[seq]["top_root"] != r["top_root"] or entry_sha(lines[seq]) != r["entry_sha"]:
        return (f"log seq {seq} is no longer what was witnessed (top_root now "
                f"{entries[seq]['top_root'][:16]}…): history rewritten after anchoring")
    return None


def anchor_checks(base: str, say, min_witnesses: int = 0) -> bool:
    """Check every receipt in BASE/anchors/; report witnesses per log entry. False if any
    receipt is invalid or the log head has fewer than min_witnesses distinct witnesses."""
    d = anchors_dir(base)
    files = sorted(f for f in os.listdir(d)) if os.path.isdir(d) else []
    if not os.path.isdir(d):
        say(f"note no {ANCHORS}/: no log entry is witnessed (`anchor WITNESS KEY` makes a receipt)")
    try:
        witnesses = load_witnesses(base)
    except (OSError, ValueError) as x:
        say(f"RED  {WITNESSES}: {x}")
        return False
    try:
        lines, entries = load_log(log_path(base)) if os.path.exists(log_path(base)) else ([], [])
    except (OSError, LogError) as x:
        say(f"RED  {ANCHORS}/: cannot check receipts, {LOG} is broken: {x}")
        return False
    ok = True
    by_seq: dict[int, set] = {}
    for f in files:
        p = os.path.join(d, f)
        if not f.endswith(".json") or not os.path.isfile(p):
            say(f"RED  {ANCHORS}/{f}: not a receipt (expected <seq>-<top_root16>-<witness>.json)")
            ok = False
            continue
        try:
            r = read_json(p)
        except (OSError, ValueError) as x:
            why = f"not JSON ({x})"
        else:
            why = check_receipt(r, f, witnesses, lines, entries)
        if why:
            say(f"RED  receipt {f}: {why}")
            ok = False
        else:
            by_seq.setdefault(r["log_seq"], set()).add(r["witness"])
            say(f"ok   receipt {f}: {r['witness']} witnessed seq {r['log_seq']} at {r['witnessed_at']}")
    for seq in sorted(by_seq):
        say(f"ok   log seq {seq}: {len(by_seq[seq])} witness(es): {', '.join(sorted(by_seq[seq]))}")
    if entries:
        head = len(entries) - 1
        n = len(by_seq.get(head, ()))
        if n < min_witnesses:
            say(f"RED  log head seq {head} has {n} witness(es), need {min_witnesses}")
            ok = False
        elif n == 0:
            say(f"note log head seq {head} is not witnessed yet (`anchor WITNESS KEY`)")
        else:
            say(f"ok   log head seq {head}: {n} witness(es) (need {min_witnesses})")
    elif min_witnesses > 0:
        say(f"RED  no log: nothing witnessed, need {min_witnesses}")
        ok = False
    return ok


def export(base: str, dest: str) -> list[str]:
    """Copy the log, the receipts and the witness list to dest (a participant's own copy).
    Later: `log compare DEST/log/roots.jsonl` and `--base DEST anchor verify`."""
    copied = []
    if not os.path.exists(log_path(base)):
        raise ValueError(f"no {LOG} to export")
    load_log(log_path(base))                     # refuse to export a broken chain
    os.makedirs(os.path.join(dest, "log"), exist_ok=True)
    shutil.copy(log_path(base), os.path.join(dest, LOG))
    copied.append(LOG)
    if os.path.exists(witnesses_path(base)):
        shutil.copy(witnesses_path(base), os.path.join(dest, WITNESSES))
        copied.append(WITNESSES)
    if os.path.isdir(anchors_dir(base)):
        os.makedirs(os.path.join(dest, ANCHORS), exist_ok=True)
        for f in sorted(os.listdir(anchors_dir(base))):
            shutil.copy(os.path.join(anchors_dir(base), f), os.path.join(dest, ANCHORS, f))
            copied.append(f"{ANCHORS}/{f}")
    return copied

