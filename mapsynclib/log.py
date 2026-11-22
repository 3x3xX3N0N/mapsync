"""log/roots.jsonl: an append-only, hash-chained log of past top roots.

One canonical JSON object per line (sort_keys, separators (",",":")):

    {"seq": 0, "prev": <entry_sha of the previous line, or 64 zeros>, "top_root": hex,
     "maps": [{"owner", "root"}...], "sumo_terms_sha": hex, "recorded_at": "YYYY-MM-DDTHH:MM:SSZ"}

plus "vocab_sha": hex when the index has one (the world has sumo/hierarchy.txt etc.).

entry_sha(line) = sha256(0x02 || canonical line bytes). Each line commits to the whole
history before it, so rewriting, dropping or reordering a past entry breaks every later
`prev`. Two copies of a log agree on history iff one is a prefix of the other; anything
else is a fork, found at the first seq where they differ.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time

from .files import read_bytes, read_json
from .index import build_index, write_index
from .identity import identity_checks
from .signing import sig_ok

LOG = os.path.join("log", "roots.jsonl")
ZERO = "0" * 64
KEYS = {"seq", "prev", "top_root", "maps", "sumo_terms_sha", "recorded_at"}
OPTIONAL_KEYS = {"vocab_sha"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")


class LogError(ValueError):
    """The log is malformed or its chain is broken."""


def log_path(base: str) -> str:
    return os.path.join(base, LOG)


def canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entry_sha(line: bytes) -> str:
    return hashlib.sha256(b"\x02" + line).hexdigest()


def read_lines(path: str) -> list[bytes]:
    """The log's lines (without newlines). Every line must end in '\\n'; no blank lines."""
    raw = read_bytes(path)
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise LogError("last line is not terminated by a newline (truncated write?)")
    return raw[:-1].split(b"\n")


def _check_entry(e, i: int) -> None:
    if not isinstance(e, dict) or not KEYS <= set(e) <= KEYS | OPTIONAL_KEYS:
        raise LogError(f"line {i}: entry must have exactly the keys {sorted(KEYS)} (+ optional {sorted(OPTIONAL_KEYS)})")
    if type(e["seq"]) is not int or e["seq"] != i:
        raise LogError(f"line {i}: seq is {e['seq']!r}, expected {i} (entry dropped, inserted or reordered)")
    for k in ("prev", "top_root", "sumo_terms_sha", *sorted(OPTIONAL_KEYS & set(e))):
        if not isinstance(e[k], str) or not HEX64.match(e[k]):
            raise LogError(f"seq {i}: {k} is not 64 lowercase hex")
    if not isinstance(e["recorded_at"], str) or not STAMP.match(e["recorded_at"]):
        raise LogError(f"seq {i}: recorded_at is not YYYY-MM-DDTHH:MM:SSZ")
    if not isinstance(e["maps"], list) or not all(
            isinstance(m, dict) and set(m) == {"owner", "root"} and isinstance(m["owner"], str)
            and isinstance(m["root"], str) and HEX64.match(m["root"]) for m in e["maps"]):
        raise LogError(f"seq {i}: maps must be a list of {{owner, root}}")


def parse(lines: list[bytes]) -> list[dict]:
    """Check the chain and return the entries. Raises LogError on the first problem."""
    entries, prev = [], ZERO
    for i, line in enumerate(lines):
        try:
            e = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as x:
            raise LogError(f"line {i}: not JSON ({x})") from None
        _check_entry(e, i)
        if canonical(e) != line:
            raise LogError(f"seq {i}: line is not canonical JSON (edited by hand?)")
        if e["prev"] != prev:
            raise LogError(f"seq {i}: prev {e['prev'][:16]}… does not match entry_sha of seq {i - 1} "
                           f"{prev[:16]}… (a past entry was rewritten, dropped or reordered)")
        entries.append(e)
        prev = entry_sha(line)
    return entries


def load_log(path: str) -> tuple[list[bytes], list[dict]]:
    lines = read_lines(path)
    return lines, parse(lines)


def entry_for(idx: dict, seq: int, prev: str, now: float | None = None) -> dict:
    e = {"seq": seq, "prev": prev, "top_root": idx["top_root"],
         "maps": [{"owner": m["owner"], "root": m["root"]} for m in idx["maps"]],
         "sumo_terms_sha": idx["sumo_terms_sha"],
         "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))}
    if "vocab_sha" in idx:
        e["vocab_sha"] = idx["vocab_sha"]
    return e


def head_matches(head: dict, idx: dict) -> bool:
    """Does the log head record exactly this index state (top_root, roots, vocabulary)?"""
    return (head["top_root"] == idx.get("top_root") and head["sumo_terms_sha"] == idx.get("sumo_terms_sha")
            and head.get("vocab_sha") == idx.get("vocab_sha")
            and head["maps"] == [{"owner": m.get("owner"), "root": m.get("root")} for m in idx.get("maps", [])])


def append(base: str, now: float | None = None) -> tuple[dict | None, str]:
    """Publish the current state: rebuild index.json if stale, then append an entry if its
    top_root differs from the log head. Returns (new entry or None, message).
    Refuses (ValueError) if a signature or identity check fails, or the log is broken."""
    fresh = build_index(base)
    bad = [e["owner"] for e in fresh["maps"] if not sig_ok(base, e["owner"], e["root"])]
    if bad:
        raise ValueError(f"refusing to log an unsigned state: bad root signature for {', '.join(bad)}")
    from .keys import key_checks
    if not key_checks(base, lambda *a: None):
        raise ValueError("refusing to log a state whose key chain checks fail (run keys verify)")
    if not identity_checks(base, lambda *a: None):
        raise ValueError("refusing to log a state that fails identity checks (run verify)")
    ip = os.path.join(base, "index.json")
    rebuilt = not os.path.exists(ip) or read_json(ip) != fresh
    if rebuilt:
        write_index(base)
    p = log_path(base)
    lines, entries = load_log(p) if os.path.exists(p) else ([], [])
    note = "index.json rebuilt; " if rebuilt else ""
    if entries and entries[-1]["top_root"] == fresh["top_root"]:
        return None, f"{note}unchanged: log head seq {entries[-1]['seq']} already is top_root {fresh['top_root'][:16]}…"
    e = entry_for(fresh, len(entries), entry_sha(lines[-1]) if lines else ZERO, now)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "ab") as f:
        f.write(canonical(e) + b"\n")
    return e, f"{note}appended seq {e['seq']} top_root {e['top_root'][:16]}…"


def log_checks(base: str, say, required: bool = False) -> bool:
    """Chain intact, and the head is the current index.json. No log: a note (green) unless required."""
    p = log_path(base)
    if not os.path.exists(p):
        say(f"{'RED' if required else 'note'} no {LOG}: past top roots are not recorded "
            "(`log append` starts the log)")
        return not required
    try:
        lines, entries = load_log(p)
    except (OSError, LogError) as x:
        say(f"RED  {LOG}: {x}")
        return False
    if not entries:
        say(f"RED  {LOG} is empty")
        return False
    say(f"ok   {LOG}: {len(entries)} entries, chain intact, head entry_sha {entry_sha(lines[-1])[:16]}…")
    try:
        idx = read_json(os.path.join(base, "index.json"))
    except (OSError, ValueError) as x:
        say(f"RED  cannot read index.json: {x}")
        return False
    head = entries[-1]
    if not head_matches(head, idx):
        say(f"RED  current index is not the log head: index top_root {str(idx.get('top_root', '?'))[:16]}…, "
            f"log seq {head['seq']} top_root {head['top_root'][:16]}… (publish with `log append`)")
        return False
    say(f"ok   current index is the log head (seq {head['seq']})")
    return True


def show(base: str) -> list[str]:
    lines, entries = load_log(log_path(base))
    out = []
    for line, e in zip(lines, entries):
        owners = ", ".join(f"{m['owner']}:{m['root'][:8]}" for m in e["maps"])
        out.append(f"{e['seq']:>4}  {e['recorded_at']}  top_root {e['top_root'][:16]}…  "
                   f"entry {entry_sha(line)[:16]}…  [{owners}]")
    return out


def compare(mine: str, theirs: str) -> tuple[bool, list[str]]:
    """Is one log a prefix of the other? (True, lines) if consistent, (False, lines) on a fork
    or if either chain is broken."""
    logs = []
    for name, p in (("this log", mine), ("other log", theirs)):
        try:
            lines, _ = load_log(p)
        except (OSError, LogError) as x:
            return False, [f"BROKEN  {name} ({p}): {x}"]
        logs.append(lines)
    a, b = logs
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            ea, eb = json.loads(x), json.loads(y)
            return False, [f"FORK at seq {i}: histories diverge",
                           f"  this:  top_root {ea['top_root'][:16]}…  recorded_at {ea['recorded_at']}",
                           f"  other: top_root {eb['top_root'][:16]}…  recorded_at {eb['recorded_at']}"]
    if len(a) == len(b):
        return True, [f"OK  identical histories ({len(a)} entries)"]
    short, long_ = ("this", "other") if len(b) > len(a) else ("other", "this")
    return True, [f"OK  consistent: the {short} log is a prefix of the {long_} "
                  f"({min(len(a), len(b))} of {max(len(a), len(b))} entries; {long_} is "
                  f"{abs(len(a) - len(b))} ahead)"]
