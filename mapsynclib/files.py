"""Tiny file helpers that always close what they open."""
from __future__ import annotations

import json


def read_bytes(p: str) -> bytes:
    with open(p, "rb") as f:
        return f.read()


def write_bytes(p: str, b: bytes) -> None:
    with open(p, "wb") as f:
        f.write(b)


def read_text(p: str) -> str:
    with open(p, encoding="utf-8") as f:
        return f.read()


def append_text(p: str, s: str) -> None:
    with open(p, "a", encoding="utf-8") as f:
        f.write(s)


def read_json(p: str):
    """json.load, but a parse error names the file (still a json.JSONDecodeError / ValueError)."""
    with open(p, encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"{p}: invalid JSON: {e.msg}", e.doc, e.pos) from None
        except UnicodeDecodeError as e:
            raise ValueError(f"{p}: not UTF-8 text ({e.reason} at byte {e.start})") from None


def write_json(p: str, obj, **kw) -> None:
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, **kw)
