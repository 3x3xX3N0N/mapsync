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
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def write_json(p: str, obj, **kw) -> None:
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, **kw)
