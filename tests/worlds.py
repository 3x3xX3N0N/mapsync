"""Shared helpers: temp copies of the shipped world and freshly keyed demo worlds."""
import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from mapsynclib import REPO  # noqa: E402
from mapsynclib.demo import make_world  # noqa: E402
from mapsynclib.g1 import sandbox  # noqa: E402

SHIPPED_ROOTS = {
    "alice": "656b6e9d362ee0bba42bd5cef266a5ae604f5194dc55eef25ae6cbe0c983f626",
    "bob": "2ea2aa8c1191e1d9c8e7960623187919e0c29f95191697265bcb65c2d8762af7",
}
SHIPPED_TOP = "5063e96c07099d44d4ea013eacaebc0b089ebf151c64ebc8e05178d7cf61f7fd"


def tmpdir(test: unittest.TestCase) -> str:
    d = tempfile.mkdtemp(prefix="mapsync-test-")
    test.addCleanup(shutil.rmtree, d, True)
    return d


def shipped_copy(test: unittest.TestCase) -> str:
    """A throwaway copy of the shipped example (no private keys)."""
    return sandbox(REPO, os.path.join(tmpdir(test), "w"))


def demo_world(test: unittest.TestCase) -> dict:
    """A fresh signed world with ephemeral keys; see mapsynclib.demo.make_world."""
    return make_world(os.path.join(tmpdir(test), "w"))


def quietly(fn, *a, **kw):
    """Run fn with stdout captured; returns (result, output)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **kw)
    return r, buf.getvalue()
