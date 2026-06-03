#!/usr/bin/env python3
"""
Reference solver for relic-archive.

The artifact was built as  reverse( rot13( base64( flag ) ) ), so we undo it in
the opposite order: reverse the text, ROT13 it back, then Base64-decode.

    python3 solve.py [path-to-relic.txt]
"""
import base64
import codecs
import sys


def solve(blob: str) -> str:
    step = blob.strip()[::-1]               # undo the final reverse
    step = codecs.decode(step, "rot_13")    # undo ROT13 (its own inverse)
    return base64.b64decode(step).decode()  # undo Base64


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "dist/relic.txt"
    with open(path) as f:
        print(solve(f.read()))
