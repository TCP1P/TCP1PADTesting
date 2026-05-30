"""
SLA test cases for pwn-armory — FUNCTIONALITY ONLY.

Drives the menu over a raw TCP socket using only its legitimate, intended
behaviour; it never triggers any of the memory-corruption bugs. The harness
(checker.py) is HTTP-oriented, but a Target still carries .ip/.port/.flag, so
these checks open their own socket and map connection failures to Offline.

It asserts ONLY behaviours that hold on BOTH the shipped (vulnerable) build and
a reasonably patched one — e.g. it does not assume the item list is empty right
after a delete (the shipped build leaves a dangling slot; a patched build
clears it). That keeps a defender's SLA green while they harden the binary.

Verdicts: return = Ok, raise Mumble = up-but-wrong, raise Offline = unreachable.
"""
import socket

from checker import Mumble, Offline, check

# A scripted legitimate session. Raw item data ("hello"/"world") is exactly
# `size` bytes with NO trailing newline so the binary's exact-length read
# consumes precisely those bytes and the following menu choice lines stay
# aligned.
SCRIPT = (
    b"1\n0\n5\n5\nhello"   # Add: slot 0, size 5, write 5 bytes "hello"
    b"2\n0\n"              # Show slot 0           -> DATA: hello
    b"5\n"                 # List                  -> ITEMS: 0
    b"3\n0\n5\nworld"      # Edit slot 0, 5 bytes "world"
    b"2\n0\n"              # Show slot 0           -> DATA: world
    b"6\nECHOMARK\n"       # Echo benign string    -> ECHOMARK
    b"8\n"                 # Secret (locked)       -> Access denied.
    b"4\n0\n"              # Delete slot 0         -> OK freed
    b"9\n"                 # Exit
)

# Fragments that must appear, in this order, in the transcript.
EXPECT = [
    b"=== Armory ===",
    b"OK index=0",
    b"DATA: hello",
    b"ITEMS: 0",
    b"OK edited",
    b"DATA: world",
    b"ECHOMARK",
    b"Access denied.",
    b"OK freed",
]


@check
def menu_flow(t):
    """Add -> Show -> List -> Edit -> Show -> Echo -> Secret(locked) -> Delete,
    all via the legitimate menu, asserting the intended outputs in order."""
    try:
        s = socket.create_connection((t.ip, t.port), timeout=6)
    except OSError as e:
        raise Offline(f"connect {t.ip}:{t.port}: {e}") from e

    s.settimeout(6)
    chunks = []
    try:
        s.sendall(SCRIPT)
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break  # service may not close promptly; assert on what we have
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > (1 << 20):
                break  # don't let a misbehaving build OOM the checker
    except OSError as e:
        raise Offline(f"io on {t.ip}:{t.port}: {e}") from e
    finally:
        s.close()

    transcript = b"".join(chunks)
    if not transcript:
        raise Offline("no output from service")

    pos = 0
    for frag in EXPECT:
        idx = transcript.find(frag, pos)
        if idx < 0:
            near = transcript[max(0, pos - 20):pos + 120]
            raise Mumble(f"missing/out-of-order {frag!r}; near: {near!r}")
        pos = idx + len(frag)
