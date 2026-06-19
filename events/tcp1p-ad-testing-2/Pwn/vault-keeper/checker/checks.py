"""
SLA test cases for vault-keeper — FUNCTIONALITY ONLY.

Drives the menu over a raw TCP socket using only its legitimate, intended
behaviour; it NEVER triggers the use-after-free. The harness (checker.py) is
HTTP-oriented, but a Target still carries .ip/.port/.flag, so these checks open
their own socket and map connection failures to Offline.

It asserts ONLY behaviours that hold on BOTH the shipped (vulnerable) build and
a null-on-free patched build. In particular it deliberately does NOT show a slot
after deleting it (that would rely on the dangling-pointer bug). A defender who
adds `notes[idx] = NULL;` on delete keeps this SLA green while killing the UAF.

Verdicts: return = Ok, raise Mumble = up-but-wrong, raise Offline = unreachable.
"""
import socket

from checker import Mumble, Offline, check

# A scripted legitimate session. Raw note data ("hello"/"world") is exactly
# `size` bytes with NO trailing newline so the binary's exact-length read
# consumes precisely those bytes and the following menu choice lines stay
# aligned.
#
# Vault menu shapes (NOTE: different field counts from other templates):
#   create: 1\n<idx>\n<size>\n<data:size bytes>   (data is exactly `size` bytes)
#   show:   2\n<idx>\n                            -> DATA: <data>
#   edit:   3\n<idx>\n<data:size bytes>           (reads exactly the slot's size)
#   delete: 4\n<idx>\n                            -> OK freed
#   exit:   9\n
SCRIPT = (
    b"1\n0\n5\nhello"   # Create: slot 0, size 5, data "hello"  -> OK index=0
    b"2\n0\n"           # Show slot 0                            -> DATA: hello
    b"3\n0\nworld"      # Edit slot 0, 5 bytes "world"           -> OK edited
    b"2\n0\n"           # Show slot 0                            -> DATA: world
    b"4\n0\n"           # Delete slot 0                          -> OK freed
    b"9\n"             # Exit                                    -> bye
)

# Fragments that must appear, in this order, in the transcript. Every one holds
# on both the vulnerable and the null-on-free patched build.
EXPECT = [
    b"=== Vault ===",
    b"OK index=0",
    b"DATA: hello",
    b"OK edited",
    b"DATA: world",
    b"OK freed",
]


@check
def menu_flow(t):
    """Create -> Show -> Edit -> Show -> Delete -> Exit, all via the legitimate
    menu, asserting the intended outputs in order. No show-after-delete, so the
    check passes identically on the patched build."""
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
