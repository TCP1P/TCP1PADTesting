#!/usr/bin/env python3
# =============================================================================
# Functionality (SLA) checker for the pwn-armory A&D challenge.
#
# Drives the menu over TCP using only its LEGITIMATE, intended behaviour — it
# never triggers any of the memory-corruption bugs. It answers "does the
# service still work?" so a defender who hardens the binary keeps SLA as long
# as the normal item-manager flow still behaves. It deliberately asserts ONLY
# behaviours that hold on both the shipped (vulnerable) build and a reasonably
# patched one — e.g. it does NOT assume the list is empty right after a delete
# (the shipped build leaves a dangling slot; a patched build clears it).
#
# enochecker3 exit-code contract: 0=Ok, 1=Mumble, 2=Offline, 3=InternalError.
# Env: GZCTF_TARGET_IP, GZCTF_TARGET_PORT (GZCTF_FLAG not needed for SLA).
# =============================================================================

import os
import socket
import sys

OK, MUMBLE, OFFLINE, INTERNAL = 0, 1, 2, 3

IP = os.environ.get("GZCTF_TARGET_IP")
PORT = os.environ.get("GZCTF_TARGET_PORT")
if not IP or not PORT:
    print("missing GZCTF_TARGET_IP / GZCTF_TARGET_PORT", file=sys.stderr)
    sys.exit(INTERNAL)

# A scripted, legitimate session. Raw item data ("hello"/"world") is exactly
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

# Expected fragments, in the order they must appear in the transcript.
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


def main():
    try:
        s = socket.create_connection((IP, int(PORT)), timeout=6)
    except OSError as e:
        print(f"connect failed: {e}", file=sys.stderr)
        sys.exit(OFFLINE)

    s.settimeout(6)
    try:
        s.sendall(SCRIPT)
    except OSError as e:
        print(f"send failed: {e}", file=sys.stderr)
        sys.exit(OFFLINE)

    chunks = []
    try:
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 1 << 20:
                break  # don't let a flooding/patched-wrong build OOM us
    except socket.timeout:
        pass  # server may not close promptly; assert on what we have
    except OSError as e:
        print(f"recv failed: {e}", file=sys.stderr)
        sys.exit(OFFLINE)
    finally:
        s.close()

    transcript = b"".join(chunks)
    if not transcript:
        print("no output from service", file=sys.stderr)
        sys.exit(OFFLINE)

    pos = 0
    for frag in EXPECT:
        idx = transcript.find(frag, pos)
        if idx < 0:
            snippet = transcript[max(0, pos - 20):pos + 120]
            print(f"missing/out-of-order {frag!r}; near: {snippet!r}", file=sys.stderr)
            sys.exit(MUMBLE)
        pos = idx + len(frag)

    sys.exit(OK)


if __name__ == "__main__":
    main()
