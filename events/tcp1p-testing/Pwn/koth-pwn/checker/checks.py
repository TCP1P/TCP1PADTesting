"""
HEALTH checks for the koth-pwn hill — KotH has NO per-team flag, so this is a
pure health probe (Ok / Mumble / Offline) that gates hold points vs. the
broken-hill penalty. The harness (checker.py) is HTTP-oriented but a Target
still carries .ip/.port, so these checks open a raw socket.

CRUCIAL: this is read-only — it never sets the banner, never flips is_admin,
and never crowns, so it cannot write /koth/king or disturb the current king.
It only confirms the hill is alive and the crown is still guarded.

Verdicts: return = Ok, raise Mumble = up-but-degraded, raise Offline = down.
"""
import socket

from checker import Mumble, Offline, check


def _talk(t, payload, settle=1.5):
    try:
        s = socket.create_connection((t.ip, t.port), timeout=6)
    except OSError as e:
        raise Offline(f"connect {t.ip}:{t.port}: {e}") from e
    s.settimeout(settle)
    buf = b""
    try:
        s.sendall(payload)
        while True:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            if not c:
                break
            buf += c
            if len(buf) > (1 << 20):
                break
    except OSError as e:
        raise Offline(f"io on {t.ip}:{t.port}: {e}") from e
    finally:
        s.close()
    return buf


@check
def hill_menu_alive(t):
    """Connecting must present the KotH menu — otherwise the hill is down."""
    out = _talk(t, b"2\n0\n")           # Show banner, then Exit
    if not out:
        raise Offline("no output from hill")
    if b"King of the Hill: Throne" not in out:
        raise Mumble(f"unexpected hill banner: {out[:120]!r}")


@check
def crown_is_guarded(t):
    """A crown attempt with no admin foothold must be DENIED — proving the
    hill is contestable-by-exploit-only and the crown path isn't bricked.
    (Read-only: this neither sets the banner nor flips is_admin, so it cannot
    write /koth/king.)"""
    out = _talk(t, b"6\n0\n")           # Crown (not admin) -> denied, then Exit
    if b"denied" not in out:
        raise Mumble(f"crown not guarded (expected 'denied'): {out[:160]!r}")
