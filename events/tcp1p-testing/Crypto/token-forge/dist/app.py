#!/usr/bin/env python3
"""
token-forge — a JWT "members area" whose verifier still accepts alg:"none".

Legit tokens are signed HS256 with a server secret you cannot recover. The bug
is that verify() trusts the *token's* `alg` header and treats the RFC-7519
"unsecured" value `none` as valid — so an attacker forges an admin token with an
empty signature. GET /flag returns $GZCTF_FLAG to any admin token.
"""
import base64
import hashlib
import hmac
import json
import os

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

# Server signing key for legitimately-issued (HS256) tokens. NOT leaked anywhere
# and not meant to be recovered — you bypass it via the alg-confusion bug below.
SECRET = os.environ.get("JWT_SECRET", "n0t-th3-w4y-1n-a91f33d7").encode()


def b64u(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def b64u_dec(seg: bytes) -> bytes:
    return base64.urlsafe_b64decode(seg + b"=" * (-len(seg) % 4))


def _sig(signing_input: bytes) -> bytes:
    return b64u(hmac.new(SECRET, signing_input, hashlib.sha256).digest())


def issue(payload: dict) -> str:
    head = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64u(json.dumps(payload).encode())
    return b".".join([head, body, _sig(head + b"." + body)]).decode()


def verify(token: str):
    try:
        head_b, body_b, sig_b = token.encode().split(b".")
        header = json.loads(b64u_dec(head_b))
        payload = json.loads(b64u_dec(body_b))
    except Exception:
        return None
    alg = (header.get("alg") or "").lower()
    if alg == "none":  # <-- BUG: "unsecured" JWT accepted; the signature is ignored
        return payload
    if alg == "hs256" and hmac.compare_digest(_sig(head_b + b"." + body_b), sig_b):
        return payload
    return None


PAGE = """<!doctype html><meta charset=utf-8><title>token-forge</title>
<h1>members area</h1>
<p>Signed in as <b>{user}</b> (admin={admin}). Your JWT is in the <code>auth</code>
cookie; <code>GET /flag</code> needs an <b>admin</b> token.</p>
<pre>{token}</pre>"""


@app.get("/")
def index():
    tok = issue({"user": "guest", "admin": False})
    resp = make_response(PAGE.format(user="guest", admin=False, token=tok))
    resp.set_cookie("auth", tok)
    return resp


@app.get("/flag")
def flag():
    tok = request.cookies.get("auth") or request.args.get("token", "")
    claims = verify(tok)
    if not claims or not claims.get("admin"):
        return jsonify(error="forbidden: an admin token is required"), 403
    return jsonify(flag=os.environ.get("GZCTF_FLAG", "TCP1P{local_test_flag_not_injected}"))


@app.get("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
