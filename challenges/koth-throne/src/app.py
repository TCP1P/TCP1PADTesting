#!/usr/bin/env python3
# =============================================================================
# Throne Room — an intentionally vulnerable King-of-the-Hill "hill".
#
# ONE shared container for the whole game. There is NO per-team flag. Teams
# compete to control the hill by landing their platform-issued, per-round
# control TOKEN into the marker file the platform reads each tick:
#
#       /koth/king        (the platform Trim()s it and matches it EXACTLY
#                          against the round token -> must equal the token)
#
# The hill exposes a privileged "crown" that writes /koth/king. Legitimately
# only an admin may crown, and players get no admin account — so taking the
# hill REQUIRES exploiting one of the planted OWASP Top 10 (2021) bugs. Every
# bug below ends in an exact write of an attacker-chosen string to /koth/king
# (either by reaching the crown, or by writing the marker directly via RCE /
# arbitrary-write). The defender's job is to patch the bugs while keeping GET /
# and the legitimate crown working (so the hill stays healthy and claimable).
#
# VULN MAP (path -> OWASP category -> how it crowns):
#   A01 Broken Access Control ...... POST /throne w/ X-User-Role: admin header
#   A02 Cryptographic Failures ..... forge weak session cookie (role=admin) -> /throne
#   A03 Injection .................. POST /login SQLi auth-bypass -> admin -> /throne
#   A04 Insecure Design ............ POST /reset leaks token -> take admin -> /throne
#   A05 Security Misconfiguration .. GET /debug/write?file=/koth/king&data=TOKEN
#   A06 Vulnerable Components ....... POST /import/yaml PyYAML RCE -> write marker
#   A07 Auth Failures .............. default creds admin:admin123 -> /throne
#   A08 Integrity Failures ......... POST /import/prefs pickle RCE -> write marker
#   A09 Logging Failures ........... X-Forwarded-Log header -> raw access-log write
#   A10 SSRF ....................... GET /fetch?url=http://127.0.0.1:8080/internal/crown?token=
# =============================================================================

import base64
import hashlib
import hmac
import json
import os
import pickle
import sqlite3
import urllib.request

import yaml  # pinned OLD in requirements.txt (A06)
from flask import Flask, request, jsonify, Response, g

app = Flask(__name__)

KING_FILE = "/koth/king"          # platform reads THIS exact path each tick
DB_PATH = "/tmp/throne.db"
COOKIE_SECRET = b"secret"         # A02: short, guessable signing secret

os.makedirs("/koth", exist_ok=True)


# ----------------------------------------------------------------------------
# The crown: the ONE place that writes the marker. Atomic so the platform never
# reads a half-written /koth/king. Writes EXACTLY the token (no prefix) so the
# platform's Trim()+equality match succeeds.
# ----------------------------------------------------------------------------
def do_crown(token: str):
    token = (token or "").strip()
    tmp = KING_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(token)
    os.replace(tmp, KING_FILE)


def read_king() -> str:
    try:
        with open(KING_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


# ----------------------------------------------------------------------------
# DB (for the SQLi + auth bugs)
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_e):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            reset_token TEXT
        );
        """
    )
    # A07: default admin with weak, well-known credentials.
    db.execute("INSERT OR IGNORE INTO users(id,username,password,role) VALUES (1,'admin','admin123','admin')")
    db.commit()
    db.close()


# ----------------------------------------------------------------------------
# A02: weak, forgeable session cookie (md5 + guessable secret)
# ----------------------------------------------------------------------------
def make_cookie(uid, username, role):
    p = base64.urlsafe_b64encode(json.dumps({"uid": uid, "username": username, "role": role}).encode())
    sig = hmac.new(COOKIE_SECRET, p, hashlib.md5).hexdigest()
    return p.decode() + "." + sig


def parse_cookie(raw):
    if not raw or "." not in raw:
        return None
    p, sig = raw.rsplit(".", 1)
    if not hmac.compare_digest(sig, hmac.new(COOKIE_SECRET, p.encode(), hashlib.md5).hexdigest()):
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return None


def is_admin() -> bool:
    u = parse_cookie(request.cookies.get("session", ""))
    if u and u.get("role") == "admin":
        return True
    # A01 Broken Access Control: trust a client-supplied role header.
    return request.headers.get("X-User-Role", "") == "admin"


# ----------------------------------------------------------------------------
# A09: logging misconfiguration — a per-request access log whose PATH comes
# from a client header and whose CONTENT is the raw User-Agent (no prefix,
# truncating write). X-Forwarded-Log: /koth/king + User-Agent: <token> writes
# exactly the token to the marker.
# ----------------------------------------------------------------------------
@app.before_request
def access_log():
    init_once()
    path = request.headers.get("X-Forwarded-Log")
    if path:
        try:
            with open(path, "w") as f:                 # truncating, raw content
                f.write(request.headers.get("User-Agent", ""))
        except OSError:
            pass


_INITED = False


def init_once():
    global _INITED
    if not _INITED:
        init_db()
        _INITED = True


# ----------------------------------------------------------------------------
# Health + throne view (functionality the checker relies on)
# ----------------------------------------------------------------------------
@app.route("/health")
def health():
    return "ok"


@app.route("/")
def index():
    king = read_king() or "(nobody)"
    return Response(
        f"king of the hill — Throne Room\ncurrent king token: {king}\n",
        mimetype="text/plain",
    )


# ----------------------------------------------------------------------------
# The privileged crown action (legit path: admin only)
# ----------------------------------------------------------------------------
@app.route("/throne", methods=["POST"])
def throne():
    if not is_admin():                                  # A01/A02/A03/A04/A07 reach this
        return jsonify(error="forbidden — only the admin may crown"), 403
    data = request.get_json(silent=True) or request.form
    token = data.get("token") or ""
    if not token:
        return jsonify(error="token required"), 400
    do_crown(token)
    return jsonify(ok=True, king=read_king())


# ----------------------------------------------------------------------------
# Auth (A03 SQLi bypass, A07 default creds)
# ----------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    d = request.get_json(silent=True) or request.form
    u, p = (d.get("username") or "").strip(), d.get("password") or ""
    if not u or not p:
        return jsonify(error="username and password required"), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users(username,password,role) VALUES (?,?,'user')", (u, p))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username taken"), 409
    return jsonify(ok=True)


@app.route("/login", methods=["POST"])
def login():
    # A03 Injection: username/password concatenated into the query, so
    #   username = admin'--   (or  ' OR role='admin'-- )  bypasses the password.
    # A07 also lives here: the default admin:admin123 just works.
    d = request.get_json(silent=True) or request.form
    u, p = (d.get("username") or ""), (d.get("password") or "")
    db = get_db()
    sql = "SELECT id, username, role FROM users WHERE username='%s' AND password='%s'" % (u, p)
    try:
        row = db.execute(sql).fetchone()
    except sqlite3.Error as e:
        return jsonify(error=str(e), sql=sql), 400
    if not row:
        return jsonify(error="invalid credentials"), 401
    resp = jsonify(ok=True, role=row["role"])
    resp.set_cookie("session", make_cookie(row["id"], row["username"], row["role"]))
    return resp


# ----------------------------------------------------------------------------
# A04: insecure-design password reset (token disclosed in the response)
# ----------------------------------------------------------------------------
@app.route("/reset", methods=["POST"])
def reset():
    d = request.get_json(silent=True) or request.form
    u = (d.get("username") or "").strip()
    db = get_db()
    if not db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
        return jsonify(error="no such user"), 404
    token = hashlib.md5(("reset" + u).encode()).hexdigest()[:8]
    db.execute("UPDATE users SET reset_token=? WHERE username=?", (token, u))
    db.commit()
    return jsonify(ok=True, token=token)            # leaked in response


@app.route("/reset/confirm", methods=["POST"])
def reset_confirm():
    d = request.get_json(silent=True) or request.form
    token, pw = d.get("token") or "", d.get("password") or ""
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE reset_token=?", (token,)).fetchone()
    if not row:
        return jsonify(error="invalid token"), 400
    db.execute("UPDATE users SET password=?, reset_token=NULL WHERE username=?", (pw, row["username"]))
    db.commit()
    return jsonify(ok=True)


# ----------------------------------------------------------------------------
# A05: security misconfiguration — DEBUG on exposes an arbitrary file WRITER
# ----------------------------------------------------------------------------
@app.route("/debug/write")
def debug_write():
    if os.environ.get("APP_DEBUG", "1") != "1":
        return jsonify(error="debug disabled"), 403
    target, data = request.args.get("file", ""), request.args.get("data", "")
    if not target:
        return jsonify(error="file required"), 400
    try:
        with open(target, "w") as f:
            f.write(data)
        return jsonify(ok=True)
    except OSError as e:
        return jsonify(error=str(e)), 400


# ----------------------------------------------------------------------------
# A06: vulnerable/outdated component — old PyYAML full-load (RCE)
# ----------------------------------------------------------------------------
@app.route("/import/yaml", methods=["POST"])
def import_yaml():
    try:
        loaded = yaml.load(request.get_data(as_text=True))   # unsafe full loader
    except Exception as e:
        return jsonify(error=str(e)), 400
    return jsonify(ok=True, loaded=str(loaded))


# ----------------------------------------------------------------------------
# A08: software & data integrity failure — pickle of attacker-controlled data
# ----------------------------------------------------------------------------
@app.route("/export/prefs")
def export_prefs():
    return jsonify(prefs=base64.b64encode(pickle.dumps({"theme": "throne"})).decode())


@app.route("/import/prefs", methods=["POST"])
def import_prefs():
    d = request.get_json(silent=True) or request.form
    try:
        prefs = pickle.loads(base64.b64decode(d.get("prefs") or ""))
    except Exception as e:
        return jsonify(error=str(e)), 400
    return jsonify(ok=True, prefs=str(prefs))


# ----------------------------------------------------------------------------
# A10: SSRF — server-side fetch, no scheme/host filter, can reach the
# localhost-only internal crown.
# ----------------------------------------------------------------------------
@app.route("/internal/crown")
def internal_crown():
    # "Trusted" internal endpoint: only callable from localhost... which SSRF
    # makes reachable. Crowns whatever token is passed.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify(error="internal only"), 403
    token = request.args.get("token", "")
    if not token:
        return jsonify(error="token required"), 400
    do_crown(token)
    return jsonify(ok=True, king=read_king())


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="url required"), 400
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            return Response(r.read(65536).decode("utf-8", "replace"), mimetype="text/plain")
    except Exception as e:
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    init_once()
    app.run(host="0.0.0.0", port=8080, threaded=True)
