#!/usr/bin/env python3
# =============================================================================
# TeamPortal — an intentionally vulnerable Attack & Defense web target.
#
# This is the OWASP-Top-10 (2021) challenge. It is a small "team portal":
# users register, log in, write private notes, search them, reset their
# password, import preferences/settings, and fetch link previews.
#
# Every legitimate feature ALSO carries one deliberately planted vulnerability,
# one per OWASP Top-10 category, and EVERY one of them yields the live flag.
# Defenders must patch the vulnerabilities WITHOUT breaking the legitimate
# functionality that the SLA checker exercises (owasp-portal-checker).
#
# Flag plumbing (same contract as the other GZCTF A&D harness challenges):
#   * The platform writes the live, per-tick flag to $GZCTF_FLAG_FILE
#     (Docker: /flag bind-mount, K8s: /gzctf-flag/flag). We read it FRESH on
#     every request — never baked into the image.
#   * The flag is exposed to the app's data layer (admin note + config table)
#     so that each vuln class has a realistic path to it.
#
# VULN MAP (path -> OWASP category):
#   A01 Broken Access Control ...... GET /api/notes/<id>      (IDOR, no owner check)
#   A02 Cryptographic Failures ..... session cookie           (forgeable role= claim)
#   A03 Injection .................. GET /api/search?q=        (string-concat SQL)
#   A04 Insecure Design ............ POST /reset               (reset token leaked in response)
#   A05 Security Misconfiguration .. GET /debug?file=          (DEBUG on -> arbitrary file read)
#   A06 Vulnerable Components ...... POST /import/yaml         (old PyYAML yaml.load -> RCE)
#   A07 Auth Failures .............. POST /login               (default creds admin:admin123, no throttle)
#   A08 Integrity Failures ......... POST /import/prefs        (pickle.loads of user data -> RCE)
#   A09 Logging Failures ........... GET /logs/<name>          (flag logged to web-served logfile)
#   A10 SSRF ....................... GET /fetch?url=           (file:// + internal access)
# =============================================================================

import base64
import json
import hmac
import hashlib
import os
import pickle
import sqlite3
import logging
import urllib.request
from flask import Flask, request, jsonify, Response, g

import yaml  # pinned to an OLD release in requirements.txt (A06)

app = Flask(__name__)

FLAG_FILE = os.environ.get("GZCTF_FLAG_FILE", "/flag")
DB_PATH = "/tmp/portal.db"
LOG_DIR = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")

# A02: a short, hard-coded, guessable signing secret. The session cookie is a
# signed-but-weak token; the secret is trivially brute-forced / leaked via the
# other bugs, after which any role can be forged.
COOKIE_SECRET = b"secret"

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("portal")


# ----------------------------------------------------------------------------
# Flag helpers
# ----------------------------------------------------------------------------
def read_flag():
    """Read the live flag fresh from disk every time (platform rotates it)."""
    try:
        with open(FLAG_FILE, "r") as f:
            return f.read().strip()
    except OSError:
        return "flag{warming_up}"


# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
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
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT,
            title TEXT,
            body TEXT
        );
        CREATE TABLE IF NOT EXISTS config (
            k TEXT PRIMARY KEY,
            v TEXT
        );
        """
    )
    # A07: a default admin account with weak, well-known credentials.
    db.execute(
        "INSERT OR IGNORE INTO users(id, username, password, role) VALUES (1,'admin','admin123','admin')"
    )
    # The admin's note #1 holds the live flag (refreshed below). A01 IDOR
    # reads it without an ownership check.
    db.execute("INSERT OR IGNORE INTO notes(id, owner, title, body) VALUES (1,'admin','Recovery Codes','')")
    db.commit()
    db.close()


def refresh_secrets():
    """Push the current flag into the data layer so every vuln path can reach it.

    Runs before each request: the platform rotates the flag each tick, and we
    keep the admin note + config table in sync so SQLi (A03) and IDOR (A01)
    expose the *current* flag.
    """
    flag = read_flag()
    db = get_db()
    db.execute("UPDATE notes SET body=? WHERE id=1", (flag,))
    db.execute("INSERT INTO config(k,v) VALUES('flag',?) "
               "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (flag,))
    db.commit()


@app.before_request
def _before():
    refresh_secrets()


# ----------------------------------------------------------------------------
# A02: weak session cookie (signed JSON, guessable secret, forgeable role)
# ----------------------------------------------------------------------------
def make_cookie(uid, username, role):
    payload = base64.urlsafe_b64encode(
        json.dumps({"uid": uid, "username": username, "role": role}).encode()
    )
    sig = hmac.new(COOKIE_SECRET, payload, hashlib.md5).hexdigest()  # weak: md5 + short secret
    return payload.decode() + "." + sig


def parse_cookie(raw):
    if not raw or "." not in raw:
        return None
    payload, sig = raw.rsplit(".", 1)
    expected = hmac.new(COOKIE_SECRET, payload.encode(), hashlib.md5).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def current_user():
    return parse_cookie(request.cookies.get("session", ""))


# ----------------------------------------------------------------------------
# Health + landing (functionality)
# ----------------------------------------------------------------------------
@app.route("/health")
def health():
    return "ok"


@app.route("/")
def index():
    return (
        "TeamPortal\n"
        "  POST /register {username,password}\n"
        "  POST /login    {username,password}\n"
        "  GET  /me\n"
        "  POST /api/notes {title,body}    GET /api/notes    GET /api/notes/<id>\n"
        "  GET  /api/search?q=\n"
        "  POST /reset {username}          POST /reset/confirm {token,password}\n"
        "  POST /import/yaml   POST /import/prefs   GET /export/prefs\n"
        "  GET  /fetch?url=\n"
        "  GET  /admin\n"
    )


# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify(error="username and password required"), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users(username, password, role) VALUES (?,?,'user')",
            (username, password),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username taken"), 409
    return jsonify(ok=True, id=cur.lastrowid)


@app.route("/login", methods=["POST"])
def login():
    # A07: parameterised here (so it's not ALSO SQLi), but there is NO rate
    # limiting / lockout, and the seeded admin:admin123 default account makes
    # brute force / credential-stuffing trivial.
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    db = get_db()
    row = db.execute(
        "SELECT id, username, role FROM users WHERE username=? AND password=?",
        (username, password),
    ).fetchone()
    if not row:
        log.info("failed login for %s", username)
        return jsonify(error="invalid credentials"), 401
    resp = jsonify(ok=True, role=row["role"])
    resp.set_cookie("session", make_cookie(row["id"], row["username"], row["role"]))
    return resp


@app.route("/me")
def me():
    u = current_user()
    if not u:
        return jsonify(error="not authenticated"), 401
    return jsonify(u)


# ----------------------------------------------------------------------------
# Notes (functionality core) + A01 IDOR + A03 SQLi
# ----------------------------------------------------------------------------
@app.route("/api/notes", methods=["POST"])
def create_note():
    u = current_user()
    if not u:
        return jsonify(error="not authenticated"), 401
    data = request.get_json(silent=True) or request.form
    title = data.get("title") or ""
    body = data.get("body") or ""
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes(owner, title, body) VALUES (?,?,?)",
        (u["username"], title, body),
    )
    db.commit()
    return jsonify(ok=True, id=cur.lastrowid)


@app.route("/api/notes", methods=["GET"])
def list_notes():
    u = current_user()
    if not u:
        return jsonify(error="not authenticated"), 401
    db = get_db()
    rows = db.execute(
        "SELECT id, title FROM notes WHERE owner=? ORDER BY id", (u["username"],)
    ).fetchall()
    return jsonify(notes=[dict(r) for r in rows])


@app.route("/api/notes/<int:note_id>", methods=["GET"])
def get_note(note_id):
    # A01 Broken Access Control: a session is required, but there is NO check
    # that the note belongs to the caller — any authenticated user can read any
    # note id, including admin's note #1 which contains the flag (IDOR).
    u = current_user()
    if not u:
        return jsonify(error="not authenticated"), 401
    db = get_db()
    row = db.execute(
        "SELECT id, owner, title, body FROM notes WHERE id=?", (note_id,)
    ).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))


@app.route("/api/search")
def search():
    # A03 Injection: q is concatenated straight into the SQL text. A normal
    # query (?q=foo) does a LIKE search over the caller's own notes; an
    # attacker can UNION-select the flag out of the config table:
    #   ?q=zzz' UNION SELECT 1,'pwn',v,'x' FROM config-- -
    u = current_user()
    if not u:
        return jsonify(error="not authenticated"), 401
    q = request.args.get("q", "")
    db = get_db()
    sql = (
        "SELECT id, title, body FROM notes "
        "WHERE owner='%s' AND (title LIKE '%%%s%%' OR body LIKE '%%%s%%')"
        % (u["username"], q, q)
    )
    try:
        rows = db.execute(sql).fetchall()
    except sqlite3.Error as e:
        return jsonify(error=str(e), sql=sql), 400
    return jsonify(results=[dict(r) for r in rows])


# ----------------------------------------------------------------------------
# A04: insecure-design password reset (token disclosed in the response body)
# ----------------------------------------------------------------------------
@app.route("/reset", methods=["POST"])
def reset_request():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify(error="no such user"), 404
    # Insecure design: a short, predictable token is generated AND handed back
    # in the HTTP response instead of being sent out-of-band. Anyone can reset
    # anyone's password — including admin's — and then read the flag at /admin.
    token = hashlib.md5(("reset" + username).encode()).hexdigest()[:8]
    db.execute("UPDATE users SET reset_token=? WHERE username=?", (token, username))
    db.commit()
    return jsonify(ok=True, token=token, note="dev build returns token in response")


@app.route("/reset/confirm", methods=["POST"])
def reset_confirm():
    data = request.get_json(silent=True) or request.form
    token = data.get("token") or ""
    password = data.get("password") or ""
    if not token or not password:
        return jsonify(error="token and password required"), 400
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE reset_token=?", (token,)).fetchone()
    if not row:
        return jsonify(error="invalid token"), 400
    db.execute(
        "UPDATE users SET password=?, reset_token=NULL WHERE username=?",
        (password, row["username"]),
    )
    db.commit()
    return jsonify(ok=True)


# ----------------------------------------------------------------------------
# A05: security misconfiguration — DEBUG on exposes an arbitrary file reader
# ----------------------------------------------------------------------------
@app.route("/debug")
def debug():
    # Shipped with DEBUG enabled. The "view a server file for troubleshooting"
    # helper does no path validation: ?file=/flag reads the live flag.
    if os.environ.get("APP_DEBUG", "1") != "1":
        return jsonify(error="debug disabled"), 403
    target = request.args.get("file", "")
    if not target:
        return jsonify(debug=True, env=dict(os.environ), cwd=os.getcwd())
    try:
        with open(target, "r") as f:
            return Response(f.read(), mimetype="text/plain")
    except OSError as e:
        return jsonify(error=str(e)), 400


# ----------------------------------------------------------------------------
# A06: vulnerable/outdated component — old PyYAML full-load (RCE)
# ----------------------------------------------------------------------------
@app.route("/import/yaml", methods=["POST"])
def import_yaml():
    # "Import settings as YAML." Uses the FULL loader of an outdated PyYAML
    # (pinned <5.1 in requirements.txt) which constructs arbitrary Python
    # objects — e.g. !!python/object/apply:os.system or subprocess to read /flag.
    raw = request.get_data(as_text=True)
    try:
        loaded = yaml.load(raw)  # noqa: S506 — intentionally unsafe (A06)
    except Exception as e:
        return jsonify(error=str(e)), 400
    return jsonify(ok=True, loaded=str(loaded))


# ----------------------------------------------------------------------------
# A08: software & data integrity failure — pickle of attacker-controlled data
# ----------------------------------------------------------------------------
@app.route("/export/prefs")
def export_prefs():
    u = current_user() or {"username": "guest", "theme": "light"}
    blob = base64.b64encode(pickle.dumps({"username": u.get("username"), "theme": "light"}))
    return jsonify(prefs=blob.decode())


@app.route("/import/prefs", methods=["POST"])
def import_prefs():
    # Round-trips the blob from /export/prefs. It pickle-loads attacker bytes,
    # so a crafted __reduce__ payload runs code and can read /flag (A08).
    data = request.get_json(silent=True) or request.form
    blob = data.get("prefs") or ""
    try:
        prefs = pickle.loads(base64.b64decode(blob))  # noqa: S301 — intentional (A08)
    except Exception as e:
        return jsonify(error=str(e)), 400
    return jsonify(ok=True, prefs=str(prefs))


# ----------------------------------------------------------------------------
# A09: security logging failure — sensitive data logged to a web-served file
# ----------------------------------------------------------------------------
@app.route("/admin")
def admin():
    # Legit admins (role=admin via real login OR a forged A02 cookie) see the
    # flag. The A09 twist: every admin view logs the flag in cleartext to
    # app.log, and that log directory is served unauthenticated at /logs/...
    u = current_user()
    if not u or u.get("role") != "admin":
        return jsonify(error="forbidden"), 403
    flag = read_flag()
    log.info("admin %s viewed dashboard; flag=%s", u.get("username"), flag)  # A09: logs the secret
    return jsonify(dashboard=True, flag=flag)


@app.route("/logs/<path:name>")
def logs(name):
    # "Static" log viewer with no auth and no path containment beyond basename.
    # /logs/app.log discloses everything logged above, including the flag (A09).
    path = os.path.join(LOG_DIR, os.path.basename(name))
    try:
        with open(path, "r") as f:
            return Response(f.read(), mimetype="text/plain")
    except OSError:
        return jsonify(error="not found"), 404


# ----------------------------------------------------------------------------
# A10: SSRF — server-side fetch with no scheme/host restrictions
# ----------------------------------------------------------------------------
@app.route("/fetch")
def fetch():
    # "Link preview": fetch a URL server-side. No allow-list, no scheme filter,
    # so file:///flag (or http://127.0.0.1/admin via a forged cookie) leaks.
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="url required"), 400
    try:
        with urllib.request.urlopen(url, timeout=4) as r:  # noqa: S310 — intentional (A10)
            body = r.read(65536).decode("utf-8", "replace")
        return Response(body, mimetype="text/plain")
    except Exception as e:
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, threaded=True)
