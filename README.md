# TCP1P A&D + KotH Testing

Four challenges for [GZCTF](https://github.com/GZTimeWalker/GZCTF) — an **OWASP
Top 10** target and a **PWN** target in each of two live-engine modes:
**Attack & Defense** and **King of the Hill**. Import the whole set into a GZCTF
instance with one **repo binding** (admin → Repo Bindings): the server clones
this repo, turns `events/tcp1p-testing/.gzevent` into a Game, and imports every
`challenge.yml` beneath it — the `src/` services and `checker/` images build
automatically, so there's nothing to push.

```
events/
  tcp1p-testing/
    .gzevent                   # → one Game (the repo binding imports this)
    Web/
      owasp-portal/   (A&D)    OWASP Top 10 web target — every vuln leaks the flag
      koth-throne/    (KotH)   OWASP Top 10 web hill — every vuln crowns you
    Pwn/
      pwn-armory/     (A&D)    multi-bug PWN target — every bug leaks the flag
      koth-pwn/       (KotH)   multi-bug PWN hill — every bug crowns you
# each leaf: challenge.yml + src/{Dockerfile,…} + checker/{checker.py,checks.py,run.py,…} + solver/solve.py
```

The **category is the folder** (`Web/`, `Pwn/`) — the importer takes it from the
path (the `category:` in each `challenge.yml` is kept in sync for clarity).

> Need a platform to import these into first? Stand one up with the
> [GZCTF platform template](https://github.com/TCP1P/gzctf-platform-template)
> (`make wizard && make setup && make platform-up`).

**Template contract.** The **service** auto-builds from `./src/Dockerfile`
(supervisord PID 1 so a botched exploit doesn't drop the box). The **checker**
is the enochecker3 harness — `checker.py`/`run.py` copied verbatim, you only edit
`checks.py` (each `@check` gets a `Target`; return = Ok, `raise Mumble` =
up-but-wrong, `t.get/post`/sockets → `Offline`). **All four checkers verify
functionality/health only**; capturing the flag (A&D) or crowning (KotH) is the
`solver/` job.

- **A&D**: one container per team; the platform plants a fresh flag at
  `$GZCTF_FLAG_FILE` each tick. Steal other teams' flags and submit them.
- **KotH**: ONE shared "hill"; no per-team flag. Each round the platform issues
  a control token — write it **exactly** into `/koth/king` (the platform
  `Trim()`s the file and matches it against the token). Hold it while the hill
  is healthy to score. `allowSelfReset: false` (shared hill).

---

## Challenge 1 — `owasp-portal` (OWASP Top 10, every vuln leaks the flag)

A Flask "team portal" (register / login / notes CRUD / search / password reset /
settings & prefs import / link preview). Each legitimate feature carries one
OWASP-2021 vuln; the live flag is mirrored into admin note #1 and the `config`
table each request so every class can reach it.

| OWASP 2021 | Where | Flag leak |
|------------|-------|-----------|
| A01 Broken Access Control | `GET /api/notes/<id>` | IDOR — no ownership check, read admin note #1 |
| A02 Cryptographic Failures | `session` cookie | `md5`/secret=`"secret"` → forge `role=admin` → `/admin` |
| A03 Injection | `GET /api/search?q=` | `' ) UNION SELECT 1,k,v FROM config-- -` |
| A04 Insecure Design | `POST /reset` | reset token returned in response → admin takeover |
| A05 Security Misconfiguration | `GET /debug?file=/flag` | arbitrary file read (DEBUG on) |
| A06 Vulnerable Components | `POST /import/yaml` | PyYAML 3.13 `yaml.load` → `!!python/object` RCE |
| A07 Auth Failures | `POST /login` | default `admin:admin123`, no rate limit |
| A08 Integrity Failures | `POST /import/prefs` | `pickle.loads` of user blob → RCE |
| A09 Logging Failures | `GET /logs/app.log` | flag logged cleartext to a web-served log |
| A10 SSRF | `GET /fetch?url=file:///flag` | no scheme/host filter |

`solver/solve.py` implements all ten paths; `checker/checks.py` exercises only
the legitimate flow (`health` + a full `core_flow`).

## Challenge 2 — `pwn-armory` (many PWN bugs)

A C menu heap "item manager" over TCP (one process/connection via socat),
compiled **no canary / no PIE / no RELRO / exec stack**. `print_flag()` reads
`$GZCTF_FLAG_FILE` and is the canonical win target.

| Bug | Menu | Notes |
|-----|------|-------|
| Stack buffer overflow | `0` Set nick | 32B buf, `read()` 256 → ret2win (offset 40, `print_flag@0x401226`+1) |
| Format string | `6` Echo | `printf(buf)` → leak + `%n` write `admin` |
| Use-after-free / double free | `4` Delete | slot never NULLed; free-twice |
| OOB array index | `1/2/3/4` | `idx` unchecked (incl. negative) |
| Signed size → malloc | `1` Add | negative size → huge `size_t` |
| Heap overflow | `3` Edit | writes a caller-supplied length, unbounded |
| Command injection | `7` Ping | `system("ping -c1 " + host)` |
| Uninitialized heap leak | `1`→`2` | `malloc` not zeroed + optional write |

`solver/solve.py` does command-injection and ret2win; `checker/checks.py`
drives Add→Show→List→Edit→Show→Echo→Secret(locked)→Delete legitimately.

## Challenge 3 — `koth-throne` (KotH, OWASP Top 10 — every vuln crowns you)

A Flask "hill". Crowning (writing `/koth/king`) is admin-only and players get
no admin account, so taking the hill means exploiting one of ten OWASP vulns —
each lands your **exact** round token in `/koth/king`.

| OWASP 2021 | Where | How it crowns |
|------------|-------|---------------|
| A01 Broken Access Control | `POST /throne` + `X-User-Role: admin` | trusts a client role header |
| A02 Cryptographic Failures | `session` cookie | forge `role=admin` (md5/secret=`"secret"`) → `/throne` |
| A03 Injection | `POST /login` | SQLi `admin'-- ` auth bypass → admin → `/throne` |
| A04 Insecure Design | `POST /reset` | leaked reset token → take admin → `/throne` |
| A05 Security Misconfiguration | `GET /debug/write?file=/koth/king&data=` | arbitrary file write |
| A06 Vulnerable Components | `POST /import/yaml` | PyYAML 3.13 RCE writes the marker |
| A07 Auth Failures | `POST /login` | default `admin:admin123` → `/throne` |
| A08 Integrity Failures | `POST /import/prefs` | pickle RCE writes the marker |
| A09 Logging Failures | `X-Forwarded-Log: /koth/king` + `User-Agent: <token>` | header-controlled raw log write |
| A10 SSRF | `GET /fetch?url=…/internal/crown?token=` | reach the localhost-only crown |

`solver/solve.py` implements all ten (`crown_via_AXX`); `checker/checks.py` is a
read-only health probe — never crowns — confirming `GET /` is up and the crown
is still guarded (non-admin `POST /throne` → 4xx, not 5xx, not 200).

## Challenge 4 — `koth-pwn` (KotH, PWN — every bug crowns you)

A C binary hill over TCP (no canary/PIE/RELRO/exec-stack). Only `do_crown()`
(`0x401226`) writes `/koth/king`, enthroning the global `banner`. Set `banner`
to your token, then flip `is_admin` (`0x4038c0`) or `ret2 do_crown()`.

| Bug | Menu | Notes |
|-----|------|-------|
| Stack buffer overflow | `3` Set nick | 64B buf, `read()` 512 → ret2 `do_crown` (offset 72) |
| Format string | `4` Echo | `printf(buf)` → `%n` write `is_admin` |
| OOB array write | `7/8` Notes | unchecked `idx` → write `is_admin` |
| UAF / double free / heap overflow | `7/8/9` Notes | slot never NULLed; unbounded edit len |
| Auth backdoor | `5` Login | password `letmein` → `is_admin` |

`solver/solve.py` crowns via the auth backdoor and ret2win; `checker/checks.py`
is read-only — confirms the menu is alive and an un-privileged crown is denied
(it never sets `banner` or flips `is_admin`, so it can't touch `/koth/king`).

---

## Deploy (admin → Repo Bindings)

Both the **service** (`src/Dockerfile`) and the **checker** (`checker/Dockerfile`)
are built automatically on import — you don't push images or set `containerImage`
/ `checkerImage`. To deploy:

1. In the GZCTF admin UI open **Repo Bindings** and add a binding — **Repo URL**
   `https://github.com/TCP1P/TCP1PADTesting`, **Ref** empty (default branch),
   **Interval** `60`, **no token** (this repo is public).
2. Hit **Scan now**. The poller finds `events/tcp1p-testing/.gzevent`, creates the
   Game *TCP1P A&D + KotH Testing*, and imports all four `challenge.yml`s (hidden).
   The four `src/` services and four `checker/` images build in the background —
   watch **admin → Builds**.
3. The game imports **hidden**: open **admin → game → Info**, set your own
   start/end time, and unhide it. Later syncs keep the challenges current but
   won't revert your Info-page edits.

Local smoke test (event tree paths):

```sh
EV=events/tcp1p-testing
docker build -t owasp-portal $EV/Web/owasp-portal/src
docker build -t owasp-portal-checker $EV/Web/owasp-portal/checker

echo 'flag{local_test}' > /tmp/flag
docker run -d --name svc -v /tmp/flag:/flag:ro owasp-portal
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' svc)
docker run --rm --network host \
  -e GZCTF_TARGET_IP=$IP -e GZCTF_TARGET_PORT=8080 -e GZCTF_ROUND=1 -e GZCTF_TEAM_ID=1 \
  owasp-portal-checker; echo "exit=$?"                       # 0 = Ok
python3 $EV/Web/owasp-portal/solver/solve.py $IP 8080        # prints captured flags
```

> These are intentionally vulnerable. Run them only inside the isolated A&D
> environment — never expose them on a trusted network.
