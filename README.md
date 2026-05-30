# TCP1P A&D Testing

Two **Attack & Defense** challenges for GZCTF, authored in the gzcli challenge
template format (matching `gzctf-platform-template/challenges/attack-defense`):
a `.gzevent` event manifest plus one directory per challenge, each with
`challenge.yml`, an auto-built `src/` service, a harness-based `checker/`, and a
reference `solver/`.

```
challenges/
  .gzevent                     # event manifest (repo-binding imports this)
  owasp-portal/                # OWASP Top 10 web target
    challenge.yml
    src/      Dockerfile app.py requirements.txt supervisord.conf
    checker/  Dockerfile checker.py checks.py run.py requirements.txt
    solver/   solve.py
  pwn-armory/                  # multi-bug PWN target
    challenge.yml
    src/      Dockerfile armory.c supervisord.conf
    checker/  Dockerfile checker.py checks.py run.py requirements.txt
    solver/   solve.py
```

Per the template contract: the **service** auto-builds from `./src/Dockerfile`
(supervisord PID 1 so a botched exploit doesn't drop the box; reads the live
flag fresh from `$GZCTF_FLAG_FILE`, never baked). The **checker** is the
enochecker3 harness — `checker.py`/`run.py` are copied verbatim and you only
edit `checks.py` (each `@check` function gets a `Target` with
`.url/.ip/.port/.flag`; return = Ok, `raise Mumble` = up-but-wrong, `t.get/post`
raise `Offline`). **Both checkers verify functionality only** (SLA); flag theft
is the attackers' `solver/` job.

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

---

## Build, test, deploy

```sh
# --- service images (what challenge.yml auto-builds) ---
docker build -t owasp-portal challenges/owasp-portal/src
docker build -t pwn-armory   challenges/pwn-armory/src

# --- checker images: build, then PUSH to the registry referenced in each
#     challenge.yml `ad.checkerImage` so the cluster/daemon can pull them ---
docker build -t ghcr.io/tcp1p/owasp-portal-checker:latest challenges/owasp-portal/checker
docker build -t ghcr.io/tcp1p/pwn-armory-checker:latest   challenges/pwn-armory/checker
docker push  ghcr.io/tcp1p/owasp-portal-checker:latest
docker push  ghcr.io/tcp1p/pwn-armory-checker:latest

# --- local smoke test: run a service with a fake flag, point the checker at it ---
echo 'flag{local_test}' > /tmp/flag
docker run -d --name svc -v /tmp/flag:/flag:ro owasp-portal
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' svc)
docker run --rm --network host \
  -e GZCTF_TARGET_IP=$IP -e GZCTF_TARGET_PORT=8080 -e GZCTF_ROUND=1 -e GZCTF_TEAM_ID=1 \
  ghcr.io/tcp1p/owasp-portal-checker:latest; echo "exit=$?"   # 0 = Ok
python3 challenges/owasp-portal/solver/solve.py $IP 8080      # prints captured flags
```

Deploy via **admin → Repo Bindings**: point it at this repo; the `.gzevent`
becomes a Game and both `challenge.yml`s are imported (hidden until enabled).

> These are intentionally vulnerable. Run them only inside the isolated A&D
> environment — never expose them on a trusted network.
