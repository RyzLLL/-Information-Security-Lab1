# Lab 1 — Secure REST API with CI/CD and a real CVE

[![CI](https://github.com/RyzLLL/-Information-Security-Lab1/actions/workflows/ci.yml/badge.svg)](https://github.com/RyzLLL/-Information-Security-Lab1/actions/workflows/ci.yml)

A small but deliberately complete Flask API that is built the way a security
reviewer would ask you to build it, wired to a CI pipeline that runs SAST and
SCA on every push, and paired with a reproducible real-world CVE
(**CVE-2021-29441**) that is exploited, analysed and then fixed.

| | |
|---|---|
| Language / stack | Python 3.11+ / Flask 3.1 / SQLite |
| Auth | bcrypt password hashes + short-lived HS256 JWT |
| SAST | Bandit (plus SARIF upload to GitHub code scanning) |
| SCA | pip-audit |
| Tests | 84 pytest tests, incl. dedicated SQLi/XSS regression tests |
| CVE target | CVE-2021-29441 — Nacos < 1.4.1 authentication bypass (spoofed User-Agent) |
| Report | [`docs/report_en.md`](docs/report_en.md) · [`docs/report_zh.md`](docs/report_zh.md) |
| Step-by-step guide | [`docs/GUIDE.md`](docs/GUIDE.md) (中文) |
| Submission checklist | [`docs/SUBMISSION.md`](docs/SUBMISSION.md) |
| Postman | [`docs/postman_collection.json`](docs/postman_collection.json) |

---

## 1. The API

Base URL in development: `http://127.0.0.1:5000`.

| # | Method | Path | Auth | Purpose |
|---|---|---|---|---|
| 1 | `POST` | `/auth/login` | — | Authenticate, return a JWT |
| 2 | `GET` | `/api/data` | Bearer | Read the post feed (paginated, searchable) |
| 3 | `POST` | `/api/posts` | Bearer | Create a post (the "own method" required by the lab) |
| + | `GET` | `/api/me` | Bearer | Return the identity encoded in the token |
| + | `GET` | `/health` | — | Liveness probe |

Demo accounts (seeded on first start, **for the lab only**):

| user | password | role |
|---|---|---|
| `alice` | `Passw0rd!Alice` | admin |
| `bob` | `Passw0rd!Bob` | user |

### 1.1 Run it

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python run.py                                        # http://127.0.0.1:5000
```

Environment variables (all optional in development):

| Variable | Default | Meaning |
|---|---|---|
| `APP_ENV` | `development` | `development` / `production` / `testing` |
| `SECRET_KEY` | random per boot | JWT signing key — **required** in production |
| `DATABASE_PATH` | `instance/app.db` | SQLite file |
| `JWT_TTL_MINUTES` | `15` | Token lifetime |
| `BCRYPT_ROUNDS` | `12` | Password hashing cost |
| `LOGIN_MAX_ATTEMPTS` | `5` | Failed logins per window per (IP, user) |
| `LOGIN_WINDOW_SECONDS` | `300` | Rate-limit window |

### 1.2 Call it

```bash
# login -> token
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Passw0rd!Alice"}' | jq -r .access_token)

# 2. protected read (401 without the header)
curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:5000/api/data?limit=2'

# 3. create
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Hello","body":"first post"}' http://127.0.0.1:5000/api/posts

# who am I
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/api/me
```

Windows users: `scripts/demo.ps1` runs the whole walkthrough (login, 401
without token, 401 with a forged token, 200 with a real one, create, SQLi
attempt, XSS attempt) and prints a transcript that can be screenshotted
directly. Postman users can import `docs/postman_collection.json`: the *Login*
request stores the JWT in the `{{token}}` collection variable and every request
carries assertions for the Collection Runner.

```powershell
python run.py            # terminal 1
powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1   # terminal 2
```

Responses follow one error shape:

```json
{"error": {"code": "unauthorized", "message": "Invalid token."}}
```

---

## 2. Security measures

### 2.1 SQL injection — parameterised statements everywhere

Every statement uses bound parameters; no SQL string is ever concatenated.
`app/db.py` is the only place that talks to SQLite.

```python
# app/db.py — the username is data, never SQL
conn.execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,),
)
```

The search filter is bound too, so `' OR 1=1 --` is a *literal substring* and
returns zero rows instead of every row:

```python
"WHERE p.title LIKE ? OR p.body LIKE ?", (f"%{search}%", f"%{search}%")
```

Evidence: `python -m pytest tests/test_sqli_xss.py -k sqli` — seven payloads
(tautologies, `UNION SELECT`, `DROP TABLE`, comment truncation) all fail to
authenticate and leave the schema intact. A test additionally asserts that no
SQLite error text ever reaches the client.

### 2.2 XSS — encode on output

Stored data stays raw; every string leaving the API is HTML-escaped
(`app/security.py::escape_value`, applied recursively to list/dict payloads):

```python
"<script>alert('XSS')</script>"  ->  "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"
```

Responses are `application/json` with `X-Content-Type-Options: nosniff`, a
`Content-Security-Policy: default-src 'none'` and `Cache-Control: no-store`.
Input validation rejects control characters (`\x00`, `\x1b`, …) and enforces
length limits, which also blocks log/header injection.

Evidence: `pytest tests/test_sqli_xss.py -k xss` stores five payloads
(`<script>`, `<img onerror>`, `<svg onload>`, `javascript:`, `<iframe>`) and
asserts the raw forms never appear in a response.

### 2.3 Authentication and session handling

| Requirement | Implementation |
|---|---|
| Never store plaintext | bcrypt, cost 12, per-password salt (`app/security.py::hash_password`) |
| bcrypt's 72-byte limit | rejected up-front instead of silently truncating |
| Issue a token | HS256 JWT with `sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti` — 15 min TTL |
| Verify on every protected endpoint | `@jwt_required` decorator (`app/security.py`) |
| Algorithm pinning | `algorithms=["HS256"]` — blocks `alg: none` and RS→HS confusion |
| Claim validation | issuer, audience and required claims checked; expiry with 5 s leeway |
| Revocation | the subject is re-read from the DB on every request; a deleted user's token stops working |
| No user enumeration | identical status and body for "unknown user" and "wrong password"; a dummy bcrypt check keeps the timing flat |
| Brute force | 5 failed logins per (IP, username) per 5 min → `429` + `Retry-After` |

Evidence: `tests/test_auth.py` covers expired tokens, tokens signed with an
attacker key, `alg=none`, wrong scheme, deleted users and the rate limiter.

### 2.4 Everything else

* Security headers on every response (`nosniff`, `DENY`, `no-referrer`, CSP, `no-store`).
* JSON error handler that never leaks stack traces, SQL or paths.
* `MAX_CONTENT_LENGTH` 64 KiB → `413` instead of an unbounded body.
* Production refuses to boot without `SECRET_KEY`.
* The dev server binds `127.0.0.1`, never `0.0.0.0`.

---

## 3. CI/CD pipeline

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Tool | What it proves |
|---|---|---|
| `test` | pytest (3.11 + 3.12 matrix, coverage) | functional + security regression tests pass |
| `lint` | ruff (pinned) | imports, unused names, obvious bugs |
| `sast-bandit` | Bandit (`-ll -ii`) + SARIF upload | no medium/high static findings; results appear in *Security → Code scanning* |
| `sca-pip-audit` | pip-audit (`--strict`) | no known vulnerabilities in the pinned dependencies |

Both scanners also write their raw report into the GitHub **job summary**, so a
screenshot of the run shows the tool output itself, not just a green check.

### What they found, and what was fixed

`bandit -r app -ll -ii` → `No issues identified` (636 LOC; three low-severity
B105/B106 false positives on config keys such as `PASSWORD_MIN_LENGTH`).

`pip-audit -r requirements.txt --strict` initially reported **23 known
vulnerabilities in 2 packages** — `flask 3.1.2` (PYSEC-2026-2151, missing
`Vary: Cookie`) and `pyjwt 2.10.1` (20 advisories: unvalidated `crit` header,
algorithm-policy issues, …). Both pins were raised and the audit is now clean:

```diff
- flask==3.1.2
- PyJWT==2.10.1
+ flask==3.1.3
+ PyJWT==2.15.0
```

```
$ pip-audit -r requirements.txt --strict
No known vulnerabilities found
```

All 84 tests pass on both the old and the new versions, so the upgrade did not
merely hide a breakage.

### Screenshots

> Replace these placeholders with your own runs after pushing.

| What | Where to click |
|---|---|
| Green pipeline | *Actions* → *CI* → latest run |
| Lint | *Actions* → *CI* → *Lint - ruff* |
| Bandit report | *Actions* → *CI* → *SAST - Bandit* → *Summary* |
| pip-audit report | *Actions* → *CI* → *SCA - pip-audit* → *Summary* |
| Code scanning findings | *Security* → *Code scanning* |

![CI run](docs/screenshots/ci-green.png)
![Bandit](docs/screenshots/bandit.png)
![pip-audit](docs/screenshots/pip-audit.png)

Run the same tools locally:

```bash
bandit -r app -ll -ii
pip-audit -r requirements.txt --strict --desc
```

---

## 4. The CVE: CVE-2021-29441

Full analysis, commands and defence-in-depth notes: **[`cve/README.md`](cve/README.md)**.

**What it is.** Nacos < 1.4.1, with authentication enabled, runs every request
through `AuthFilter`. That filter short-circuits any request whose
`User-Agent` is `Nacos-Server`, on the assumption that only another Nacos server
would send it. A header is attacker-controlled data, so the assumption is the
bug: CWE-290, authentication bypass by spoofing, CVSS 3.1 **8.6**. The bypass
skips *all* authorisation, so `/nacos/v1/auth/users` becomes reachable — the user
table (with bcrypt hashes) can be read and a new administrator can be created,
which yields the full console.

> The stock Vulhub image runs with `nacos.core.auth.enabled=false`; with auth
> off the header is irrelevant, so our images enable authentication — the exact
> precondition the advisory names.

**Reproduce** (vulnerable image, port 8848):

```bash
cd cve && docker compose up -d --build
powershell -ExecutionPolicy Bypass -File .\exploit.ps1     # or ./exploit.sh
```

```
baseline  (no header)            -> 403  "unknown user!"
bypass    (User-Agent: Nacos-Server) -> 200  user table + hashes
impact    (POST create user)     -> 200  {"message":"create user ok!"}
```

**Fix** — two settings, and the version bump alone is *not* enough:

```diff
-  NACOS_VERSION=1.4.0
+  NACOS_VERSION=1.4.1
+  nacos.core.auth.enable.userAgentAuthWhite=false
+  nacos.core.auth.server.identity.key=lab1server
+  nacos.core.auth.server.identity.value=lab1secret
```

1.4.1 only *introduces* `userAgentAuthWhite` and ships it **true**, so a stock
1.4.1 is still bypassable (verified); the last two lines are what make a
whitelist-free cluster work at all.

```bash
docker compose down
docker compose -f docker-compose.fixed.yml up -d --build
powershell -ExecutionPolicy Bypass -File .\verify-fix.ps1   # or ./verify-fix.sh
```

`verify-fix` replays both requests, asserts 403 instead of the user table, and
adds two checks a naive test would miss: no account can be created, and
**authentication is still enabled** (a "fix" that turns auth off is a
regression, not a fix).

Screenshots to take: the leak/create output on the vulnerable build and the
`RESULT: fix verified` summary on the patched one.

---

## 5. Tests

```bash
pytest                                   # 84 tests
pytest tests/test_sqli_xss.py -v         # only the attack regressions
pytest --cov=app --cov-report=term-missing
python scripts/validate_manifests.py     # ci.yml + compose files vs their schemas
```

```
tests/test_auth.py        22 passed
tests/test_api.py         30 passed
tests/test_config.py       8 passed
tests/test_sqli_xss.py    24 passed
======================== 84 passed ========================
```

Coverage is **94%** (`pytest --cov=app`: 24 of 394 statements uncovered, mostly defensive branches such as over-long passwords, failed claim validation and rate-limit retries), and `ruff check` is clean.

---

## 6. Layout

```
lab1-secure-api/
├── app/
│   ├── __init__.py        # application factory, security headers
│   ├── config.py          # env-driven config, prod refuses to boot without SECRET_KEY
│   ├── db.py              # schema + every parameterised query
│   ├── security.py        # bcrypt, JWT, validation, output escaping, rate limiter
│   ├── errors.py          # typed JSON errors, no stack-trace leakage
│   ├── auth.py            # POST /auth/login
│   └── api.py             # GET /api/data, POST /api/posts, GET /api/me
├── tests/                 # 84 tests, incl. SQLi/XSS regressions
├── scripts/demo.ps1       # end-to-end walkthrough for screenshots
├── cve/                   # vulnerable env, exploit, patch, verification
├── .github/workflows/ci.yml
└── docs/                  # report (EN + ZH), screenshots
```

---

## 7. References

* OWASP Top 10 2021 — <https://owasp.org/www-project-top-ten/>
* OWASP Cheat Sheets: Authentication, SQL Injection Prevention, XSS Prevention — <https://cheatsheetseries.owasp.org/>
* JWT introduction — <https://jwt.io/introduction>
* GitHub Actions — <https://docs.github.com/en/actions>
* Vulhub — <https://github.com/vulhub/vulhub>
* NVD — <https://nvd.nist.gov/>

> The credentials in `app/db.py` are seeded demo data for a disposable lab
> database. They are not secrets and must never be reused outside this project.
