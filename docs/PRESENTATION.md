# 实验一 · 讲解稿与八个问题 / Walkthrough & eight questions

> 一页纸，照着念即可。Everything below is written to be read aloud.

---

## 一、3 分钟讲解 / A three-minute walkthrough

### 1. 一句话概括 / One sentence

**中文：** 我搭了一个 Flask API，按 OWASP 做了三项防护，用 GitHub Actions 自动跑 SAST 和 SCA，
然后复现并修复了一个真实 CVE（Nacos 认证绕过）。

**English:** I built a Flask API with the three required defences, wired SAST and SCA into
GitHub Actions, then reproduced and fixed a real CVE (Nacos authentication bypass).

---

### 2. 做了什么 / What was built

| 部分 | 内容 | 在哪 |
|---|---|---|
| API | `POST /auth/login`、`GET /api/data`、`POST /api/posts`（自选），另加 `/api/me`、`/health` | `app/api.py`, `app/auth.py` |
| SQLi 防护 | 所有 SQL 用 `?` 占位符 + 参数元组，不拼字符串 | `app/db.py` |
| XSS 防护 | 所有出站字符串递归 HTML 转义，另加 CSP / nosniff | `app/security.py::escape_value` |
| 认证 | bcrypt cost 12 + HS256 JWT（15 分钟）+ 每个受保护端点校验 + 算法白名单 | `app/security.py`, `app/auth.py` |
| 测试 | 84 个，其中 **24 个是攻击用例**（7 种 SQLi、5 种 XSS、过期/伪造/alg=none 令牌、限速） | `tests/` |
| CI | 4 个 job：测试（3.11/3.12）、ruff、Bandit、pip-audit | `.github/workflows/ci.yml` |
| CVE | CVE-2021-29441：Nacos 1.4.0 被绕过，1.4.1 + 关开关修复 | `cve/` |

**English:** three required endpoints plus two helpers; parameterised queries, output
escaping and bcrypt+JWT; 84 tests of which 24 are attack regressions; four CI jobs;
and the CVE lab under `cve/`.

---

### 3. 怎么完成的 / How it was done

1. **先写攻击用例，再写实现** —— 测试里直接放 `' OR 1=1 --`、`<script>alert(1)</script>`，
   实现必须让它们失效。这样"防护有效"是可回归的，不靠嘴说。
   *Attack tests first, implementation second — the defences are regressions, not claims.*

2. **CI 每次 push 跑四件事**，并把扫描器输出写进 Job Summary，方便截图留证。
   *Four jobs on every push; the scanner output goes into the job summary so it can be shown.*

3. **CVE 选"一条命令能复现、修复能验证"的**：起容器 → 复现 → 读 `AuthFilter` 源码 →
   打补丁 → 回归验证。*Pick a CVE that reproduces with one command and whose fix is verifiable.*

4. **三个关键判断**（老师最可能追问的地方）：
   *Three decisions worth explaining:*
   - Vulhub 的 `nacos:1.4.0` 默认 `auth.enabled=false`，那样"谁都能进"跟 CVE 无关 ——
     所以镜像里**把认证打开**，这才符合 advisory 写的"when configured to use authentication"。
   - 1.4.1 只是**引入**了开关且默认开着，光升级**修不好**（我实测过）。
   - 关掉开关后还必须配 `server.identity`，否则连控制台都会被 403 —— 那是"修好了也用不了"。

---

### 4. 现场演示（2 分钟）/ Live demo

```powershell
cd lab1-secure-api
python run.py                     # 或 PyCharm 里点 "1. API server (Flask)"
python -m pytest -q               # 84 passed

cd cve
powershell -ExecutionPolicy Bypass -File .\run-all.ps1   # 约 30 秒：复现 + 修复 + 验证
```

**English:** start the API (or the PyCharm run configuration), run the suite, then one
script that reproduces the CVE, applies the patch and verifies it.

---

## 二、八个问题 / The eight questions

### 1. 为什么用 bcrypt 而不是 SHA-256？/ Why bcrypt and not SHA-256?

**中：** SHA-256 的设计目标是快，GPU 每秒能算几十亿次，泄露的哈希很快被爆破；
bcrypt 故意慢（cost 12 ≈ 0.25 秒一次）、每用户独立盐、并且 cost 可随硬件提升而上调。
*代码：* `app/security.py::hash_password`。

**En:** SHA-256 is built to be fast, which is exactly wrong for passwords; bcrypt is
deliberately slow, salts every hash, and its cost can be raised as hardware improves.
See `app/security.py::hash_password`.

### 2. SAST 和 DAST 有什么区别？/ SAST vs DAST?

**中：** SAST 是白盒，不运行程序，直接分析源码，能在提交阶段发现问题并定位到行，
但误报多、看不到运行时配置。DAST 是黑盒，对运行中的系统发请求，能找到真实可利用的问题，
但指不出代码位置。本实验用 SAST（Bandit + pip-audit）。

**En:** SAST is white-box and points at a line but produces false positives; DAST is
black-box and proves exploitability but cannot name the code. This lab uses SAST
(Bandit + pip-audit); DAST is the tool of the next lab (ZAP).

### 3. JWT 是什么，服务端怎么验证？/ What is a JWT and how is it verified?

**中：** 三段 base64url：header.payload.signature。payload 只编码不加密，谁拿到都能读，
所以不放敏感数据。服务端用密钥重算 `header.payload` 的签名并比对，同时校验 `iss`、`aud`、
`exp` 和必需声明；算法固定为 HS256，挡住 `alg:none` 和 RS→HS 混淆。

**En:** Three base64url parts; the payload is readable by anyone, so it holds no secrets.
The server recomputes the signature and checks `iss`/`aud`/`exp` plus the required
claims, with the algorithm pinned to HS256.

### 4. 不审计第三方依赖会怎样？/ Why audit dependencies?

**中：** 现代应用大部分代码来自依赖，攻击者不用碰你的代码，只要一个传递依赖有洞就能进来。
本实验里 pip-audit 一开始报了 **23 个已知漏洞**（flask 2 个、PyJWT 21 个），升级到
`flask 3.1.3` / `PyJWT 2.15.0` 后归零 —— 这就是 SCA 的价值。

**En:** Most of a modern app is third-party code. pip-audit found 23 advisories here
(2 in Flask, 21 in PyJWT); raising the pins cleared them to zero.

### 5. 用 Docker + Vulhub 学安全，比本机装有漏洞的软件好在哪？/ Why Docker + Vulhub?

**中：** 隔离、可丢弃、版本可复现、能用不同 tag 把"漏洞版/修复版"并排对比，
配置固化成代码可复核；打坏了 `down -v` 重建即可。

**En:** Isolation and disposability, reproducible versions, vulnerable and fixed builds
side by side differing only by a tag, and configuration as code.

### 6. 漏洞和 exploit 的区别？你复现的是哪个？/ Vulnerability vs exploit?

**中：** 漏洞是缺陷本身（`AuthFilter` 用请求头判断"是否内部服务器"）；exploit 是利用它的
具体手段（加一行 `User-Agent: Nacos-Server`）。我是在人为搭的漏洞环境里**用公开利用复现漏洞**，
然后分析根因、打补丁、再证明利用失效。

**En:** The vulnerability is the flaw; the exploit is the technique that weaponises it.
I reproduced the vulnerability by running the exploit against a deliberately vulnerable
build, then fixed it and proved the exploit no longer works.

### 7. 打了补丁为什么还要回归测试？/ Why regression-test a patch?

**中：** 修复往往改公共路径，容易顺带弄坏正常功能。1.4.1 就是现成例子：它加了开关却默认开着，
升级后依然能绕过；而关掉开关不配 identity 又会把控制台锁死。所以验证脚本第 1 项查"控制台仍 200"，
第 4 项查"匿名访问仍被拒" —— 防止"把功能关掉"冒充修复。

**En:** 1.4.1 added the switch but left it on, so the upgrade alone did not help; switching
it off without a server identity locks out the console. Hence the regression checks:
console still 200, anonymous access still refused.

### 8. 掌握 CVE 复现对渗透测试 / SOC 有什么用？/ Why does CVE work matter?

**中：** 对渗透测试：复现是"证明影响"的标准动作，也是按 KEV 清单快速排查资产的手段。
对 SOC：知道请求长什么样（`User-Agent: Nacos-Server` 来自非集群地址）才写得出检测规则。
更根本的是它教会你**模式**：认证绕过、路径穿越、反序列化，会在不同框架里反复出现。

**En:** For a pentester, reproduction proves impact and triages assets against KEV. For a
SOC analyst, knowing the request shape is what makes a detection rule possible. Above all
it teaches patterns that recur across frameworks.

---

## 三、老师可能追问的两处，提前准备 / Two likely follow-ups

**Q: 为什么不用 Vulhub 那个镜像，自己 build？**
A: `vulhub/nacos:1.4.0` 默认 `nacos.core.auth.enabled=false`，认证关着的时候这个头毫无作用，
演示不出 CVE。所以镜像里把认证打开 —— 版本、攻击路径都与 Vulhub 一致，只是补上了 advisory 的前提。

**Q: 你的"修复"到底改了什么？**
A: 三处，都在 `cve/Dockerfile.fixed`：版本 1.4.0 → 1.4.1；`userAgentAuthWhite=false`；
配一对 `server.identity`。只改版本不够（实测），第三项是让服务在关掉白名单后还能正常工作。

---

## 四、文件在哪 / Where to look

| 想看什么 | 打开 |
|---|---|
| API 与端点 | `app/api.py`、`app/auth.py` |
| 三项防护的实现 | `app/db.py`（SQLi）、`app/security.py`（XSS + JWT + bcrypt） |
| 攻击用例 | `tests/test_sqli_xss.py`、`tests/test_auth.py` |
| CI 配置 | `.github/workflows/ci.yml` |
| CVE 复现 / 修复 / 验证 | `cve/exploit.ps1`、`cve/Dockerfile.fixed`、`cve/verify-fix.ps1` |
| CVE 根因分析 | `cve/README.md` 第 5 节 |
| 报告 | `docs/report_zh.md` / `report_en.md`（PDF 同名） |
| 截图 | `docs/screenshots/` |
