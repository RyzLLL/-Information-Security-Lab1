# 实验 1 — 安全 REST API + CI/CD + 真实 CVE 复现

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)

一个刻意做完整的小型 Flask API：按安全评审的标准实现，接上每次 push 自动跑 SAST/SCA
的 CI，并配一个可复现的真实漏洞（**CVE-2021-41773**）——复现、分析根因、修复、验证。

> 仓库地址 `OWNER/REPO` 请替换成你自己的。

| | |
|---|---|
| 技术栈 | Python 3.11+ / Flask 3.1 / SQLite |
| 认证 | bcrypt 口令哈希 + 短时效 HS256 JWT |
| SAST | Bandit（并上传 SARIF 到代码扫描） |
| SCA | pip-audit |
| 测试 | 84 个 pytest 用例，含 SQLi / XSS 专项回归 |
| CVE | CVE-2021-41773 — Apache HTTP Server 2.4.49 路径穿越 → RCE |
| 报告 | [`docs/report_zh.md`](docs/report_zh.md) · [`docs/report_en.md`](docs/report_en.md) |
| 分步指南 | [`docs/GUIDE.md`](docs/GUIDE.md) |
| 无 Docker 方案 | [`docs/PWD.md`](docs/PWD.md) — 在 Play with Docker 上跑 CVE |
| 提交清单 | [`docs/SUBMISSION.md`](docs/SUBMISSION.md) |
| Postman | [`docs/postman_collection.json`](docs/postman_collection.json) |

---

## 1. API

开发环境地址：`http://127.0.0.1:5000`

| # | 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|---|
| 1 | POST | `/auth/login` | — | 登录，返回 JWT |
| 2 | GET | `/api/data` | Bearer | 读取帖子列表（分页、搜索） |
| 3 | POST | `/api/posts` | Bearer | **自选接口**：创建帖子 |
| + | GET | `/api/me` | Bearer | 返回令牌中的身份 |
| + | GET | `/health` | — | 存活探针 |

演示账号（首次启动写入，**仅用于实验**）：`alice / Passw0rd!Alice`、`bob / Passw0rd!Bob`。

### 1.1 运行

```bash
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements-dev.txt
python run.py                 # http://127.0.0.1:5000
```

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `APP_ENV` | `development` | `development` / `production` / `testing` |
| `SECRET_KEY` | 每次启动随机 | JWT 签名密钥，**production 必填** |
| `DATABASE_PATH` | `instance/app.db` | SQLite 文件 |
| `JWT_TTL_MINUTES` | `15` | 令牌有效期 |
| `BCRYPT_ROUNDS` | `12` | 口令哈希代价 |
| `LOGIN_MAX_ATTEMPTS` | `5` | 每窗口每 (IP, 用户) 允许的失败次数 |
| `LOGIN_WINDOW_SECONDS` | `300` | 限速窗口 |

### 1.2 调用

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Passw0rd!Alice"}' | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:5000/api/data?limit=2'
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"title":"Hello","body":"first post"}' http://127.0.0.1:5000/api/posts
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/api/me
```

Windows 用户可直接跑完整演示（登录、无令牌 401、伪造令牌 401、正常 200、创建、
SQLi 尝试、XSS 尝试），输出可直接截图：

```powershell
python run.py            # 终端 1
powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1   # 终端 2
```

用 Postman 的话，导入 [`docs/postman_collection.json`](docs/postman_collection.json)：
先跑 *Login*（会把 JWT 存进集合变量 `{{token}}`），其余请求已带断言，
可直接用 Collection Runner 跑一遍并截图。

统一错误格式：

```json
{"error": {"code": "unauthorized", "message": "Invalid token."}}
```

---

## 2. 安全措施

### 2.1 防 SQL 注入：全参数化

`app/db.py` 是唯一访问 SQLite 的模块，所有语句都用 `?` 绑定：

```python
conn.execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,),          # 用户名是数据，不是 SQL
)
```

搜索条件同样绑定，`' OR 1=1 --` 只会被当作普通子串：

```python
"WHERE p.title LIKE ? OR p.body LIKE ?", (f"%{search}%", f"%{search}%")
```

证据：`pytest tests/test_sqli_xss.py -k sqli` —— 7 种 payload（恒真式、`UNION SELECT`、
`DROP TABLE`、注释截断）全部无法登录，且表结构完好；另有用例断言响应里不出现任何
SQLite 报错文本。

### 2.2 防 XSS：输出编码

存储保留原文，**离开 API 时**递归 HTML 转义（`app/security.py::escape_value`）：

```python
"<script>alert('XSS')</script>"  ->  "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"
```

配套：`application/json` + `X-Content-Type-Options: nosniff`、
`Content-Security-Policy: default-src 'none'`、`Cache-Control: no-store`；
输入侧拒绝控制字符并限制长度（顺带挡住日志/响应头注入）。

证据：`pytest tests/test_sqli_xss.py -k xss` —— 5 种 payload（`<script>`、`<img onerror>`、
`<svg onload>`、`javascript:`、`<iframe>`）的原文均不出现在响应中。

### 2.3 认证与会话

| 要求 | 实现 |
|---|---|
| 口令绝不明文 | bcrypt cost 12，独立随机盐 |
| bcrypt 72 字节上限 | 超长口令在建哈希前直接拒绝，不做静默截断 |
| 登录签发令牌 | HS256 JWT：`sub/iss/aud/iat/nbf/exp/jti`，15 分钟 |
| 受保护端点校验 | `@jwt_required` 装饰器 |
| 固定算法 | `algorithms=["HS256"]`，挡住 `alg:none` 与 RS→HS 混淆 |
| 声明校验 | `iss`、`aud`、必需声明、过期（5 秒容差） |
| 吊销 | 每次请求回表，账号删除后令牌立即失效 |
| 防用户枚举 | “用户不存在”与“口令错误”状态码与正文完全一致，并做一次假 bcrypt 拉平耗时 |
| 防暴力破解 | 同 (IP, 用户名) 5 分钟内 5 次失败 → `429` + `Retry-After` |

### 2.4 其他

统一 JSON 错误（不泄露堆栈/SQL/路径）、`MAX_CONTENT_LENGTH` 64 KiB、
`X-Frame-Options: DENY`、开发服务器只监听 `127.0.0.1`、production 缺 `SECRET_KEY`
直接拒绝启动。

---

## 3. CI/CD

`.github/workflows/ci.yml`，push 与 PR 自动触发：

| Job | 工具 | 作用 |
|---|---|---|
| `test` | pytest（3.11 / 3.12 矩阵 + 覆盖率） | 功能与安全回归 |
| `lint` | `ruff check`（版本锁定） | 导入顺序、未使用名称、明显 bug |
| `sast-bandit` | `bandit -r app -ll -ii` + SARIF 上传 | 静态发现中高危问题 |
| `sca-pip-audit` | `pip-audit -r requirements.txt --strict` | 依赖已知漏洞 |

两个扫描器都会把原始报告写进 **Job Summary**，截图里能直接看到工具输出。

### 扫到了什么、修了什么

`bandit -r app -ll -ii` → `No issues identified`（636 行；另有 3 条 Low 误报，
都是配置常量名里带 `PASSWORD` 触发的 B105/B106）。

`pip-audit -r requirements.txt --strict` 初次运行报了 **2 个包共 23 个已知漏洞**：
`flask 3.1.2`（PYSEC-2026-2151，缺少 `Vary: Cookie`）与 `pyjwt 2.10.1`
（20 条公告：`crit` 头未校验、算法策略相关缺陷等）。升级版本后审计归零：

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

84 个测试在升级前后都全绿，说明不是"升级把测试改绿了"。

### 截图

> push 之后按上表位置截图，替换以下占位。

| 内容 | 位置 |
|---|---|
| 绿色流水线 | Actions → CI → 最近一次运行 |
| Lint | Actions → CI → *Lint - ruff* |
| Bandit 报告 | Actions → CI → *SAST - Bandit* → Summary |
| pip-audit 报告 | Actions → CI → *SCA - pip-audit* → Summary |
| 代码扫描 | Security → Code scanning |

![CI](docs/screenshots/ci-green.png)
![Bandit](docs/screenshots/bandit.png)
![pip-audit](docs/screenshots/pip-audit.png)

本地同样可跑：

```bash
bandit -r app -ll -ii
pip-audit -r requirements.txt --strict --desc
```

---

## 4. CVE-2021-41773

完整分析、命令与纵深防御建议见 **[`cve/README.md`](cve/README.md)**。

**是什么**：Apache HTTP Server 2.4.49 重写了 URI 规范化（`server/request.c` 的
`ap_normalize_path()`）。它判断某段是否 `.`/`..` 时，字符**还是百分号编码态**，
之后才把 `%2e` 解码成 `.`。于是 `.%2e` 不被当作穿越段，解码后却变成真正的 `..`；
`ap_core_translate()` 又未校验映射结果是否仍在 `Alias` 目录内。结果：
`GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd` 直接读走口令文件；
开启 `mod_cgi` 时同一手法可落到 `/bin/sh` 执行命令。CWE-22，CVSS 3.1 **7.5**
（RCE 变体 CVE-2021-42013 为 9.8），2021-11-03 进入 CISA KEV。

**复现**（漏洞镜像，8080 端口）：

```bash
cd cve && docker compose up -d --build
powershell -ExecutionPolicy Bypass -File .\exploit.ps1     # 或 ./exploit.sh
```

**修复**——只改一行版本，配置完全不动，从而只隔离一个变量：

```diff
-FROM vulhub/httpd:2.4.49
+FROM httpd:2.4.51
```

```bash
docker compose down
docker compose -f docker-compose.fixed.yml up -d --build
powershell -ExecutionPolicy Bypass -File .\verify-fix.ps1   # 或 ./verify-fix.sh
```

`verify-fix` 会重放**整个绕过家族**（双重编码、`%2f`、`/.%2e/`），断言返回 400/403/404
而不是文件内容，并检查首页仍正常返回（回归）。只修公告里那一个字符串等于做黑名单，
2.4.50 的教训就在眼前。

待补截图：漏洞环境 `/etc/passwd` + `id` 输出、修复后 400、`verify-fix` PASS 汇总。

> **本机装不上 Docker？** `.github/workflows/cve-repro.yml` 可以在 GitHub runner 上跑同一套流程（手动触发，约 4 分钟），两段转录会出现在该次运行的 Summary 里 —— 见 [`docs/GUIDE.md`](docs/GUIDE.md) 的“方案 D”。

![Exploit](docs/screenshots/cve-exploit.png)
![Fix](docs/screenshots/cve-fixed.png)

---

## 5. 测试

```bash
pytest                                   # 84 个用例
pytest tests/test_sqli_xss.py -v         # 只跑攻击回归
pytest --cov=app --cov-report=term-missing
```

```
tests/test_auth.py        22 passed
tests/test_api.py         30 passed
tests/test_config.py       8 passed
tests/test_sqli_xss.py    24 passed
======================== 84 passed ========================
```

覆盖率 **94%**（`pytest --cov=app`：394 行中 24 行未覆盖，基本都是防御性分支，如密码超长、声明校验失败、限速重试等）；`ruff check` 无告警。

---

## 6. 目录结构

```
lab1-secure-api/
├── app/                      应用代码（工厂 / 配置 / DB / 安全原语 / 路由）
├── tests/                    84 个用例，含 SQLi、XSS 专项回归
├── scripts/demo.ps1          端到端演示，输出可截图
├── cve/                      漏洞环境、利用脚本、补丁、验证脚本、CVE 分析
├── .github/workflows/ci.yml  CI：测试 + Bandit + pip-audit
└── docs/                     中英文报告与截图
```

---

## 7. 参考

* OWASP Top 10 — <https://owasp.org/www-project-top-ten/>
* OWASP Cheat Sheet Series — <https://cheatsheetseries.owasp.org/>
* JWT — <https://jwt.io/introduction>
* GitHub Actions — <https://docs.github.com/en/actions>
* Vulhub — <https://github.com/vulhub/vulhub>
* NVD — <https://nvd.nist.gov/>

> `app/db.py` 里的口令是一次性实验库的演示数据，不是秘密，也不能在项目之外复用。
