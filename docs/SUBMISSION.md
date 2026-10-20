# 提交清单（一页版）

按手册 *What Students Submit* 的五项逐条对照。所有路径相对于仓库根目录
`lab1-secure-api/`。

---

## 1. 公开 Git 仓库链接

```
https://github.com/RyzLLL/-Information-Security-Lab1
```

- [ ] 仓库是 **public**
- [ ] 已 push（本地 `git remote -v` 能看到 origin）
- [ ] 根目录有 `README.md`、`app/`、`tests/`、`cve/`、`docs/`、`.github/workflows/`

## 2. README.md 内容（手册要求的八个小节）

| 手册要求 | 位置 | 状态 |
|---|---|---|
| 项目与 API 说明（有哪些端点、怎么调） | `README.md` §1 | ✅ |
| 安全措施细节（SQLi / XSS / 认证如何实现） | `README.md` §2 | ✅ |
| SAST/SCA 报告截图 | `README.md` §3 + `docs/screenshots/` | ⬜ 待截图 |
| 选定的 CVE 名称与简介 | `README.md` §4 | ✅ |
| 复现步骤（含截图与命令） | `README.md` §4 + `cve/README.md` | ⬜ 待截图 |
| 根因分析（用自己的话） | `README.md` §4 + `cve/README.md` §5 | ✅ |
| 修复说明（改了什么、为什么有效） | `README.md` §4 + `cve/README.md` §6 | ✅ |
| 修复有效的证明 | `README.md` §4 | ⬜ 待截图 |

## 3. 最近一次成功流水线的链接

```
https://github.com/RyzLLL/-Information-Security-Lab1/actions
```

- [ ] `CI` 这次运行是绿的（4 个 job：test / lint / SAST - Bandit / SCA - pip-audit）
- [ ] `CVE reproduction (manual)` 这次运行是绿的（若用 CI 路线跑 CVE）
- [ ] 把链接填进 `docs/report_zh.md` / `docs/report_en.md` 首页的 *CI 流水线地址*

## 4. 修复文件目录

手册要求"如果改了配置文件或源码，这些文件必须附上"：

```
cve/Dockerfile                 # 漏洞版（Nacos 1.4.0，开启认证）
cve/Dockerfile.fixed           # 修复版（1.4.1 + 关白名单 + server identity）
cve/docker-compose.yml
cve/docker-compose.fixed.yml
```

打包提交也可以：`cve/` 整个目录（含 `exploit.ps1/.sh`、`verify-fix.ps1/.sh`、`run-all.ps1`、`README.md`）。

## 5. 实验报告

- [ ] `docs/report_zh.pdf`（中文）
- [ ] `docs/report_en.pdf`（英文）
- [x] 首页已填：**姓名**、**HDU 号**
- [ ] 已把 4.2 / 4.5 节的"预期结果"替换成你的**实际输出**
- [ ] 已把 `docs/screenshots/` 的 5 张图放好并重新生成 PDF

生成命令：

```powershell
python scripts\build_report.py --pdf
```

---

## 截图清单（5 张）

| 文件 | 内容 |
|---|---|
| `docs/screenshots/ci-green.png` | CI 四个 job 全绿 |
| `docs/screenshots/bandit.png` | *SAST - Bandit* 的 Job Summary（`No issues identified`） |
| `docs/screenshots/pip-audit.png` | *SCA - pip-audit* 的 Job Summary（`No known vulnerabilities found`） |
| `docs/screenshots/cve-exploit.png` | 漏洞版：`root:x:0:0` + `uid=` |
| `docs/screenshots/cve-fixed.png` | 修复版：全部 `404` + `It works!` |

详见 `docs/screenshots/README.md`。

---

## 提交前最后三分钟

```powershell
cd "C:\Users\ryz20\OneDrive\文档\deepseek-harness\default-workspace\lab1-secure-api"

python -m pytest -q                 # 应该 84 passed
python scripts\build_report.py --pdf
git status                          # 应该没有未提交改动（截图和 PDF 已被 gitignore）
```

- [ ] `git log --oneline` 有清晰的提交历史（不是一次巨型 commit）
- [ ] 仓库里**没有**密钥、token、`.env`、`instance/*.db`
- [ ] PDF 里的红色虚线框**全部消失**（说明 5 张图都补齐了）

---

## 常见扣分点自查

| 风险 | 本仓库的处理 |
|---|---|
| 口令明文存储 | bcrypt cost 12，`tests/test_auth.py` 断言 `$2b$` 前缀 |
| SQL 字符串拼接 | 全参数化，`tests/test_sqli_xss.py` 7 个 payload |
| XSS 未转义 | 输出统一 HTML 转义，5 个 payload 用例 |
| 令牌不校验/可伪造 | 固定算法白名单，`alg=none`、伪造签名、过期、删号四种用例 |
| CI 里没有真正的扫描器 | Bandit + pip-audit，且报告写进 Job Summary |
| 只改配置就叫"修复" | 修复只改 `FROM` 一行，配置完全相同 |
| 攻击失效但功能坏了 | `verify-fix.ps1` 里有回归检查（首页仍 200） |
| 依赖有已知漏洞 | pip-audit 初次报 23 个，升级后归零（报告 §3.5 有记录） |
