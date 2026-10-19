# Work 1 中文逐步操作指南

这份指南对应手册第 1 页到第 5 页的 Work 1。目标不是“把代码跑起来”就结束，
而是形成可提交的完整证据链：代码、测试、CI 报告、CVE 复现、根因、修复、
回归验证。

## 第 0 步：先理解任务在考什么

Work 1 有两条主线：

1. **自己写一个安全的 API**：登录、受保护的数据接口、第三个自定义接口；
   防 SQLi、防 XSS、JWT + 密码哈希；接入 SAST/SCA。
2. **复现一个真实 CVE**：用 Vulhub 启动漏洞环境，按 README 打出效果，
   分析根因，修复，再打一次证明打不通了。

评分点中，API 功能 2 分、安全措施 2 分、CI 2 分、CVE 复现 2 分、根因 1 分、
修复与验证 1 分。因此截图和命令记录不是装饰，是得分证据。

## 第 1 步：准备环境

```powershell
cd C:\Users\29611\Desktop\信息安全\lab\secure-api
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

如果 PowerShell 阻止激活脚本：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

生成 JWT 密钥并写进 `.env`：

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
Copy-Item .env.example .env
```

把生成的值填到 `.env` 的 `JWT_SECRET=` 后面。`.env` 已被 `.gitignore` 忽略，
不要提交。

## 第 2 步：启动并手工验证 API

```powershell
$env:JWT_SECRET = "把刚才生成的值贴在这里"
python run.py
```

另开一个终端：

```powershell
# 1. 健康检查
curl.exe http://127.0.0.1:5000/health

# 2. 不带 token 访问，应该 401
curl.exe -i http://127.0.0.1:5000/api/data

# 3. 登录，拿到 access_token
curl.exe -s -X POST http://127.0.0.1:5000/auth/login `
  -H "Content-Type: application/json" `
  -d '{\"login\":\"alice\",\"password\":\"AlicePass123!\"}'
```

把 token 复制到变量里：

```powershell
$TOKEN = "粘贴 access_token"
curl.exe -s http://127.0.0.1:5000/api/data -H "Authorization: Bearer $TOKEN"
```

**要理解的现象**：没有 token 是 401；有 token 是 200；token 被改一个字符也是
401，因为签名验证失败。

## 第 3 步：验证 SQLi 防护

在搜索参数里放经典 payload：

```powershell
curl.exe -s "http://127.0.0.1:5000/api/data?q=%27%20OR%201%3D1%20--" `
  -H "Authorization: Bearer $TOKEN"
```

正确结果是 `{"count":0,"items":[]}`。如果返回全部帖子，说明输入拼进了 SQL。

代码层面的关键是 `app/routes.py` 里的 `?` 占位符和参数元组。**不要**写成：

```python
# 错误示例：可被 SQLi
sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%'"
```

## 第 4 步：验证 XSS 输出转义

```powershell
curl.exe -s -X POST http://127.0.0.1:5000/api/data `
  -H "Authorization: Bearer $TOKEN" `
  -H "Content-Type: application/json" `
  -d '{\"title\":\"<script>alert(1)</script>\",\"body\":\"<img src=x onerror=alert(1)>\"}'
```

返回中的 `<` 应该变成 `&lt;`，`"` 变成 `&quot;`。这样浏览器会把内容当文本，
不会执行脚本。

## 第 5 步：运行测试与扫描

```powershell
python -m pytest -q
python -m bandit -r app -f txt
python -m pip_audit -r requirements.txt
```

本地预期：

- 16 个测试全部通过；
- Bandit 输出 `No issues identified`；
- pip-audit 输出 `No known vulnerabilities found`。

## 第 6 步：推送到 GitLab，让 CI 跑起来

提交仓库在 `gitlab.se.ifmo.ru`，所以使用仓库根目录的 `.gitlab-ci.yml`。
先创建空仓库（不要勾选自动生成 README），然后：

```powershell
git init
git add .
git commit -m "Work 1: secure API, CI scans, CVE-2021-41773 analysis"
git branch -M main
git remote add origin https://gitlab.se.ifmo.ru/<your-account>/<repo>.git
git push -u origin main
```

打开仓库的 **Build → Pipelines**，等 `test`、`bandit`、`pip-audit` 三个
job 变绿。进去后：

1. 截整页图，证明 pipeline 成功；
2. 点开 `bandit` job 截图；
3. 点开 `pip-audit` job 截图；
4. 点开 **Browse artifacts**，再截一张 JSON 报告。

把这些图放到 `docs/screenshots/`，在 README 和报告里引用。手册明确要求
CI 报告截图，这一步不能省。

## 第 7 步：安装 Docker 并复现 CVE

Work 1 选择的是 **CVE-2021-41773**：Apache HTTP Server 2.4.49 路径穿越，
可读 `/etc/passwd`；开启 CGI 时可执行命令。选它是因为环境简单、效果直观、
根因清楚。

安装 Docker Desktop 后，确认：

```powershell
docker --version
docker compose version
```

然后一键复现：

```powershell
powershell -ExecutionPolicy Bypass -File .\cve\reproduce.ps1
```

脚本会自动 sparse clone Vulhub、构建 2.4.49 镜像、等待端口、发两个请求：

- `/icons/.%2e/.../etc/passwd` → 读到 `root:x:0:0`；
- `/cgi-bin/.%2e/.../bin/sh` + `echo;id` → 返回 `uid=...`。

## 第 8 步：修复并验证

```powershell
powershell -ExecutionPolicy Bypass -File .\cve\verify-fix.ps1
```

脚本会同时启动三个环境：

| 端口 | 版本/配置 | 预期 |
|---|---|---|
| 8080 | 2.4.49 原版 | 穿越成功，命令执行成功 |
| 8081 | 2.4.51，仍宽松配置 | 穿越 404 |
| 8082 | 2.4.51 + 根目录默认拒绝 | 穿越 403/404，首页仍 200 |

这同时证明了三件事：漏洞可复现、升级版本能修、配置加固是第二层防线。
注意 2.4.50 的修复不完整，还有 CVE-2021-42013，所以最低要升到 2.4.51。

## 第 9 步：整理报告

打开 `REPORT.md`，填写：

- Variant number；
- 姓名的英文写法；
- HDU number；
- 仓库 URL；
- 最后一次成功 pipeline URL；
- 所有截图位置。

报告里要能回答“为什么”而不只是“做了什么”：

- 为什么参数化查询能防 SQLi；
- 为什么输出转义能防 XSS；
- 为什么 bcrypt 比 SHA-256 适合存密码；
- CVE 的根因是路径规范化 + 宽松的 `<Directory />` 策略；
- 为什么修完要再做一次正常访问（回归测试）。

## 第 10 步：提交前自查

```powershell
python -m pytest -q
git status
```

确认没有提交 `.env`、`instance/`、`reports/`、`.venv/`。然后对照
`REPORT.md` 末尾的 checklist 和手册第 4 页的 “What Students Submit” 逐项打勾。
