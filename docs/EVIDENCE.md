# Local Evidence

Date: 2026-10-19

## 1. Test suite

```text
$ python -m pytest -q
................                                                         [100%]
16 passed in 0.90s
```

## 2. SAST — Bandit

```text
$ python -m bandit -r app -f txt
Run started:2026-10-19 02:29:27

Test results:
    No issues identified.

Code scanned:
    Total lines of code: 395
    Total issues (by severity):
        High: 0
        Medium: 0
        Low: 0
```

## 3. SCA — pip-audit

```text
$ python -m pip_audit -r requirements.txt
No known vulnerabilities found
```

## 4. Runtime checks

### Health

```text
GET /health -> 200 {"status":"ok"}
```

### Access control

```text
GET /api/data without token -> 401
GET /api/me with forged JWT -> 401
```

### Login and data

```text
POST /auth/login -> 200
token_type = Bearer
expires_in = 1800

GET /api/data with token -> 200
count = 2
```

### XSS output encoding

Request body:

```json
{"title":"<script>alert(\"xss\")</script>","body":"<img src=x onerror=\"alert(1)\">"}
```

Response body (JSON-escaped `&` shown as `\u0026`):

```json
{
  "title": "\u0026lt;script\u0026gt;alert(\u0026quot;xss\u0026quot;)\u0026lt;/script\u0026gt;",
  "body": "\u0026lt;img src=x onerror=\u0026quot;alert(1)\u0026quot;\u0026gt;"
}
```

Decoded value:

```text
&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;
```

### SQL injection

```text
GET /api/data?q=' OR 1=1 -- -> 200 {"count":0,"items":[]}
```

The payload did not change the query structure and returned no rows.

## 5. CVE evidence

Run after Docker is installed:

```powershell
powershell -ExecutionPolicy Bypass -File .\cve\reproduce.ps1
powershell -ExecutionPolicy Bypass -File .\cve\verify-fix.ps1
```

Paste the terminal output and screenshots below.

```text
<vulnerable traversal output>
<vulnerable RCE output>
<fixed traversal output>
<regression output>
```
