$ErrorActionPreference = "SilentlyContinue"

$dockerBin = "C:\Program Files\Docker\Docker\resources\bin"
if (Test-Path $dockerBin) { $env:PATH = "$dockerBin;$env:PATH" }

$repoRoot = Split-Path $PSScriptRoot -Parent
$vulhubRoot = Join-Path $repoRoot "vulhub"

Push-Location (Join-Path $vulhubRoot "httpd/CVE-2021-41773")
docker compose down
Pop-Location

Push-Location (Join-Path $PSScriptRoot "fixed-version-only")
docker compose down
Pop-Location

Push-Location (Join-Path $PSScriptRoot "fixed-hardened")
docker compose down
Pop-Location
