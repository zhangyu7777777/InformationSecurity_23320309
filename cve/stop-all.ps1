$ErrorActionPreference = "SilentlyContinue"

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
