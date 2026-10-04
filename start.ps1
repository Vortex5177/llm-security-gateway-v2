# Start LLM Gateway with the project-local .venv
# Usage: powershell -ExecutionPolicy Bypass -File .\start.ps1
# Security policy: set GATEWAY_SECURITY_CONFIG to override (default: config/security.strict-demo.yaml)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Host "[ERROR] Project venv not found: $Python" -ForegroundColor Red
    Write-Host "Run these commands in $Root first:" -ForegroundColor Yellow
    Write-Host "    python -m venv .venv"
    Write-Host "    .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    exit 1
}

Set-Location $Root

# 安全档默认 strict-demo；调用方显式设置 GATEWAY_SECURITY_CONFIG 时不覆盖
if (-not $env:GATEWAY_SECURITY_CONFIG) {
    $env:GATEWAY_SECURITY_CONFIG = "config/security.strict-demo.yaml"
    Write-Host "[INFO] GATEWAY_SECURITY_CONFIG not set, defaulting to config/security.strict-demo.yaml" -ForegroundColor DarkGray
}

Write-Host "Starting LLM Gateway (V2) on http://0.0.0.0:4101 (LAN reachable) ..." -ForegroundColor Green
& $Python -m uvicorn app.main:app --host 0.0.0.0 --port 4101