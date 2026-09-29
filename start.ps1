# Start LLM Gateway with the project-local .venv
# Usage: powershell -ExecutionPolicy Bypass -File .\start.ps1
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
Write-Host "Starting LLM Gateway (V2) on http://127.0.0.1:4101 ..." -ForegroundColor Green
& $Python -m uvicorn app.main:app --host 127.0.0.1 --port 4101