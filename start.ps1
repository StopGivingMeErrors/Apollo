# Sentinel SOC — kill stale listeners and start API
# Usage from project root:  .\start.ps1

$ErrorActionPreference = "Continue"
$Backend = Join-Path $PSScriptRoot "backend"
if (-not (Test-Path (Join-Path $Backend "main.py"))) {
    $Backend = $PSScriptRoot
}

$ports = @(8000, 2222, 8080, 2121, 2323)
Write-Host ""
Write-Host "[*] Freeing Sentinel ports..." -ForegroundColor Cyan
foreach ($port in $ports) {
    $lines = netstat -ano | Select-String ":$port\s+.*LISTENING"
    foreach ($line in $lines) {
        $procId = ($line.ToString().Trim() -split '\s+')[-1]
        if ($procId -match '^\d+$' -and [int]$procId -gt 0) {
            Write-Host "    killing PID $procId (port $port)"
            & taskkill /PID $procId /F 2>$null | Out-Null
        }
    }
}
Start-Sleep -Seconds 1

Set-Location $Backend
Write-Host "[*] Starting uvicorn on http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "    Live attack sim ON - open http://localhost:5173" -ForegroundColor DarkGray
Write-Host ""
uvicorn main:app --host 127.0.0.1 --port 8000
