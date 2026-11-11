# Sentinel SOC — kill stale listeners, then start API
$ErrorActionPreference = "Continue"
$ports = 8000, 2222, 8080, 2121, 2323

Write-Host "Freeing ports $($ports -join ', ')..." -ForegroundColor Cyan
foreach ($port in $ports) {
    $lines = netstat -ano | Select-String -Pattern ":$port\s+.*LISTENING"
    foreach ($line in $lines) {
        $procId = ($line.ToString() -split '\s+')[-1]
        if ($procId -match '^\d+$' -and [int]$procId -gt 0) {
            Write-Host "  Killing PID $procId (port $port)"
            taskkill /PID $procId /F 2>$null | Out-Null
        }
    }
}

Start-Sleep -Seconds 1

# Allow the Vercel-hosted dashboard to talk to this local API. Browsers treat
# http://127.0.0.1 as a trustworthy origin, so an HTTPS page may call it.
if (-not $env:SENTINEL_ORIGINS) {
    $env:SENTINEL_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,https://sentinel-soc-sand.vercel.app"
}

Write-Host "Starting Sentinel on http://127.0.0.1:8000 ..." -ForegroundColor Green
Set-Location $PSScriptRoot
uvicorn main:app --host 127.0.0.1 --port 8000
