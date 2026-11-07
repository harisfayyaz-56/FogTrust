Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Starting FogTrust Frontend Dashboard (Port 5173)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$frontendDir = Join-Path $PSScriptRoot "..\frontend"
Set-Location $frontendDir
npm run dev

