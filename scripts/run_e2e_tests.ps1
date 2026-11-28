Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Running FogTrust Member 4 E2E QA Test Suite" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$rootDir = Join-Path $PSScriptRoot ".."
Set-Location $rootDir
node --test tests/e2e/dashboard.test.mjs

