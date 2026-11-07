Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Starting FogTrust Demo Environment" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$frontendDir = Join-Path $PSScriptRoot "..\frontend"
Write-Host "Starting Frontend (React + Vite) on http://127.0.0.1:5173..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$frontendDir'; npm run dev"

Write-Host ""
Write-Host "Tip: To run backend alongside:" -ForegroundColor Yellow
Write-Host "  cd backend" -ForegroundColor Gray
Write-Host "  python manage.py runserver" -ForegroundColor Gray
Write-Host ""
Write-Host "If backend is not yet started, you can use the built-in" -ForegroundColor Yellow
Write-Host "'Demo Data Mode' toggle directly in the dashboard UI!" -ForegroundColor Yellow
Write-Host ""

