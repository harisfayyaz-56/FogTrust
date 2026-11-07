@echo off
echo ========================================================
echo   Starting FogTrust Demo Environment
echo ========================================================
echo.
echo Starting Frontend (React + Vite) on http://127.0.0.1:5173...
start "FogTrust-Frontend" cmd /k "cd /d %~dp0..\frontend && npm run dev"

echo.
echo Tip: To run backend alongside:
echo   cd backend
echo   python manage.py runserver
echo.
echo If backend is not yet started, you can use the built-in
echo "Demo Data Mode" toggle directly in the dashboard UI!
echo.
pause

