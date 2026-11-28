@echo off
echo ========================================================
echo   Running FogTrust Member 4 E2E QA Test Suite
echo ========================================================
cd /d "%~dp0.."
node --test tests/e2e/dashboard.test.mjs

