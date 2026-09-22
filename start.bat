@echo off
set "ROOT=%~dp0"

echo ============================================
echo   Malicious File Detection System
echo ============================================
echo.

echo Starting Backend (FastAPI)...
cd /d "%ROOT%backend"
start "MFDS-Backend" python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

timeout /t 1 /nobreak >nul

echo Starting Frontend (React)...
cd /d "%ROOT%frontend"
start "MFDS-Frontend" cmd /c "npm run dev"

cd /d "%ROOT%"

echo.
echo ============================================
echo   Servers Starting...
echo ============================================
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5173
echo ============================================
echo.
timeout /t 2 /nobreak >nul
start http://localhost:5173
