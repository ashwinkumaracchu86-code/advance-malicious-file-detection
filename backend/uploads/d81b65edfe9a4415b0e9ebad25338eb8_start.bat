@echo off
title Two-Factor Authentication System
echo ========================================
echo   Two-Factor Authentication System
echo ========================================
echo.

if not exist "backend\venv" (
    echo [1/3] Creating Python virtual environment...
    python -m venv backend\venv
)

echo [2/3] Installing backend dependencies...
call backend\venv\Scripts\pip install -q fastapi "uvicorn[standard]" "sqlalchemy[asyncio]" aiosqlite alembic pydantic pydantic-settings "python-jose[cryptography]" "passlib[bcrypt]" argon2-cffi==21.3.0 twilio python-multipart httpx email-validator >nul 2>&1

echo [3/3] Starting servers...
echo.

echo Starting Backend on port 8000...
start "Backend" cmd /k "cd /d %~dp0backend && ..\backend\venv\Scripts\activate && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak >nul

echo Starting Frontend on port 7010...
start "Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ========================================
echo   Servers are starting...
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:7010
echo   API Docs: http://localhost:8000/docs
echo ========================================
echo.
echo   NOTE: In dev mode, OTP codes appear in the
echo   browser and in the backend console.
echo.
echo Press any key to stop all servers...
pause >nul

echo.
echo Stopping servers...
taskkill /FI "WindowTitle eq Backend" /T /F >nul 2>&1
taskkill /FI "WindowTitle eq Frontend" /T /F >nul 2>&1
echo Done.
