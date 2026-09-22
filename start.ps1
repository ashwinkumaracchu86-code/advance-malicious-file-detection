$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Malicious File Detection System" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Starting Backend (FastAPI)..." -ForegroundColor Yellow
Start-Process -FilePath "python" -ArgumentList "-m", "uvicorn", "app.main:app", "--reload", "--host", "0.0.0.0", "--port", "8000" -WorkingDirectory "$projectRoot\backend"
Start-Sleep -Seconds 1

Write-Host "Starting Frontend (React)..." -ForegroundColor Yellow
Start-Process -FilePath "cmd.exe" -ArgumentList "/c npm run dev" -WorkingDirectory "$projectRoot\frontend"
Start-Sleep -Seconds 2

Set-Location "$projectRoot"

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Servers are running!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Backend:  http://localhost:8000" -ForegroundColor White
Write-Host "  Frontend: http://localhost:5173" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green

Start-Process "http://localhost:5173"
