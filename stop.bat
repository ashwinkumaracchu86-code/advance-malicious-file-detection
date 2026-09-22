@echo off
echo Stopping MFDS servers...
taskkill /FI "WINDOWTITLE eq MFDS Backend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq MFDS Frontend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq VITE*" /F >nul 2>&1
echo Done.
