@echo off
rem IdleLock - lock immediately
setlocal
set "SCRIPT=%~dp0idle_lock.py"
where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "IdleLock" pythonw "%SCRIPT%"
) else (
  if exist "%LocalAppData%\Programs\Python\Python312\pythonw.exe" (
    start "IdleLock" "%LocalAppData%\Programs\Python\Python312\pythonw.exe" "%SCRIPT%"
  ) else (
    echo [IdleLock] Python not found. Please install Python 3.10+ first.
    pause
  )
)
endlocal
