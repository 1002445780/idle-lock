@echo off
rem IdleLock - auto lock after N minutes of system idle (resident process)
rem Change IDLE_MIN below to adjust the idle timeout.
setlocal
set "IDLE_MIN=30"
set "SCRIPT=%~dp0idle_lock.py"
where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "IdleLock" pythonw "%SCRIPT%" --idle %IDLE_MIN%
) else (
  if exist "%LocalAppData%\Programs\Python\Python312\pythonw.exe" (
    start "IdleLock" "%LocalAppData%\Programs\Python\Python312\pythonw.exe" "%SCRIPT%" --idle %IDLE_MIN%
  ) else (
    echo [IdleLock] Python not found. Please install Python 3.10+ first.
    pause
  )
)
endlocal
