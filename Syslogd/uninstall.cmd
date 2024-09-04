@echo off

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Please run as Administrator...
	pause
    exit /B
)

sc.exe stop ".NET Syslogd Service"

sc.exe delete ".NET Syslogd Service"
pause
