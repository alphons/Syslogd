@echo off

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Please run as Administrator...
	pause
    exit /B
)
sc.exe create ".NET Syslogd Service" binpath="%~dp0Syslogd.exe" start= auto
sc.exe start ".NET Syslogd Service"
pause
