@echo off
:: Launcher for configure_tools_windows.ps1.
:: All implementation lives in the PowerShell script next to this file.
:: Forwards any args to the script (use -TenantName, -CertDir, -NonInteractive, etc.).
:: enabledelayedexpansion is required: a parenthesized if/else block has all of its
:: %VAR% references expanded at parse time, so a plain %ERRORLEVEL% inside the block
:: would read a stale value from before `where` ran. !ERRORLEVEL! defers the read.
setlocal enabledelayedexpansion

set "PS_SCRIPT=%~dp0configure_tools_windows.ps1"
if not exist "%PS_SCRIPT%" (
    echo Error: configure_tools_windows.ps1 not found alongside this launcher.
    exit /b 1
)

:: Prefer pwsh (PowerShell 7+); fall back to Windows PowerShell 5.1.
set "PS_EXE="
where pwsh >NUL 2>&1
if !ERRORLEVEL! EQU 0 (
    set "PS_EXE=pwsh"
) else (
    where powershell >NUL 2>&1
    if !ERRORLEVEL! EQU 0 set "PS_EXE=powershell"
)
if "!PS_EXE!"=="" (
    echo Error: neither pwsh nor powershell is on PATH.
    exit /b 1
)

%PS_EXE% -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
exit /b %ERRORLEVEL%
