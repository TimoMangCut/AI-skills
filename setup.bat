@echo off
REM Bootstrap script for LocalSec AI-skills on Windows CMD.
REM Run from <Project-Root> as:
REM   AI-skills\setup.bat
REM Or to uninstall:
REM   AI-skills\setup.bat --uninstall

setlocal
set "SKILL_DIR=%~dp0"
if "%SKILL_DIR:~-1%"=="\" set "SKILL_DIR=%SKILL_DIR:~0,-1%"
set "PROJECT_ROOT=%CD%"
for %%I in ("%SKILL_DIR%") do set "SKILL_FOLDER_NAME=%%~nxI"
set "MODE=%~1"
if "%MODE%"=="" set "MODE=install"

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python "%SKILL_DIR%\setup_bootstrap.py" "%SKILL_DIR%" "%PROJECT_ROOT%" "%SKILL_FOLDER_NAME%" "%MODE%"
    exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py -3 "%SKILL_DIR%\setup_bootstrap.py" "%SKILL_DIR%" "%PROJECT_ROOT%" "%SKILL_FOLDER_NAME%" "%MODE%"
    exit /b %ERRORLEVEL%
)

where python3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python3 "%SKILL_DIR%\setup_bootstrap.py" "%SKILL_DIR%" "%PROJECT_ROOT%" "%SKILL_FOLDER_NAME%" "%MODE%"
    exit /b %ERRORLEVEL%
)

echo [!] Khong tim thay Python (python hoac py -3). Vui long cai dat Python 3.10+ tren Windows.
exit /b 1
