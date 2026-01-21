@echo off
REM ===========================================================================
REM Jarwis Agent - Build Windows Installer
REM ===========================================================================
REM
REM Quick launcher for the installer build process.
REM
REM Usage:
REM   BUILD_WINDOWS_INSTALLER.bat           - Build all installers
REM   BUILD_WINDOWS_INSTALLER.bat --exe     - Build EXE only
REM   BUILD_WINDOWS_INSTALLER.bat --msi     - Build MSI only
REM   BUILD_WINDOWS_INSTALLER.bat --sign    - Build and sign
REM
REM ===========================================================================

cd /d "%~dp0"
call installer\BUILD_INSTALLER.bat %*
