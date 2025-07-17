@echo off
rem Installation script for Biometric Credential Provider
rem Copyright (c) 2024 Biometric Credential Provider
rem 
rem This script installs the Biometric Credential Provider on the system
rem Run as Administrator

echo ========================================
echo Installing Biometric Credential Provider
echo ========================================

rem Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must be run as Administrator!
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

set SCRIPT_DIR=%~dp0
set DLL_NAME=BiometricCredentialProvider.dll
set SYSTEM_DIR=C:\Windows\System32
set CONFIG_DIR=C:\ProgramData\BiometricCredentialProvider
set LOG_DIR=%CONFIG_DIR%\logs

rem Check if DLL exists
if not exist "%SCRIPT_DIR%\%DLL_NAME%" (
    echo Error: %DLL_NAME% not found in current directory
    echo Please build the project first using build.bat
    pause
    exit /b 1
)

echo Creating directories...
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo Copying DLL to System32...
copy "%SCRIPT_DIR%\%DLL_NAME%" "%SYSTEM_DIR%\" >nul
if %errorlevel% neq 0 (
    echo Error: Failed to copy DLL to System32
    pause
    exit /b 1
)

echo Copying configuration files...
if exist "%SCRIPT_DIR%\config\BiometricConfig.ini" (
    copy "%SCRIPT_DIR%\config\BiometricConfig.ini" "%CONFIG_DIR%\" >nul
)
if exist "%SCRIPT_DIR%\config\AIModelConfig.json" (
    copy "%SCRIPT_DIR%\config\AIModelConfig.json" "%CONFIG_DIR%\" >nul
)

echo Registering COM components...
regsvr32 /s "%SYSTEM_DIR%\%DLL_NAME%"
if %errorlevel% neq 0 (
    echo Error: Failed to register COM components
    pause
    exit /b 1
)

echo Applying registry settings...
if exist "%SCRIPT_DIR%\scripts\register.reg" (
    regedit /s "%SCRIPT_DIR%\scripts\register.reg"
    if %errorlevel% neq 0 (
        echo Warning: Registry import may have failed
    )
)

echo Setting up TPM (if available)...
powershell -Command "& {
    try {
        $tpm = Get-Tpm
        if ($tpm.TpmPresent -eq $true) {
            Write-Host 'TPM is available and will be used for secure storage'
        } else {
            Write-Host 'TPM not available, using software encryption'
        }
    } catch {
        Write-Host 'TPM status check failed, using software encryption'
    }
}"

echo Configuring permissions...
icacls "%CONFIG_DIR%" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant "BUILTIN\Administrators:(OI)(CI)F" /grant "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)R" >nul
icacls "%LOG_DIR%" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant "BUILTIN\Administrators:(OI)(CI)F" /grant "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)W" >nul

echo Verifying installation...
if exist "%SYSTEM_DIR%\%DLL_NAME%" (
    echo ✓ DLL copied successfully
) else (
    echo ✗ DLL copy failed
)

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{E74E1D00-5A8F-4D85-9A2B-7C8E9F1A2B3C}" >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ Registry entries created
) else (
    echo ✗ Registry entries missing
)

if exist "%CONFIG_DIR%\BiometricConfig.ini" (
    echo ✓ Configuration files copied
) else (
    echo ✗ Configuration files missing
)

echo.
echo Installation Summary:
echo ====================
echo DLL Location: %SYSTEM_DIR%\%DLL_NAME%
echo Config Directory: %CONFIG_DIR%
echo Log Directory: %LOG_DIR%
echo.

echo Testing credential provider registration...
powershell -Command "& {
    try {
        $providers = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\*' -Name '(Default)' -ErrorAction SilentlyContinue
        $biometricProvider = $providers | Where-Object { $_.PSChildName -eq '{E74E1D00-5A8F-4D85-9A2B-7C8E9F1A2B3C}' }
        if ($biometricProvider) {
            Write-Host '✓ Biometric Credential Provider registered successfully'
        } else {
            Write-Host '✗ Biometric Credential Provider not found in registry'
        }
    } catch {
        Write-Host '✗ Error checking credential provider registration'
    }
}"

echo.
echo IMPORTANT NOTES:
echo ================
echo 1. The system will need to be restarted for the credential provider to take effect
echo 2. Configure the AI model endpoint in %CONFIG_DIR%\AIModelConfig.json
echo 3. Update the API key in the configuration file
echo 4. Test the installation on a non-production system first
echo 5. Check the log files in %LOG_DIR% for any issues
echo.

set /p restart=Restart the system now? (y/n): 
if /i "%restart%"=="y" (
    echo Restarting system in 10 seconds...
    shutdown /r /t 10 /c "Restarting to enable Biometric Credential Provider"
) else (
    echo Installation complete. Please restart the system manually.
)

echo.
echo Installation completed!
pause