@echo off
rem Build script for Biometric Credential Provider
rem Copyright (c) 2024 Biometric Credential Provider

echo ========================================
echo Building Biometric Credential Provider
echo ========================================

set SOLUTION_DIR=%~dp0
set PROJECT_NAME=BiometricCredentialProvider
set BUILD_CONFIG=Release
set PLATFORM=x64

rem Check if Visual Studio is installed
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if %errorlevel% neq 0 (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    if %errorlevel% neq 0 (
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
        if %errorlevel% neq 0 (
            echo Error: Visual Studio 2019 not found
            pause
            exit /b 1
        )
    )
)

rem Clean previous build
echo Cleaning previous build...
if exist "%SOLUTION_DIR%\%PLATFORM%" rmdir /s /q "%SOLUTION_DIR%\%PLATFORM%"
if exist "%SOLUTION_DIR%\x64" rmdir /s /q "%SOLUTION_DIR%\x64"
if exist "%SOLUTION_DIR%\Win32" rmdir /s /q "%SOLUTION_DIR%\Win32"

rem Create output directories
if not exist "%SOLUTION_DIR%\%PLATFORM%\%BUILD_CONFIG%" mkdir "%SOLUTION_DIR%\%PLATFORM%\%BUILD_CONFIG%"
if not exist "%SOLUTION_DIR%\logs" mkdir "%SOLUTION_DIR%\logs"

echo Building solution...
msbuild "%SOLUTION_DIR%\%PROJECT_NAME%.sln" /p:Configuration=%BUILD_CONFIG% /p:Platform=%PLATFORM% /p:PlatformToolset=v143 /m /v:minimal

if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo Build completed successfully!

rem Check if DLL was created
if exist "%SOLUTION_DIR%\%PLATFORM%\%BUILD_CONFIG%\%PROJECT_NAME%.dll" (
    echo DLL created: %SOLUTION_DIR%\%PLATFORM%\%BUILD_CONFIG%\%PROJECT_NAME%.dll
) else (
    echo Error: DLL not found!
    pause
    exit /b 1
)

echo.
echo Build Summary:
echo ==============
echo Configuration: %BUILD_CONFIG%
echo Platform: %PLATFORM%
echo Output: %SOLUTION_DIR%\%PLATFORM%\%BUILD_CONFIG%\%PROJECT_NAME%.dll
echo.

rem Optional: Run tests
set /p run_tests=Run tests? (y/n): 
if /i "%run_tests%"=="y" (
    echo Running tests...
    if exist "%SOLUTION_DIR%\%PLATFORM%\%BUILD_CONFIG%\BiometricTests.exe" (
        "%SOLUTION_DIR%\%PLATFORM%\%BUILD_CONFIG%\BiometricTests.exe"
    ) else (
        echo Tests not found, skipping...
    )
)

rem Optional: Copy to system directory
set /p copy_dll=Copy DLL to System32? (y/n): 
if /i "%copy_dll%"=="y" (
    echo Copying DLL to System32...
    copy "%SOLUTION_DIR%\%PLATFORM%\%BUILD_CONFIG%\%PROJECT_NAME%.dll" "C:\Windows\System32\" >nul
    if %errorlevel% equ 0 (
        echo DLL copied successfully!
    ) else (
        echo Error copying DLL. Run as administrator.
    )
)

echo.
echo Build process completed!
pause