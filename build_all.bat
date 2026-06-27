@echo off
setlocal enabledelayedexpansion

set "VCVARS=D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
set "SRC_DIR=%~dp0"
set "SRC_DIR=%SRC_DIR:~0,-1%"
set "RELEASE_DIR=%SRC_DIR%\release"
mkdir "%RELEASE_DIR%\x64" 2>nul
mkdir "%RELEASE_DIR%\x86" 2>nul

:: ============================================
echo ===== Step 1: Build x64 (all targets) =====
:: ============================================
call "%VCVARS%" x64
if %errorlevel% neq 0 (
    echo [ERROR] vcvarsall x64 failed
    exit /b 1
)

set "BUILD_X64=%SRC_DIR%\build_x64"
if exist "%BUILD_X64%" rmdir /s /q "%BUILD_X64%"
mkdir "%BUILD_X64%"
cd /d "%BUILD_X64%"

echo --- CMake Configure x64 ---
cmake "%SRC_DIR%" -G "Ninja" -DCMAKE_CXX_COMPILER=cl -DCMAKE_C_COMPILER=cl -DCMAKE_BUILD_TYPE=Release
if %errorlevel% neq 0 (
    echo Ninja not found, trying Visual Studio generator...
    cmake "%SRC_DIR%" -G "Visual Studio 17 2022" -A x64
)
if %errorlevel% neq 0 (
    echo [ERROR] CMake x64 config failed
    exit /b 1
)

echo --- Build x64 ---
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo [ERROR] Build x64 failed
    exit /b 1
)

echo --- Copy x64 outputs ---
for %%T in (pe2shc runshc injector) do (
    if exist "%%T\Release\%%T.exe" (
        copy /y "%%T\Release\%%T.exe" "%RELEASE_DIR%\x64\%%T.x64.exe" >nul
        echo   %RELEASE_DIR%\x64\%%T.x64.exe
    ) else if exist "%%T\%%T.exe" (
        copy /y "%%T\%%T.exe" "%RELEASE_DIR%\x64\%%T.x64.exe" >nul
        echo   %RELEASE_DIR%\x64\%%T.x64.exe
    ) else if exist "%%T.exe" (
        copy /y "%%T.exe" "%RELEASE_DIR%\x64\%%T.x64.exe" >nul
        echo   %RELEASE_DIR%\x64\%%T.x64.exe
    ) else (
        echo   [WARN] %%T not found in expected paths
    )
)
echo.

:: ============================================
echo ===== Step 2: Build x86 (all targets) =====
:: ============================================
call "%VCVARS%" x86
if %errorlevel% neq 0 (
    echo [ERROR] vcvarsall x86 failed
    exit /b 1
)

set "BUILD_X86=%SRC_DIR%\build_x86"
if exist "%BUILD_X86%" rmdir /s /q "%BUILD_X86%"
mkdir "%BUILD_X86%"
cd /d "%BUILD_X86%"

echo --- CMake Configure x86 ---
cmake "%SRC_DIR%" -G "Ninja" -DCMAKE_CXX_COMPILER=cl -DCMAKE_C_COMPILER=cl -DCMAKE_BUILD_TYPE=Release
if %errorlevel% neq 0 (
    cmake "%SRC_DIR%" -G "Visual Studio 17 2022" -A Win32
)
if %errorlevel% neq 0 (
    echo [ERROR] CMake x86 config failed
    exit /b 1
)

echo --- Build x86 ---
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo [ERROR] Build x86 failed
    exit /b 1
)

echo --- Copy x86 outputs ---
for %%T in (pe2shc runshc injector) do (
    if exist "%%T\Release\%%T.exe" (
        copy /y "%%T\Release\%%T.exe" "%RELEASE_DIR%\x86\%%T.x86.exe" >nul
        echo   %RELEASE_DIR%\x86\%%T.x86.exe
    ) else if exist "%%T\%%T.exe" (
        copy /y "%%T\%%T.exe" "%RELEASE_DIR%\x86\%%T.x86.exe" >nul
        echo   %RELEASE_DIR%\x86\%%T.x86.exe
    ) else if exist "%%T.exe" (
        copy /y "%%T.exe" "%RELEASE_DIR%\x86\%%T.x86.exe" >nul
        echo   %RELEASE_DIR%\x86\%%T.x86.exe
    ) else (
        echo   [WARN] %%T not found in expected paths
    )
)
echo.

:: ============================================
echo ===== ALL BUILD COMPLETE =====
echo.
echo x64 outputs:
dir "%RELEASE_DIR%\x64\*.exe" /b 2>nul
echo.
echo x86 outputs:
dir "%RELEASE_DIR%\x86\*.exe" /b 2>nul

cd /d "%SRC_DIR%"
endlocal
pause