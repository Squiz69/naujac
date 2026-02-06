@echo off
REM Build script for Fileless DLL Loader (Windows)

echo ===============================================
echo   Fileless Reflective DLL Loader Build Script
echo ===============================================
echo.

REM Check if CMake is available
where cmake >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] CMake not found in PATH
    echo Please install CMake or add it to PATH
    pause
    exit /b 1
)

REM Create build directory
if not exist "build" mkdir build
cd build

echo [1/3] Configuring with CMake...
cmake .. -G "Visual Studio 16 2019" -A x64
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] CMake configuration failed
    cd ..
    pause
    exit /b 1
)

echo.
echo [2/3] Building Release configuration...
cmake --build . --config Release
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed
    cd ..
    pause
    exit /b 1
)

echo.
echo [3/3] Build complete!
echo.
echo Output files:
echo   - FilelessDLLLoader.exe : build\Release\FilelessDLLLoader.exe
echo   - ExamplePayload.dll    : build\Release\ExamplePayload.dll
echo.

cd ..

echo ===============================================
echo   Build Successful!
echo ===============================================
echo.
echo To run the injector:
echo   cd build\Release
echo   FilelessDLLLoader.exe local ExamplePayload.dll notepad.exe
echo.
pause
