#!/bin/bash
# Build script for Fileless DLL Loader (Linux/MinGW)

echo "==============================================="
echo "  Fileless Reflective DLL Loader Build Script"
echo "==============================================="
echo ""

# Check if CMake is available
if ! command -v cmake &> /dev/null; then
    echo "[ERROR] CMake not found in PATH"
    echo "Please install CMake"
    exit 1
fi

# Create build directory
mkdir -p build
cd build

echo "[1/3] Configuring with CMake..."
cmake .. || {
    echo "[ERROR] CMake configuration failed"
    cd ..
    exit 1
}

echo ""
echo "[2/3] Building Release configuration..."
cmake --build . --config Release || {
    echo "[ERROR] Build failed"
    cd ..
    exit 1
}

echo ""
echo "[3/3] Build complete!"
echo ""
echo "Output files:"
echo "  - FilelessDLLLoader.exe : build/Release/FilelessDLLLoader.exe"
echo "  - ExamplePayload.dll    : build/Release/ExamplePayload.dll"
echo ""

cd ..

echo "==============================================="
echo "  Build Successful!"
echo "==============================================="
echo ""
echo "To run the injector:"
echo "  cd build/Release"
echo "  ./FilelessDLLLoader.exe local ExamplePayload.dll notepad.exe"
echo ""
