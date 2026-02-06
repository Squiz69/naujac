# Technical Architecture

## System Overview

The Fileless Reflective DLL Loader implements a sophisticated code injection technique that operates entirely in memory, without writing files to disk. It uses thread hijacking instead of the more common (and more easily detected) CreateRemoteThread approach.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Main Program (main.cpp)                   │
│                                                               │
│  • Command-line parsing                                      │
│  • Workflow orchestration                                    │
│  • User interaction                                          │
└────────────┬─────────────────────────────────────┬──────────┘
             │                                     │
             │                                     │
    ┌────────▼─────────┐                 ┌────────▼──────────┐
    │  NetworkStream   │                 │  ThreadHijacker    │
    │                  │                 │                    │
    │  • Fetch DLL     │                 │  • Find process    │
    │  • Network I/O   │                 │  • Find thread     │
    │  • Buffer mgmt   │                 │  • Suspend thread  │
    └────────┬─────────┘                 │  • Capture context │
             │                           │  • Hijack thread   │
             │                           └────────┬───────────┘
             │                                    │
    ┌────────▼─────────┐                         │
    │     PEMapper     │◄────────────────────────┘
    │                  │
    │  • Validate PE   │
    │  • Map sections  │
    │  • Resolve IAT   │
    │  • Relocations   │
    │  • Entry point   │
    └────────┬─────────┘
             │
             │
    ┌────────▼─────────┐
    │  PanicFunction   │
    │                  │
    │  • Restore ctx   │
    │  • Zero memory   │
    │  • Free memory   │
    │  • Clear traces  │
    └──────────────────┘
```

## Execution Flow

### Phase 1: DLL Acquisition
```
1. User specifies DLL source (local file or network)
2. NetworkStream component fetches raw DLL bytes
3. DLL remains in memory buffer (never written to disk)
```

### Phase 2: Process and Thread Location
```
1. ThreadHijacker scans running processes
2. Locates target process by name (e.g., "FiveM.exe")
3. Opens process handle with required permissions
4. Enumerates threads in target process
5. Selects a suitable thread for hijacking
```

### Phase 3: Manual PE Mapping
```
1. PEMapper validates PE headers (DOS, NT)
2. Allocates memory in target process (VirtualAllocEx)
3. Copies PE headers to allocated memory
4. Maps each section to its Virtual Address (VA)
5. Resolves Import Address Table (IAT):
   - Parse Import Directory
   - Load each imported DLL
   - Resolve function addresses
   - Write addresses to IAT
6. Applies base relocations:
   - Calculate delta from preferred base
   - Parse relocation directory
   - Apply fixups to absolute addresses
7. Calculates DLL entry point address
```

### Phase 4: Thread Hijacking
```
1. Open thread handle with required permissions
2. Suspend target thread (SuspendThread)
3. Capture current thread context (GetThreadContext)
4. Save original RIP/EIP for restoration
5. Modify context to redirect RIP to DLL entry point
6. Set modified context (SetThreadContext)
7. Resume thread (ResumeThread)
8. Thread executes injected DLL!
```

### Phase 5: Self-Erasure (Panic Function)
```
1. User presses 'P' key
2. Suspend hijacked thread
3. Restore original thread context
4. Zero allocated memory (SecureZeroMemory)
5. Free remote memory (VirtualFreeEx)
6. Resume thread with original context
7. Clear operation traces
```

## Memory Layout

### Before Injection
```
Target Process Memory:
┌──────────────────────┐
│  Kernel Memory       │
├──────────────────────┤
│                      │
│  User Memory         │
│  (Process code/data) │
│                      │
└──────────────────────┘
```

### After Injection
```
Target Process Memory:
┌──────────────────────┐
│  Kernel Memory       │
├──────────────────────┤
│  Injected DLL        │ ← Allocated by VirtualAllocEx
│  ┌────────────────┐  │
│  │ PE Headers     │  │
│  ├────────────────┤  │
│  │ .text section  │  │ (code)
│  ├────────────────┤  │
│  │ .data section  │  │ (initialized data)
│  ├────────────────┤  │
│  │ .rdata section │  │ (read-only data)
│  └────────────────┘  │
├──────────────────────┤
│  Original Process    │
│  Memory              │
└──────────────────────┘
```

## Thread Context Hijacking

### x64 Context Structure
```cpp
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;

// Before hijacking:
ctx.Rip = 0x00007FF8A1234567  // Original instruction pointer

// After hijacking:
ctx.Rip = 0x00007FF8B9876543  // Redirected to DLL entry point
```

### Instruction Pointer Redirection
```
Original Thread Execution:
    RIP → [Original Code] → [Next Instruction] → ...

Hijacked Thread Execution:
    RIP → [DLL Entry Point] → [DLL Code] → ...
```

## Import Address Table (IAT) Resolution

### IAT Structure
```
Import Directory Table:
┌─────────────────────────────┐
│ Import Descriptor 1         │
│  - DLL Name: "kernel32.dll" │
│  - IAT RVA: 0x2000          │
│  - ILT RVA: 0x2100          │
├─────────────────────────────┤
│ Import Descriptor 2         │
│  - DLL Name: "user32.dll"   │
│  - IAT RVA: 0x2200          │
│  - ILT RVA: 0x2300          │
└─────────────────────────────┘

Import Address Table (IAT):
┌─────────────────────────────┐
│ [0x2000] → GetProcAddress   │
│ [0x2008] → LoadLibraryA     │
│ [0x2010] → CreateThread     │
└─────────────────────────────┘
```

### Resolution Process
```
1. Read Import Descriptor
2. Get DLL name ("kernel32.dll")
3. LoadLibrary(DLL name) in injector process
4. For each import:
   a. Read function name or ordinal
   b. GetProcAddress(hModule, functionName)
   c. Write resolved address to IAT in target process
```

## Base Relocations

### Relocation Structure
```
Base Relocation Directory:
┌─────────────────────────────┐
│ Relocation Block 1          │
│  - Virtual Address: 0x1000  │
│  - Size: 0x100              │
│  - Entries:                 │
│    • Type: DIR64, Offset: 0x10
│    • Type: DIR64, Offset: 0x20
│    • ...                    │
└─────────────────────────────┘
```

### Relocation Application
```
Delta = Actual Base - Preferred Base
      = 0x180020000 - 0x180000000
      = 0x20000

For each relocation:
    1. Read value at (VirtualAddress + Offset)
    2. Add Delta to the value
    3. Write back to memory
```

## Security Features

### Memory Protection
- Uses PAGE_EXECUTE_READWRITE during mapping
- Can be enhanced to set proper section protections:
  - .text → PAGE_EXECUTE_READ
  - .data → PAGE_READWRITE
  - .rdata → PAGE_READONLY

### Panic Function Security
1. **Context Restoration**: Prevents crashes by restoring thread state
2. **Memory Zeroing**: Uses SecureZeroMemory (cannot be optimized away)
3. **Memory Release**: Frees allocated regions
4. **Trace Clearing**: Removes evidence of operation

## API Usage

### Windows APIs Used

#### Process/Thread Management
- `CreateToolhelp32Snapshot` - Enumerate processes/threads
- `Process32First/Next` - Iterate processes
- `Thread32First/Next` - Iterate threads
- `OpenProcess` - Open process handle
- `OpenThread` - Open thread handle

#### Thread Context Manipulation
- `SuspendThread` - Suspend thread execution
- `GetThreadContext` - Capture thread registers
- `SetThreadContext` - Modify thread registers
- `ResumeThread` - Resume thread execution

#### Memory Management
- `VirtualAllocEx` - Allocate memory in remote process
- `VirtualFreeEx` - Free remote memory
- `WriteProcessMemory` - Write to remote memory
- `ReadProcessMemory` - Read from remote memory
- `SecureZeroMemory` - Securely zero memory

#### PE Loading
- `LoadLibraryA` - Load DLLs for import resolution
- `GetProcAddress` - Resolve function addresses

## Performance Considerations

### Memory Overhead
- Base allocation: Size of DLL's OptionalHeader.SizeOfImage
- Additional: Import descriptors, relocation data
- Typical: 100KB - 5MB depending on DLL

### Time Complexity
- Process enumeration: O(n) where n = number of processes
- Thread enumeration: O(t) where t = number of threads
- IAT resolution: O(i * f) where i = imported DLLs, f = functions per DLL
- Relocations: O(r) where r = number of relocations

### Thread Safety
- Thread hijacking is inherently unsafe
- Suspending arbitrary threads can cause deadlocks
- Best practice: Select threads carefully

## Limitations

### Current Implementation
- x64 only (can be extended to x86)
- Basic relocation support (DIR64 type)
- Simple IAT resolution
- No TLS (Thread Local Storage) support
- No exception handling setup

### Target Process Restrictions
- Cannot inject into protected processes (PPL)
- Requires appropriate permissions
- Some system processes are protected
- Anti-cheat software may detect

## References

### PE Format
- [Microsoft PE Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- IMAGE_DOS_HEADER, IMAGE_NT_HEADERS structures
- Section headers, import/export tables

### Thread Context
- [CONTEXT Structure](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)
- x64 registers: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, RIP, R8-R15
- Flags, segment registers

### Memory Management
- [Virtual Memory Functions](https://docs.microsoft.com/en-us/windows/win32/memory/virtual-memory-functions)
- PAGE_* protection constants
- MEM_* allocation types
