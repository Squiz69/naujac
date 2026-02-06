#ifndef THREAD_HIJACKER_H
#define THREAD_HIJACKER_H

#include <windows.h>
#include <string>

/**
 * @class ThreadHijacker
 * @brief Implements thread execution hijacking for DLL injection
 * 
 * Identifies a legitimate thread in target process, suspends it,
 * captures context, and redirects RIP to DLL entry point.
 */
class ThreadHijacker {
public:
    ThreadHijacker();
    ~ThreadHijacker();

    /**
     * @brief Finds a target process by name
     * @param processName Name of the process (e.g., "FiveM.exe")
     * @return Process ID, or 0 if not found
     */
    DWORD FindTargetProcess(const char* processName);

    /**
     * @brief Opens target process
     * @param processId Target process ID
     * @return Process handle, or NULL on failure
     */
    HANDLE OpenTargetProcess(DWORD processId);

    /**
     * @brief Finds a suitable thread in target process
     * @param processId Target process ID
     * @return Thread ID, or 0 if not found
     */
    DWORD FindTargetThread(DWORD processId);

    /**
     * @brief Hijacks thread execution
     * @param threadId Target thread ID
     * @param entryPoint Address to redirect execution to
     * @return True on success
     */
    bool HijackThread(DWORD threadId, LPVOID entryPoint);

    /**
     * @brief Gets the original thread context (for restoration)
     * @return Original CONTEXT structure
     */
    CONTEXT GetOriginalContext() const { return m_originalContext; }

    /**
     * @brief Gets the hijacked thread handle
     * @return Thread handle
     */
    HANDLE GetThreadHandle() const { return m_threadHandle; }

private:
    /**
     * @brief Suspends target thread
     */
    bool SuspendTargetThread(HANDLE threadHandle);

    /**
     * @brief Captures thread context
     */
    bool CaptureThreadContext(HANDLE threadHandle, CONTEXT& context);

    /**
     * @brief Modifies thread context to redirect execution
     */
    bool ModifyThreadContext(HANDLE threadHandle, const CONTEXT& context);

    /**
     * @brief Resumes target thread
     */
    bool ResumeTargetThread(HANDLE threadHandle);

    HANDLE m_threadHandle;
    CONTEXT m_originalContext;
    bool m_isHijacked;
};

#endif // THREAD_HIJACKER_H
