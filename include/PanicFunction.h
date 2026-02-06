#ifndef PANIC_FUNCTION_H
#define PANIC_FUNCTION_H

#include <windows.h>
#include "ThreadHijacker.h"
#include "PEMapper.h"

/**
 * @class PanicFunction
 * @brief Implements self-erasure and cleanup functionality
 * 
 * Restores hijacked thread, zeros allocated memory, and clears operation traces.
 */
class PanicFunction {
public:
    PanicFunction();
    ~PanicFunction();

    /**
     * @brief Executes panic/self-erasure sequence
     * @param hijacker Thread hijacker instance
     * @param mapper PE mapper instance
     * @param targetProcess Handle to target process
     * @return True on success
     */
    bool Execute(ThreadHijacker& hijacker, PEMapper& mapper, HANDLE targetProcess);

private:
    /**
     * @brief Restores original thread context
     */
    bool RestoreThreadContext(ThreadHijacker& hijacker);

    /**
     * @brief Zeros allocated memory using SecureZeroMemory
     */
    bool ZeroAllocatedMemory(PEMapper& mapper, HANDLE targetProcess);

    /**
     * @brief Clears operation traces
     */
    bool ClearTraces();

    /**
     * @brief Frees allocated memory in target process
     */
    bool FreeRemoteMemory(HANDLE targetProcess, LPVOID baseAddress);
};

#endif // PANIC_FUNCTION_H
