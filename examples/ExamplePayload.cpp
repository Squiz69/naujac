#include <windows.h>
#include <iostream>
#include <fstream>

/**
 * Example Payload DLL
 * 
 * This is a simple example DLL that can be injected using the 
 * Fileless Reflective DLL Loader. It demonstrates basic DLL functionality.
 * 
 * WARNING: This is for educational purposes only!
 */

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Code to run when DLL is loaded
            {
                // Get system temp directory
                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                std::string logFilePath = std::string(tempPath) + "injection_proof.txt";
                
                // Create a simple log file to prove injection worked
                std::ofstream logFile(logFilePath, std::ios::app);
                if (logFile.is_open()) {
                    logFile << "[+] DLL Successfully Injected!" << std::endl;
                    logFile << "[+] Process ID: " << GetCurrentProcessId() << std::endl;
                    logFile << "[+] Thread ID: " << GetCurrentThreadId() << std::endl;
                    logFile << "[+] Module Base: 0x" << std::hex << hModule << std::dec << std::endl;
                    logFile.close();
                }
                
                // Display a message box (for demonstration)
                // Note: In real malware, you wouldn't want to show visible indicators
                MessageBoxA(NULL, 
                    "Payload DLL loaded successfully!\n\nThis is a demonstration of thread hijacking injection.",
                    "Injection Success",
                    MB_OK | MB_ICONINFORMATION);
            }
            break;
            
        case DLL_THREAD_ATTACH:
            // Code to run when a new thread is created
            break;
            
        case DLL_THREAD_DETACH:
            // Code to run when a thread exits
            break;
            
        case DLL_PROCESS_DETACH:
            // Code to run when DLL is unloaded
            {
                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                std::string logFilePath = std::string(tempPath) + "injection_proof.txt";
                
                std::ofstream logFile(logFilePath, std::ios::app);
                if (logFile.is_open()) {
                    logFile << "[+] DLL Detached/Unloaded" << std::endl;
                    logFile.close();
                }
            }
            break;
    }
    return TRUE;
}

// Exported function (optional)
extern "C" __declspec(dllexport) void PayloadFunction() {
    MessageBoxA(NULL, 
        "This is an exported function from the injected DLL!",
        "Payload Function",
        MB_OK);
}
