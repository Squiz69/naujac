#include "PEMapper.h"
#include <iostream>
#include <tlhelp32.h>

PEMapper::PEMapper() 
    : m_baseAddress(nullptr), m_entryPoint(nullptr), m_imageSize(0) {
}

PEMapper::~PEMapper() {
}

bool PEMapper::ValidatePE(const std::vector<uint8_t>& dllBuffer) {
    if (dllBuffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "[!] Buffer too small for DOS header" << std::endl;
        return false;
    }
    
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllBuffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] Invalid DOS signature" << std::endl;
        return false;
    }
    
    if (dllBuffer.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        std::cerr << "[!] Buffer too small for NT headers" << std::endl;
        return false;
    }
    
    auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        dllBuffer.data() + dosHeader->e_lfanew);
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] Invalid NT signature" << std::endl;
        return false;
    }
    
    std::cout << "[+] PE validation passed" << std::endl;
    return true;
}

LPVOID PEMapper::MapDLL(const std::vector<uint8_t>& dllBuffer, HANDLE targetProcess) {
    if (!ValidatePE(dllBuffer)) {
        return nullptr;
    }
    
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllBuffer.data());
    auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        dllBuffer.data() + dosHeader->e_lfanew);
    
    m_imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    LPVOID preferredBase = reinterpret_cast<LPVOID>(ntHeaders->OptionalHeader.ImageBase);
    
    // Allocate memory in target process
    m_baseAddress = VirtualAllocEx(
        targetProcess,
        nullptr,
        m_imageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!m_baseAddress) {
        std::cerr << "[!] VirtualAllocEx failed: " << GetLastError() << std::endl;
        return nullptr;
    }
    
    std::cout << "[+] Allocated memory at: 0x" << std::hex << m_baseAddress << std::dec << std::endl;
    
    // Copy headers
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(
        targetProcess,
        m_baseAddress,
        dllBuffer.data(),
        ntHeaders->OptionalHeader.SizeOfHeaders,
        &bytesWritten)) {
        std::cerr << "[!] Failed to write headers: " << GetLastError() << std::endl;
        VirtualFreeEx(targetProcess, m_baseAddress, 0, MEM_RELEASE);
        return nullptr;
    }
    
    // Copy sections
    if (!CopySections(dllBuffer, m_baseAddress, targetProcess)) {
        VirtualFreeEx(targetProcess, m_baseAddress, 0, MEM_RELEASE);
        return nullptr;
    }
    
    // Apply relocations
    if (!ApplyRelocations(m_baseAddress, preferredBase, targetProcess)) {
        std::cerr << "[!] Warning: Relocations failed, DLL may not work correctly" << std::endl;
    }
    
    // Resolve imports
    if (!ResolveImports(m_baseAddress, targetProcess)) {
        VirtualFreeEx(targetProcess, m_baseAddress, 0, MEM_RELEASE);
        return nullptr;
    }
    
    // Calculate entry point
    m_entryPoint = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(m_baseAddress) + 
        ntHeaders->OptionalHeader.AddressOfEntryPoint
    );
    
    std::cout << "[+] Entry point: 0x" << std::hex << m_entryPoint << std::dec << std::endl;
    
    return m_baseAddress;
}

bool PEMapper::CopySections(const std::vector<uint8_t>& dllBuffer, LPVOID baseAddress, HANDLE targetProcess) {
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllBuffer.data());
    auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        dllBuffer.data() + dosHeader->e_lfanew);
    
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData == 0) continue;
        
        LPVOID sectionDest = reinterpret_cast<LPVOID>(
            reinterpret_cast<uintptr_t>(baseAddress) + sectionHeader[i].VirtualAddress
        );
        
        const void* sectionSrc = dllBuffer.data() + sectionHeader[i].PointerToRawData;
        
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(
            targetProcess,
            sectionDest,
            sectionSrc,
            sectionHeader[i].SizeOfRawData,
            &bytesWritten)) {
            std::cerr << "[!] Failed to write section: " << sectionHeader[i].Name << std::endl;
            return false;
        }
        
        std::cout << "[+] Copied section: " << sectionHeader[i].Name << std::endl;
    }
    
    return true;
}

bool PEMapper::ResolveImports(LPVOID baseAddress, HANDLE targetProcess) {
    // Read NT headers from target process
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    SIZE_T bytesRead;
    
    if (!ReadProcessMemory(targetProcess, baseAddress, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        return false;
    }
    
    LPVOID ntHeaderAddr = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(baseAddress) + dosHeader.e_lfanew
    );
    
    if (!ReadProcessMemory(targetProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        return false;
    }
    
    DWORD importDescriptorRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDescriptorRVA == 0) {
        std::cout << "[+] No imports to resolve" << std::endl;
        return true;
    }
    
    LPVOID importDescriptorAddr = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(baseAddress) + importDescriptorRVA
    );
    
    IMAGE_IMPORT_DESCRIPTOR importDescriptor;
    size_t descriptorIndex = 0;
    
    while (true) {
        LPVOID currentDescAddr = reinterpret_cast<LPVOID>(
            reinterpret_cast<uintptr_t>(importDescriptorAddr) + 
            (descriptorIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR))
        );
        
        if (!ReadProcessMemory(targetProcess, currentDescAddr, &importDescriptor, 
            sizeof(importDescriptor), &bytesRead)) {
            break;
        }
        
        if (importDescriptor.Name == 0) break;
        
        // Read DLL name
        char dllName[256];
        LPVOID dllNameAddr = reinterpret_cast<LPVOID>(
            reinterpret_cast<uintptr_t>(baseAddress) + importDescriptor.Name
        );
        
        if (!ReadProcessMemory(targetProcess, dllNameAddr, dllName, sizeof(dllName), &bytesRead)) {
            descriptorIndex++;
            continue;
        }
        
        // Load the DLL in our process to resolve addresses
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) {
            std::cerr << "[!] Failed to load import DLL: " << dllName << std::endl;
            descriptorIndex++;
            continue;
        }
        
        std::cout << "[+] Resolving imports from: " << dllName << std::endl;
        
        // Resolve thunks
        DWORD thunkRVA = importDescriptor.OriginalFirstThunk;
        if (thunkRVA == 0) {
            thunkRVA = importDescriptor.FirstThunk;
        }
        
        LPVOID thunkAddr = reinterpret_cast<LPVOID>(
            reinterpret_cast<uintptr_t>(baseAddress) + thunkRVA
        );
        
        LPVOID iatAddr = reinterpret_cast<LPVOID>(
            reinterpret_cast<uintptr_t>(baseAddress) + importDescriptor.FirstThunk
        );
        
        size_t thunkIndex = 0;
        while (true) {
            IMAGE_THUNK_DATA thunkData;
            LPVOID currentThunkAddr = reinterpret_cast<LPVOID>(
                reinterpret_cast<uintptr_t>(thunkAddr) + (thunkIndex * sizeof(IMAGE_THUNK_DATA))
            );
            
            if (!ReadProcessMemory(targetProcess, currentThunkAddr, &thunkData, 
                sizeof(thunkData), &bytesRead)) {
                break;
            }
            
            if (thunkData.u1.AddressOfData == 0) break;
            
            FARPROC functionAddr = nullptr;
            
            if (IMAGE_SNAP_BY_ORDINAL(thunkData.u1.Ordinal)) {
                // Import by ordinal
                functionAddr = GetProcAddress(hModule, 
                    reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(thunkData.u1.Ordinal)));
            } else {
                // Import by name
                IMAGE_IMPORT_BY_NAME importByName;
                LPVOID importByNameAddr = reinterpret_cast<LPVOID>(
                    reinterpret_cast<uintptr_t>(baseAddress) + thunkData.u1.AddressOfData
                );
                
                if (ReadProcessMemory(targetProcess, importByNameAddr, &importByName, 
                    sizeof(importByName), &bytesRead)) {
                    functionAddr = GetProcAddress(hModule, importByName.Name);
                }
            }
            
            if (functionAddr) {
                LPVOID currentIATAddr = reinterpret_cast<LPVOID>(
                    reinterpret_cast<uintptr_t>(iatAddr) + (thunkIndex * sizeof(LPVOID))
                );
                
                SIZE_T bytesWritten;
                WriteProcessMemory(targetProcess, currentIATAddr, &functionAddr, 
                    sizeof(functionAddr), &bytesWritten);
            }
            
            thunkIndex++;
        }
        
        descriptorIndex++;
    }
    
    std::cout << "[+] Import resolution complete" << std::endl;
    return true;
}

bool PEMapper::ApplyRelocations(LPVOID baseAddress, LPVOID preferredBase, HANDLE targetProcess) {
    ptrdiff_t delta = reinterpret_cast<uintptr_t>(baseAddress) - 
                     reinterpret_cast<uintptr_t>(preferredBase);
    
    if (delta == 0) {
        std::cout << "[+] No relocations needed (loaded at preferred base)" << std::endl;
        return true;
    }
    
    // Read NT headers
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    SIZE_T bytesRead;
    
    if (!ReadProcessMemory(targetProcess, baseAddress, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        return false;
    }
    
    LPVOID ntHeaderAddr = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(baseAddress) + dosHeader.e_lfanew
    );
    
    if (!ReadProcessMemory(targetProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        return false;
    }
    
    DWORD relocationRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocationSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    
    if (relocationRVA == 0 || relocationSize == 0) {
        std::cout << "[!] No relocation data found" << std::endl;
        return false;
    }
    
    std::cout << "[+] Applying relocations (delta: 0x" << std::hex << delta << std::dec << ")" << std::endl;
    
    LPVOID relocationAddr = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(baseAddress) + relocationRVA
    );
    
    size_t processed = 0;
    while (processed < relocationSize) {
        IMAGE_BASE_RELOCATION relocationBlock;
        LPVOID currentBlockAddr = reinterpret_cast<LPVOID>(
            reinterpret_cast<uintptr_t>(relocationAddr) + processed
        );
        
        if (!ReadProcessMemory(targetProcess, currentBlockAddr, &relocationBlock, 
            sizeof(relocationBlock), &bytesRead)) {
            break;
        }
        
        if (relocationBlock.SizeOfBlock == 0) break;
        
        size_t numEntries = (relocationBlock.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        
        for (size_t i = 0; i < numEntries; i++) {
            WORD entry;
            LPVOID entryAddr = reinterpret_cast<LPVOID>(
                reinterpret_cast<uintptr_t>(currentBlockAddr) + sizeof(IMAGE_BASE_RELOCATION) + (i * sizeof(WORD))
            );
            
            if (!ReadProcessMemory(targetProcess, entryAddr, &entry, sizeof(entry), &bytesRead)) {
                continue;
            }
            
            WORD type = entry >> 12;
            WORD offset = entry & 0xFFF;
            
            if (type == IMAGE_REL_BASED_DIR64) {
                LPVOID patchAddr = reinterpret_cast<LPVOID>(
                    reinterpret_cast<uintptr_t>(baseAddress) + relocationBlock.VirtualAddress + offset
                );
                
                uintptr_t originalValue;
                if (ReadProcessMemory(targetProcess, patchAddr, &originalValue, 
                    sizeof(originalValue), &bytesRead)) {
                    uintptr_t newValue = originalValue + delta;
                    SIZE_T bytesWritten;
                    WriteProcessMemory(targetProcess, patchAddr, &newValue, 
                        sizeof(newValue), &bytesWritten);
                }
            }
        }
        
        processed += relocationBlock.SizeOfBlock;
    }
    
    std::cout << "[+] Relocations applied" << std::endl;
    return true;
}

bool PEMapper::SetSectionProtections(LPVOID baseAddress, HANDLE targetProcess) {
    // This would set proper memory protections for each section
    // For simplicity, we've used PAGE_EXECUTE_READWRITE during allocation
    // In production, you'd want to set proper protections per section
    return true;
}

void PEMapper::ZeroMemory(HANDLE targetProcess) {
    if (!m_baseAddress || m_imageSize == 0) {
        return;
    }
    
    // Allocate local buffer filled with zeros
    std::vector<uint8_t> zeroBuffer(m_imageSize, 0);
    
    // Use SecureZeroMemory equivalent
    SecureZeroMemory(zeroBuffer.data(), zeroBuffer.size());
    
    SIZE_T bytesWritten;
    WriteProcessMemory(targetProcess, m_baseAddress, zeroBuffer.data(), 
        zeroBuffer.size(), &bytesWritten);
    
    std::cout << "[+] Memory region zeroed: " << bytesWritten << " bytes" << std::endl;
}
