#ifndef PE_MAPPER_H
#define PE_MAPPER_H

#include <windows.h>
#include <vector>
#include <cstdint>

/**
 * @class PEMapper
 * @brief Manually maps a PE DLL into target process memory
 * 
 * Performs manual PE loading without using LoadLibrary:
 * - Resolves imports (IAT)
 * - Applies relocations
 * - Handles section mapping
 */
class PEMapper {
public:
    PEMapper();
    ~PEMapper();

    /**
     * @brief Maps a DLL into the target process
     * @param dllBuffer Raw DLL bytes
     * @param targetProcess Handle to target process
     * @return Base address where DLL was mapped, or nullptr on failure
     */
    LPVOID MapDLL(const std::vector<uint8_t>& dllBuffer, HANDLE targetProcess);

    /**
     * @brief Gets the entry point address of the mapped DLL
     * @return Address of the DLL entry point
     */
    LPVOID GetEntryPoint() const { return m_entryPoint; }

    /**
     * @brief Gets the base address where DLL was mapped
     * @return Base address of the mapped DLL
     */
    LPVOID GetBaseAddress() const { return m_baseAddress; }

    /**
     * @brief Zeros the mapped memory region (for panic function)
     * @param targetProcess Handle to target process
     */
    void ZeroMemory(HANDLE targetProcess);

private:
    /**
     * @brief Validates PE headers
     */
    bool ValidatePE(const std::vector<uint8_t>& dllBuffer);

    /**
     * @brief Copies sections to target memory
     */
    bool CopySections(const std::vector<uint8_t>& dllBuffer, LPVOID baseAddress, HANDLE targetProcess);

    /**
     * @brief Resolves imports (IAT)
     */
    bool ResolveImports(LPVOID baseAddress, HANDLE targetProcess);

    /**
     * @brief Applies relocations
     */
    bool ApplyRelocations(LPVOID baseAddress, LPVOID preferredBase, HANDLE targetProcess);

    /**
     * @brief Sets memory protections for sections
     */
    bool SetSectionProtections(LPVOID baseAddress, HANDLE targetProcess);

    LPVOID m_baseAddress;
    LPVOID m_entryPoint;
    SIZE_T m_imageSize;
};

#endif // PE_MAPPER_H
