#ifndef NETWORK_STREAM_H
#define NETWORK_STREAM_H

#include <windows.h>
#include <vector>
#include <cstdint>

/**
 * @class NetworkStream
 * @brief Handles fetching raw DLL binary from remote memory buffer
 * 
 * Simulates fetching a DLL over an SSL socket without writing to disk.
 * In production, this would connect to a remote server.
 */
class NetworkStream {
public:
    NetworkStream();
    ~NetworkStream();

    /**
     * @brief Simulates fetching a DLL from a remote buffer
     * @param filePath Path to local DLL file (for simulation purposes)
     * @return Vector containing the raw DLL bytes
     */
    std::vector<uint8_t> FetchDLL(const char* filePath);

    /**
     * @brief Fetches DLL from actual network source
     * @param host Remote host address
     * @param port Remote port
     * @param resource Resource path on remote server
     * @return Vector containing the raw DLL bytes
     */
    std::vector<uint8_t> FetchDLLFromNetwork(const char* host, int port, const char* resource);

private:
    bool InitializeWinsock();
    void CleanupWinsock();
    
    bool m_winsockInitialized;
};

#endif // NETWORK_STREAM_H
