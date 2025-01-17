#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <stdexcept>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

// Define SIO_RCVALL if not already defined
#ifndef SIO_RCVALL
#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)
#endif

// ANSI color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"

// IP header structure
typedef struct ip_hdr {
    unsigned char ip_header_len : 4;
    unsigned char ip_version : 4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    unsigned int ip_srcaddr;
    unsigned int ip_destaddr;
} IPV4_HDR;

// TCP header structure
typedef struct tcp_header {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char ns : 1;
    unsigned char reserved_part1 : 3;
    unsigned char data_offset : 4;
    unsigned char fin : 1;
    unsigned char syn : 1;
    unsigned char rst : 1;
    unsigned char psh : 1;
    unsigned char ack : 1;
    unsigned char urg : 1;
    unsigned char reserved_part2 : 2;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
} TCP_HDR;

class PacketSniffer {
private:
    SOCKET sniffer;
    char* buffer;
    int buffer_size;
    HANDLE console;

public:
    PacketSniffer(int buf_size = 65536) : buffer_size(buf_size) {
        // Enable virtual terminal processing for colors
        console = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;

        // Check if virtual terminal processing can be enabled
        if (GetConsoleMode(console, &mode)) {
            SetConsoleMode(console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }

        buffer = new char[buffer_size];
        initialize();
    }

    ~PacketSniffer() {
        delete[] buffer;
        if (sniffer != INVALID_SOCKET) {
            closesocket(sniffer);
        }
        WSACleanup();
    }

    void initialize() {
        WSADATA wsa;
        std::cout << GREEN << "Initializing Winsock..." << RESET << std::endl;

        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }

        sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (sniffer == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }

        // Get local host name
        char hostname[100];
        gethostname(hostname, sizeof(hostname));

        // Use getaddrinfo instead of gethostbyname
        struct addrinfo hints = {};
        struct addrinfo* res;

        hints.ai_family = AF_INET;  // IPv4
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, nullptr, &hints, &res) != 0) {
            throw std::runtime_error("getaddrinfo failed");
        }

        // Bind socket to local interface
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ((sockaddr_in*)res->ai_addr)->sin_addr.s_addr; // Get first address
        addr.sin_port = 0;

        if (bind(sniffer, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            freeaddrinfo(res);
            throw std::runtime_error("Bind failed");
        }

        freeaddrinfo(res);  // Free the addrinfo when done

        // Enable promiscuous mode
        unsigned long flag = 1;
        if (ioctlsocket(sniffer, SIO_RCVALL, &flag) != 0) {
            throw std::runtime_error("Failed to enable promiscuous mode");
        }
    }

    void start_sniffing() {
        std::cout << YELLOW << "Starting packet capture..." << RESET << std::endl;

        while (true) {
            int packet_size = recvfrom(sniffer, buffer, buffer_size, 0, nullptr, nullptr);

            if (packet_size > 0) {
                process_packet(buffer, packet_size);
            }
        }
    }

private:
    void process_packet(char* buffer, int size) {
        IPV4_HDR* ip_header = (IPV4_HDR*)buffer;

        // Convert IP addresses to strings using inet_ntop
        char src_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        sockaddr_in source, dest;
        source.sin_addr.s_addr = ip_header->ip_srcaddr;
        dest.sin_addr.s_addr = ip_header->ip_destaddr;

        inet_ntop(AF_INET, &source.sin_addr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &dest.sin_addr, dest_ip, sizeof(dest_ip));

        // Get current timestamp
        char time_buffer[26];
        auto now = std::time(nullptr);
        errno_t err = ctime_s(time_buffer, sizeof(time_buffer), &now);
        if (err != 0) {
            strcpy_s(time_buffer, sizeof(time_buffer), "Time Error");
        }
        else {
            time_buffer[strlen(time_buffer) - 1] = 0; // Remove newline
        }

        std::cout << BLUE << "[" << time_buffer << "]" << RESET << std::endl;
        std::cout << MAGENTA << "Protocol: " << (int)ip_header->ip_protocol << RESET << std::endl;
        std::cout << "Source IP: " << src_ip << std::endl;
        std::cout << "Destination IP: " << dest_ip << std::endl;

        // If TCP packet, print port information
        if (ip_header->ip_protocol == IPPROTO_TCP) {
            TCP_HDR* tcp_header = (TCP_HDR*)(buffer + ip_header->ip_header_len * 4);
            std::cout << RED << "Source Port: " << ntohs(tcp_header->source_port) << RESET << std::endl;
            std::cout << RED << "Destination Port: " << ntohs(tcp_header->dest_port) << RESET << std::endl;
        }

        std::cout << GREEN << "Packet Size: " << size << " bytes" << RESET << std::endl;
        std::cout << std::string(50, '-') << std::endl;
    }
};

int main() {
    try {
        PacketSniffer sniffer;
        std::cout << MAGENTA << "Packet Sniffer initialized successfully!" << RESET << std::endl;
        std::cout << YELLOW << "Starting capture (Press Ctrl+C to stop)..." << RESET << std::endl;
        sniffer.start_sniffing();
    }
    catch (const std::exception& e) {
        std::cerr << RED << "Error: " << e.what() << RESET << std::endl;
        return 1;
    }

    return 0;
}