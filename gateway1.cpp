#include <iostream>
#include <string>
#include <ws2tcpip.h> // Include for network definitions

#ifdef _WIN32 // Windows platform

#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h> // Necessary for inet_ntoa on Windows

// Link with required libraries
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib") // Ensure linking with Ws2_32.lib

std::string getLocalGatewayIP() {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return "";
    }

    MIB_IPFORWARDROW row;
    if (GetBestRoute(0, 0, &row) == NO_ERROR) {
        in_addr gatewayAddr;
        gatewayAddr.S_un.S_addr = row.dwForwardNextHop;
        std::string ip = inet_ntoa(gatewayAddr);

        // Cleanup Winsock
        WSACleanup();

        return ip;
    }

    // Cleanup Winsock
    WSACleanup();
    return "";
}

#elif __linux__ // Linux platform

#include <fstream>
#include <sstream>
#include <arpa/inet.h>

std::string getLocalGatewayIP() {
    std::ifstream routeFile("/proc/net/route");
    std::string line;

    while (std::getline(routeFile, line)) {
        std::istringstream iss(line);
        std::string iface, dest, gateway;
        int flags;

        if (!(iss >> iface >> dest >> gateway >> flags)) {
            continue;
        }

        if (flags == 3) { // Default route, equivalent to UG flags
            uint32_t gatewayAddr;
            std::stringstream(gateway) >> std::hex >> gatewayAddr;
            struct in_addr addr;
            addr.s_addr = gatewayAddr;
            return inet_ntoa(addr);
        }
    }

    return "";
}

#elif __APPLE__ // macOS platform

#include <sys/sysctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>

std::string getLocalGatewayIP() {
    // Management Information Base
    int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY};
    size_t len = 0;
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        return "";
    }
    char* buf = new char[len];

    // Retrieve the routing information into the buffer
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        delete[] buf;
        return "";
    }

    char* next = buf;
    struct rt_msghdr* rtmsg;
    while (next < buf + len) {
        // Extract the routing message header
        rtmsg = reinterpret_cast<struct rt_msghdr*>(next);
        struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(rtmsg + 1);

        // Check if the route has the gateway flag and includes the gateway address
        if ((rtmsg->rtm_flags & RTF_GATEWAY) && (rtmsg->rtm_addrs & RTA_GATEWAY)) {
            // Convert the gateway address to string
            char gatewayIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(sin->sin_addr), gatewayIP, INET_ADDRSTRLEN);

            delete[] buf;
            return std::string(gatewayIP);
        }

        next += rtmsg->rtm_msglen;
    }

    delete[] buf;
    return "";
}

#else
#error "Unsupported platform"
#endif

int main() {
    std::string gatewayIP = getLocalGatewayIP();
    
    if (!gatewayIP.empty()) {
        std::cout << "Local Network Gateway IP: " << gatewayIP << std::endl;
    } else {
        std::cerr << "Failed to retrieve Local Network Gateway IP." << std::endl;
    }

    return 0;
}
