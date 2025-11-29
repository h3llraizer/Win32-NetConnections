#include <iostream>     // cout etc
#include <winsock2.h>   // windown socket libraries
#include <Ws2tcpip.h>   // Windows socket tcp/ip connections
#include <iphlpapi.h> 
#include <windows.h>    // OpenProcess etc

#include "IPLayer.h"  // PcapPlusPlus header for creating IPv4Address objects

#include <vector>  // std::vector
#include <map>     // std::map
#include <format> // std::format (for string formatting)

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

class Snap {
private:
    HANDLE hProcess = nullptr;
    std::vector<char> filePathVec;
    std::string fileNameS;

    // split the full path and return the last element of the string which is the exe's name. \\ is delimeter
    auto split(std::string path)
    {
        std::string cur;
        for (auto& ch : path)
        {
            if (ch == '\\')
            {
                cur.clear();
                continue;
            }
            cur += ch;
        } 
        return cur;
    }

public:
    Snap(DWORD pid)
    {
        filePathVec.resize(MAX_PATH);

        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (!hProcess)
        {
            std::string exception = std::format("Could not open handle for process {}. Error {}", pid, GetLastError());
            throw std::exception(exception.c_str());
        }

        DWORD size = MAX_PATH;

        if (!QueryFullProcessImageNameA(hProcess, 0, filePathVec.data(), &size))
        {
            std::string exception = std::format("Could not QueryFullProcessImageNameA for process {}. Error {}", pid, GetLastError());
            throw std::exception(exception.c_str());
        }

        fileNameS = split(std::string(filePathVec.data()));
    }

    std::string getname()
    {
        return fileNameS;
    }

    ~Snap()
    {
        if (hProcess) CloseHandle(hProcess);
    }

};


class NetTcp {
private:
    using TcpTablePtr = std::unique_ptr<MIB_TCPTABLE_OWNER_PID,decltype(&free)>;
    TcpTablePtr tcpTable{ nullptr, free };

    DWORD size = 0;
    DWORD result = 0;

    auto getState(DWORD state)
    {
        switch (state)
        {
        case MIB_TCP_STATE_CLOSED:
            return "CLOSED";
        case MIB_TCP_STATE_LISTEN:
            return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:
            return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:
            return "SYN_RECV";
        case MIB_TCP_STATE_ESTAB:
            return "ESTAB";
        case MIB_TCP_STATE_FIN_WAIT1:
            return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:
            return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:
            return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:
            return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:
            return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB:
            return "DELETE_TCB";
        case MIB_TCP_STATE_RESERVED:
            return "RESERVED";
        default:
            return "UNKNOWN";
        }

    }

public:
    NetTcp() {
        for (;;) {
            result = GetExtendedTcpTable(tcpTable.get(), &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

            if (result == ERROR_INSUFFICIENT_BUFFER) {
                // resize buffer
                tcpTable.reset(static_cast<MIB_TCPTABLE_OWNER_PID*>(malloc(size)));
                if (!tcpTable) throw std::bad_alloc();
                continue;
            }

            break;
        }

        if (result != NO_ERROR) {
            throw std::runtime_error("GetExtendedTcpTable failed");
        }
    }

    const MIB_TCPTABLE_OWNER_PID* get() const
    {
        return tcpTable.get();
    }
     
    void PrintConnections()
    {

        auto* table = tcpTable.get();

        auto count = (*table).dwNumEntries;

        std::cout << "TCP/IP Connections: " << count << "\n";

        for (DWORD i = 0; i < count; i++) {
            MIB_TCPROW_OWNER_PID& row = (*table).table[i];

            pcpp::IPv4Address localIp(row.dwLocalAddr);
            u_short localPort = ntohs((u_short)row.dwLocalPort);
            pcpp::IPv4Address remoteIp(row.dwRemoteAddr);
            u_short remotePort = ntohs((u_short)row.dwRemotePort);
            auto pid = row.dwOwningPid;
            auto state = row.dwState;

            std::cout << localIp.toString() << ":" << localPort << " " << remoteIp.toString() << ":" << remotePort << " PID: " << pid << " Name: ";

            std::unique_ptr<Snap> processName;
            try {
                processName = std::make_unique<Snap>(pid);
                std::cout << processName->getname() << " ";
            }
            catch (std::exception& e)
            {
                std::cout << e.what();
                std::cout << "(error) ";

            }

            std::cout << getState(state) << "\n";
        }
    }

    ~NetTcp() {}
};

class NetUdp {
private:
    using UdpTablePtr = std::unique_ptr<MIB_UDPTABLE2, decltype(&free)>;
    UdpTablePtr udpTable{ nullptr, free };

    DWORD size = 0;
    DWORD result = 0;

public:
    NetUdp() {
        for (;;) {
            result = GetExtendedUdpTable(udpTable.get(), &size, TRUE,
                AF_INET, UDP_TABLE_OWNER_PID, 0);

            if (result == ERROR_INSUFFICIENT_BUFFER) {
                // resize buffer
                udpTable.reset(static_cast<MIB_UDPTABLE2*>(malloc(size)));
                if (!udpTable) throw std::bad_alloc();
                continue;
            }

            break;
        }

        if (result != NO_ERROR) {
            throw std::runtime_error("GetExtendedTcpTable failed");
        }
    }

    const auto get() const  // return MIB_UDPTABLE2*
    {
        return udpTable.get();
    }

    void PrintConnections()
    {

        auto* table = udpTable.get();

        auto count = (*table).dwNumEntries;

        std::cout << "UDP/IP Connections: " << count << "\n";

        for (DWORD i = 0; i < count; i++) {
            MIB_UDPROW2& row = (*table).table[i];

            pcpp::IPv4Address localIp(ntohs(row.dwLocalAddr));
            u_short localPort = ntohs(row.dwLocalPort);
            pcpp::IPv4Address remoteIp(ntohs(row.dwRemoteAddr));
            u_short remotePort = ntohs(row.dwRemotePort);
            auto pid = row.dwOwningPid;

            std::cout << localIp.toString() << ":" << localPort << " " << remoteIp.toString() << ":" << remotePort << " PID: " << pid << " Name: ";

            std::unique_ptr<Snap> processName;
            try {
                processName = std::make_unique<Snap>(pid);
                std::cout << processName->getname() << " ";
            }
            catch (std::exception& e)
            {
                /*std::cout << e.what();*/
                std::cout << "(error) ";

            }

            std::cout << "\n";
        }
    }

    auto GetConnectionMap()
    {

        auto* table = udpTable.get();

        auto count = (*table).dwNumEntries;

        std::vector<std::pair<std::pair<DWORD, std::string>, std::pair<pcpp::IPv4Address, u_short>>> connectionMap;

        for (DWORD i = 0; i < count; i++)
        {
            auto& row = (*table).table[i];

            pcpp::IPv4Address localIp(row.dwLocalAddr);
            auto localPort = ntohs((u_short)row.dwLocalPort);
            auto pid = row.dwOwningPid;

            std::unique_ptr<Snap> snap;
            std::string processName;
            try {
                snap = std::make_unique<Snap>(pid);
                processName = snap->getname();
            }
            catch (std::exception& e)
            {
                processName = "(error)";

            }

            std::pair<std::pair<DWORD, std::string>, std::pair<pcpp::IPv4Address, u_short>> connection = { {pid, processName}, { localIp, localPort } };

            connectionMap.push_back(connection);
        }

        return connectionMap;

    }

    ~NetUdp() {}
};

int main()
{
    auto tcp = std::make_unique<NetTcp>();

    tcp->PrintConnections();

    auto udp = std::make_unique<NetUdp>();

    udp->PrintConnections();

    return 0;

}