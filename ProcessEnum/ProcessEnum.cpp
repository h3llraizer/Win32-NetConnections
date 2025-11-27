
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include "IPLayer.h"

#include <stdio.h>
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <ProcessSnapshot.h>
#include <Psapi.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include <vector>
#include <locale>
#include <map>
#include <codecvt>

#include <format>

std::string to_utf8(const std::wstring& w)
{
    if (w.empty()) return {};

    int size = WideCharToMultiByte(CP_UTF8, 0,
        w.c_str(), (int)w.size(),
        nullptr, 0, nullptr, nullptr);

    std::string result(size, 0);

    WideCharToMultiByte(CP_UTF8, 0,
        w.c_str(), (int)w.size(),
        result.data(), size,
        nullptr, nullptr);

    return result;
}

class Snap {
private:
    HANDLE hProcess = nullptr;
    std::vector<char> filePathVec;
    std::string fileNameS;
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

        auto split = [](std::string path) {
            
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
        };

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

public:
    NetTcp() {
        for (;;) {
            result = GetExtendedTcpTable(tcpTable.get(), &size, TRUE,
                AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

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
                /*std::cout << e.what();*/
                std::cout << "(error)";

            }

            std::cout << " State: " << state << "\n";
        }
    }

    ~NetTcp() {}
};

class NetUdp {
private:
    using UdpTablePtr = std::unique_ptr<MIB_UDPTABLE_OWNER_PID, decltype(&free)>;
    UdpTablePtr udpTable{ nullptr, free };

    DWORD size = 0;
    DWORD result = 0;

public:
    NetUdp()
    {
        for (;;) {
            result = GetExtendedUdpTable(udpTable.get(), &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);

            if (result == ERROR_INSUFFICIENT_BUFFER) {
                // resize buffer
                udpTable.reset(static_cast<MIB_UDPTABLE_OWNER_PID*>(malloc(size)));
                if (!udpTable) throw std::bad_alloc();
                continue;
            }

            break;
        }

        if (result != NO_ERROR) {
            throw std::runtime_error("GetExtendedTcpTable failed");
        }
    }

    const MIB_UDPTABLE_OWNER_PID* get() const
    {
        return udpTable.get();
    }

    void PrintConnections()
    {

        auto* table = udpTable.get();

        auto count = (*table).dwNumEntries;

        std::pair<DWORD, std::pair<pcpp::IPv4Address, std::string>> connectionMap;


        std::cout << "UDP/IP Connections: " << count << "\n";

        for (DWORD i = 0; i < count; i++) {
            MIB_UDPROW_OWNER_PID& row = (*table).table[i];

            pcpp::IPv4Address localIp(row.dwLocalAddr);
            u_short localPort = ntohs((u_short)row.dwLocalPort);
            auto pid = row.dwOwningPid;

            std::cout << localIp.toString() << ":" << localPort << " " << " PID: " << pid << " Name: ";

            std::unique_ptr<Snap> processName;
            try {
                processName = std::make_unique<Snap>(pid);
                std::cout << processName->getname() << " ";
            }
            catch (std::exception& e)
            {
                /*std::cout << e.what();*/
                std::cout << "(error)";

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
            MIB_UDPROW_OWNER_PID& row = (*table).table[i];

            pcpp::IPv4Address localIp(row.dwLocalAddr);
            auto localPort = ntohs((u_short)row.dwLocalPort);
            auto pid = row.dwOwningPid;

            //std::cout << localIp.toString() << ":" << localPort << " " << " PID: " << pid << " Name: ";

            std::unique_ptr<Snap> snap;
            std::string processName;
            try {
                snap = std::make_unique<Snap>(pid);
                processName = snap->getname();
            }
            catch (std::exception& e)
            {
                /*std::cout << e.what();*/ // log this to file
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

    while (true) {

        tcp->PrintConnections();

        Sleep(3000);
    }

    return 0;

}