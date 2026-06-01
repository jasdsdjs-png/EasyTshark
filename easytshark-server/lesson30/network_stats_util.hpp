//
// Created by Codex on 2026/6/1.
//

#ifndef NETWORK_STATS_UTIL_HPP
#define NETWORK_STATS_UTIL_HPP

#include <cstdlib>
#include <map>
#include <string>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

struct NetworkCounters {
    unsigned long long ibytes = 0;
    unsigned long long obytes = 0;
};

class NetworkStatsUtil {
public:
    static std::map<std::string, NetworkCounters> getSnapshot() {
        std::map<std::string, NetworkCounters> result;

#ifdef _WIN32
        ULONG tableSize = 0;
        if (GetIfTable(nullptr, &tableSize, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
            return result;
        }

        PMIB_IFTABLE table = reinterpret_cast<PMIB_IFTABLE>(std::malloc(tableSize));
        if (table == nullptr) {
            return result;
        }

        if (GetIfTable(table, &tableSize, FALSE) != NO_ERROR) {
            std::free(table);
            return result;
        }

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_IFROW& row = table->table[i];
            if (row.dwOperStatus != IF_OPER_STATUS_OPERATIONAL) {
                continue;
            }
            if (row.dwType == IF_TYPE_SOFTWARE_LOOPBACK) {
                continue;
            }

            std::string name(
                reinterpret_cast<const char*>(row.bDescr),
                reinterpret_cast<const char*>(row.bDescr) + row.dwDescrLen
            );
            while (!name.empty() && name.back() == '\0') {
                name.pop_back();
            }
            if (name.empty()) {
                continue;
            }

            result[name] = NetworkCounters{
                static_cast<unsigned long long>(row.dwInOctets),
                static_cast<unsigned long long>(row.dwOutOctets)
            };
        }

        std::free(table);
#else
        struct ifaddrs* ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == -1 || ifaddr == nullptr) {
            return result;
        }

        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_name == nullptr) {
                continue;
            }
            if ((ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_LOOPBACK) != 0) {
                continue;
            }
            result[ifa->ifa_name];
        }

        freeifaddrs(ifaddr);
#endif

        return result;
    }

    static std::map<std::string, NetworkCounters> calculateDelta(
        const std::map<std::string, NetworkCounters>& before,
        const std::map<std::string, NetworkCounters>& after,
        unsigned int seconds
    ) {
        std::map<std::string, NetworkCounters> result;
        if (seconds == 0) {
            return result;
        }

        for (const auto& adapterCounterPair : after) {
            const std::string& adapterName = adapterCounterPair.first;
            const NetworkCounters& current = adapterCounterPair.second;
            auto previousIt = before.find(adapterName);
            if (previousIt == before.end()) {
                continue;
            }

            const NetworkCounters& previous = previousIt->second;
            if (current.ibytes < previous.ibytes || current.obytes < previous.obytes) {
                continue;
            }

            result[adapterName] = NetworkCounters{
                (current.ibytes - previous.ibytes) / seconds,
                (current.obytes - previous.obytes) / seconds
            };
        }

        return result;
    }

private:
#ifdef _WIN32
    static std::string wideToUtf8(const wchar_t* value) {
        if (value == nullptr || value[0] == L'\0') {
            return "";
        }

        int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 1) {
            return "";
        }

        std::string result(static_cast<size_t>(size - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value, -1, &result[0], size, nullptr, nullptr);
        return result;
    }
#endif
};

#endif // NETWORK_STATS_UTIL_HPP
