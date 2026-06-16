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

            std::string description(
                reinterpret_cast<const char*>(row.bDescr),
                reinterpret_cast<const char*>(row.bDescr) + row.dwDescrLen
            );
            while (!description.empty() && description.back() == '\0') {
                description.pop_back();
            }

            std::string name = normalizeWindowsAdapterAlias(getInterfaceAlias(row.dwIndex));
            if (name.empty()) {
                name = description;
            }
            if (name.empty()) {
                continue;
            }

            NetworkCounters& counters = result[name];
            counters.ibytes += static_cast<unsigned long long>(row.dwInOctets);
            counters.obytes += static_cast<unsigned long long>(row.dwOutOctets);
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
    static std::string normalizeWindowsAdapterAlias(const std::string& value) {
        const char* filterSuffixes[] = {
            "-Npcap Packet Driver",
            "-QoS Packet Scheduler",
            "-Native WiFi Filter Driver",
            "-Virtual WiFi Filter Driver",
            "-WFP 802.3 MAC Layer LightWeight Filter",
            "-WFP Native MAC Layer LightWeight Filter",
            "-Huorong NDIS Filter Driver"
        };

        for (const char* suffix : filterSuffixes) {
            size_t pos = value.find(suffix);
            if (pos != std::string::npos) {
                return value.substr(0, pos);
            }
        }

        return value;
    }

    static std::string getInterfaceAlias(DWORD ifIndex) {
        NET_LUID luid;
        if (ConvertInterfaceIndexToLuid(ifIndex, &luid) != NO_ERROR) {
            return "";
        }

        wchar_t alias[IF_MAX_STRING_SIZE + 1] = { 0 };
        if (ConvertInterfaceLuidToAlias(&luid, alias, IF_MAX_STRING_SIZE + 1) != NO_ERROR) {
            return "";
        }

        return wideToUtf8(alias);
    }

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
