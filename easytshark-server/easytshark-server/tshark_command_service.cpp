#include "tshark_command_service.h"

#include "misc_util.hpp"
#include "packet_parser.h"
#include "third_library/loguru/loguru.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#endif

#define EASYTSHARK_FCLOSE fclose

namespace {
#ifdef _WIN32
std::string wideToUtf8(const wchar_t* value) {
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

std::string getInterfaceAlias(DWORD ifIndex) {
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

std::string normalizeWindowsAdapterAlias(const std::string& value) {
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

std::string resolveWindowsInterfaceDescription(const std::string& adapterName) {
    ULONG tableSize = 0;
    if (GetIfTable(nullptr, &tableSize, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        return "";
    }

    PMIB_IFTABLE table = reinterpret_cast<PMIB_IFTABLE>(std::malloc(tableSize));
    if (table == nullptr) {
        return "";
    }

    std::string alias;
    if (GetIfTable(table, &tableSize, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_IFROW& row = table->table[i];
            std::string description(
                reinterpret_cast<const char*>(row.bDescr),
                reinterpret_cast<const char*>(row.bDescr) + row.dwDescrLen
            );
            while (!description.empty() && description.back() == '\0') {
                description.pop_back();
            }

            if (description == adapterName) {
                alias = normalizeWindowsAdapterAlias(getInterfaceAlias(row.dwIndex));
                break;
            }
        }
    }

    std::free(table);
    return alias;
}
#endif
}

TsharkCommandService::TsharkCommandService(const std::string& workDir) {
    tsharkExePath = workDir + "/tshark/bin/tshark.exe";
    editcapExePath = workDir + "/tshark/bin/editcap.exe";
}

const std::string& TsharkCommandService::tsharkPath() const {
    return tsharkExePath;
}

const std::string& TsharkCommandService::editcapPath() const {
    return editcapExePath;
}

FILE* TsharkCommandService::openAnalysisPipe(const std::string& pcapPath, PID_T* pidOut) {
    std::vector<std::string> args = { tsharkExePath, "-r", pcapPath };
    auto fields = PacketParser::getTsharkFieldArgs();
    args.insert(args.end(), fields.begin(), fields.end());
    return ProcessUtil::PopenEx(buildCommand(args), pidOut);
}

FILE* TsharkCommandService::openCapturePipe(const std::string& adapterName, const std::string& outputPath, PID_T* pidOut) {
    std::string captureInterface = resolveCaptureInterface(adapterName);
    std::vector<std::string> args = {
        tsharkExePath,
        "-i", captureInterface,
        "-w", outputPath,
        "-F", "pcap",
        "-l",
        "-P"
    };
    auto fields = PacketParser::getTsharkFieldArgs();
    args.insert(args.end(), fields.begin(), fields.end());
    return ProcessUtil::PopenEx(buildCommand(args), pidOut);
}

bool TsharkCommandService::convertToPcap(const std::string& inputFile, const std::string& outputFile) {
    std::string command = buildCommand({ editcapExePath, "-F", "pcap", inputFile, outputFile });
    if (!ProcessUtil::Exec(command)) {
        LOG_F(ERROR, "Failed to convert to pcap format, command: %s", command.c_str());
        return false;
    }

    if (!MiscUtil::fileExists(outputFile)) {
        LOG_F(ERROR, "editcap reported success but output file is missing: %s", outputFile.c_str());
        return false;
    }

    LOG_F(INFO, "Successfully converted %s to %s in pcap format", inputFile.c_str(), outputFile.c_str());
    return true;
}

std::vector<AdapterInfo> TsharkCommandService::getNetworkAdapters() {
    std::set<std::string> specialInterfaces = { "sshdump", "ciscodump", "udpdump", "randpkt" };
    std::vector<AdapterInfo> interfaces;
    char buffer[256] = { 0 };
    std::string result;

    std::string cmd = tsharkExePath + " -D";
    std::unique_ptr<FILE, decltype(&EASYTSHARK_FCLOSE)> pipe(ProcessUtil::PopenEx(cmd), EASYTSHARK_FCLOSE);
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    while (fgets(buffer, 256, pipe.get()) != nullptr) {
        result += buffer;
    }

    std::istringstream stream(result);
    std::string line;
    int index = 1;
    while (std::getline(stream, line)) {
        int startPos = static_cast<int>(line.find(' '));
        if (startPos == std::string::npos) {
            continue;
        }

        int endPos = static_cast<int>(line.find(' ', startPos + 1));
        std::string interfaceName;
        if (endPos != std::string::npos) {
            interfaceName = line.substr(startPos + 1, endPos - startPos - 1);
        }
        else {
            interfaceName = line.substr(startPos + 1);
        }

        if (specialInterfaces.find(interfaceName) != specialInterfaces.end()) {
            continue;
        }

        AdapterInfo adapterInfo;
        adapterInfo.name = interfaceName;
        adapterInfo.id = index++;
        if (line.find("(") != std::string::npos && line.find(")") != std::string::npos) {
            adapterInfo.remark = line.substr(line.find("(") + 1, line.find(")") - line.find("(") - 1);
        }

#ifdef _WIN32
        if (!adapterInfo.remark.empty()) {
            adapterInfo.name = adapterInfo.remark;
        }
#endif
        interfaces.push_back(adapterInfo);
    }

    return interfaces;
}

bool TsharkCommandService::getPacketDetailInfo(
    const std::string& currentFilePath,
    uint32_t frameNumber,
    TsharkTranslator& translator,
    const std::function<bool(uint32_t, std::vector<unsigned char>&)>& readPacketHex,
    rapidjson::Document& detailJson) {

    std::string tmpFilePath = MiscUtil::getDefaultDataDir() + MiscUtil::getRandomString(10) + ".pcap";
    std::string splitCmd = buildCommand({
        editcapExePath,
        "-r",
        currentFilePath,
        tmpFilePath,
        std::to_string(frameNumber) + "-" + std::to_string(frameNumber)
    });
    if (!ProcessUtil::Exec(splitCmd)) {
        LOG_F(ERROR, "Error in executing command: %s", splitCmd.c_str());
        remove(tmpFilePath.c_str());
        return false;
    }

    std::string cmd = buildCommand({ tsharkExePath, "-r", tmpFilePath, "-T", "pdml" });
    std::unique_ptr<FILE, decltype(&EASYTSHARK_FCLOSE)> pipe(ProcessUtil::PopenEx(cmd), EASYTSHARK_FCLOSE);
    if (!pipe) {
        std::cout << "Failed to run tshark command." << std::endl;
        remove(tmpFilePath.c_str());
        return false;
    }

    char buffer[8192] = { 0 };
    std::string tsharkResult;
    setvbuf(pipe.get(), NULL, _IOFBF, sizeof(buffer));
    while (fgets(buffer, sizeof(buffer) - 1, pipe.get()) != nullptr) {
        tsharkResult += buffer;
        memset(buffer, 0, sizeof(buffer));
    }

    remove(tmpFilePath.c_str());

    if (!MiscUtil::xml2JSON(tsharkResult, detailJson)) {
        LOG_F(ERROR, "XML to JSON failed");
        return false;
    }

    translator.translateShowNameFields(detailJson["pdml"]["packet"][0]["proto"], detailJson.GetAllocator());

    if (detailJson.HasMember("pdml") && detailJson["pdml"].HasMember("packet")) {
        std::string packetHex;
        std::vector<unsigned char> packetData;
        if (readPacketHex(frameNumber, packetData)) {
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (unsigned char ch : packetData) {
                oss << std::setw(2) << static_cast<int>(ch);
            }
            packetHex = oss.str();
        }

        detailJson["pdml"]["packet"][0].AddMember(
            "hexdata",
            rapidjson::Value().SetString(packetHex.c_str(), detailJson.GetAllocator()),
            detailJson.GetAllocator()
        );

        rapidjson::Value temp;
        temp.CopyFrom(detailJson["pdml"]["packet"][0], detailJson.GetAllocator());
        detailJson.SetObject();
        detailJson.CopyFrom(temp, detailJson.GetAllocator());

        return true;
    }

    return false;
}

DataStreamCountInfo TsharkCommandService::getSessionDataStream(
    const std::string& currentFilePath,
    const Session& session,
    std::vector<DataStreamItem>& dataStreamList) {

    DataStreamCountInfo countInfo;
    std::string transProto = session.trans_proto;
    std::transform(transProto.begin(), transProto.end(), transProto.begin(), ::tolower);

    std::string fourTuple;
    if (session.ip1.find(":") != std::string::npos) {
        fourTuple = "[" + session.ip1 + "]:" + std::to_string(session.ip1_port)
            + ",[" + session.ip2 + "]:" + std::to_string(session.ip2_port);
    }
    else {
        fourTuple = session.ip1 + ":" + std::to_string(session.ip1_port)
            + "," + session.ip2 + ":" + std::to_string(session.ip2_port);
    }

    std::string tsharkCmd = buildCommand({
        tsharkExePath,
        "-r",
        currentFilePath,
        "-q",
        "-z",
        "follow," + transProto + ",raw," + fourTuple
    });
    std::unique_ptr<FILE, decltype(&EASYTSHARK_FCLOSE)> pipe(ProcessUtil::PopenEx(tsharkCmd), EASYTSHARK_FCLOSE);
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    uint32_t maxItems = 500;
    std::vector<char> buffer(65535);
    bool dataStart = false;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        std::string line(buffer.data());
        DataStreamItem item;

        MiscUtil::trimEnd(line);
        if (line.find("Node 0: ") == 0) {
            countInfo.node0 = line.substr(strlen("Node 0: "));
            continue;
        }
        if (line.find("Node 1: ") == 0) {
            countInfo.node1 = line.substr(strlen("Node 1: "));
            dataStart = true;
            continue;
        }

        if (!dataStart || line.find("=====") != std::string::npos) {
            continue;
        }

        if (line[0] == '\t') {
            item.hexData = line.substr(1);
            item.srcNode = countInfo.node1;
            item.dstNode = countInfo.node0;
            countInfo.node1PacketCount++;
            countInfo.node1BytesCount += static_cast<uint32_t>(item.hexData.length() / 2);
        }
        else {
            item.hexData = line;
            item.srcNode = countInfo.node0;
            item.dstNode = countInfo.node1;
            countInfo.node0PacketCount++;
            countInfo.node0BytesCount += static_cast<uint32_t>(item.hexData.length() / 2);
        }

        countInfo.totalPacketCount++;
        if (dataStreamList.size() < maxItems) {
            dataStreamList.push_back(item);
        }
    }

    return countInfo;
}

std::string TsharkCommandService::resolveCaptureInterface(const std::string& adapterName) {
    std::string normalized = adapterName;
    if (normalized.size() >= 2 && normalized.front() == '"' && normalized.back() == '"') {
        normalized = normalized.substr(1, normalized.size() - 2);
    }

    std::vector<std::string> candidates = { normalized };
#ifdef _WIN32
    std::string normalizedWindowsAlias = normalizeWindowsAdapterAlias(normalized);
    if (!normalizedWindowsAlias.empty() && normalizedWindowsAlias != normalized) {
        candidates.push_back(normalizedWindowsAlias);
    }

    std::string alias = resolveWindowsInterfaceDescription(normalized);
    if (!alias.empty() && alias != normalized) {
        candidates.push_back(alias);
    }
#endif

    std::string cmd = buildCommand({ tsharkExePath, "-D" });
    std::unique_ptr<FILE, decltype(&EASYTSHARK_FCLOSE)> pipe(ProcessUtil::PopenEx(cmd), EASYTSHARK_FCLOSE);
    if (!pipe) {
        return normalized;
    }

    char buffer[512] = { 0 };
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        std::string line(buffer);
        MiscUtil::trimEnd(line);
        size_t dotPos = line.find('.');
        size_t firstSpace = line.find(' ');
        if (dotPos == std::string::npos || firstSpace == std::string::npos || firstSpace <= dotPos) {
            continue;
        }

        std::string index = line.substr(0, dotPos);
        std::string interfaceName;
        size_t secondSpace = line.find(' ', firstSpace + 1);
        if (secondSpace != std::string::npos) {
            interfaceName = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        }
        else {
            interfaceName = line.substr(firstSpace + 1);
        }

        std::string remark;
        size_t remarkStart = line.find('(');
        size_t remarkEnd = line.rfind(')');
        if (remarkStart != std::string::npos && remarkEnd != std::string::npos && remarkEnd > remarkStart) {
            remark = line.substr(remarkStart + 1, remarkEnd - remarkStart - 1);
        }

        for (const std::string& candidate : candidates) {
            if (candidate == index || candidate == interfaceName || candidate == remark) {
                LOG_F(INFO, "resolved capture adapter '%s' to tshark interface '%s'", normalized.c_str(), interfaceName.c_str());
                return interfaceName;
            }
        }
    }

    return normalized;
}

std::string TsharkCommandService::buildCommand(const std::vector<std::string>& args) const {
    std::string command;
    for (const auto& arg : args) {
        command += quoteArg(arg);
        command += " ";
    }
    return command;
}

std::string TsharkCommandService::quoteArg(const std::string& arg) const {
    if (arg.empty()) {
        return "\"\"";
    }

    bool needsQuote = arg.find_first_of(" \t\"") != std::string::npos;
    if (!needsQuote) {
        return arg;
    }

    std::string quoted = "\"";
    for (char ch : arg) {
        if (ch == '"') {
            quoted += "\\\"";
        }
        else {
            quoted += ch;
        }
    }
    quoted += "\"";
    return quoted;
}

