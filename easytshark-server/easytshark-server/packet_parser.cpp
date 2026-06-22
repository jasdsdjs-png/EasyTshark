#include "packet_parser.h"

#include <cstdint>
#include <limits>
#include <map>
#include <sstream>

namespace {
const std::map<uint8_t, std::string> kIpProtoMap = {
    {1, "ICMP"},
    {2, "IGMP"},
    {6, "TCP"},
    {17, "UDP"},
    {47, "GRE"},
    {50, "ESP"},
    {51, "AH"},
    {88, "EIGRP"},
    {89, "OSPF"},
    {132, "SCTP"}
};

bool ParseInt(const std::string& value, int& out) {
    if (value.empty()) {
        return false;
    }
    try {
        size_t consumed = 0;
        long parsed = std::stol(value, &consumed, 10);
        if (consumed != value.size()
            || parsed < std::numeric_limits<int>::min()
            || parsed > std::numeric_limits<int>::max()) {
            return false;
        }
        out = static_cast<int>(parsed);
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool ParseUInt16(const std::string& value, uint16_t& out) {
    int parsed = 0;
    if (!ParseInt(value, parsed) || parsed < 0 || parsed > std::numeric_limits<uint16_t>::max()) {
        return false;
    }
    out = static_cast<uint16_t>(parsed);
    return true;
}

bool ParseDouble(const std::string& value, double& out) {
    if (value.empty()) {
        return false;
    }
    try {
        size_t consumed = 0;
        double parsed = std::stod(value, &consumed);
        if (consumed != value.size()) {
            return false;
        }
        out = parsed;
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}
}

std::vector<std::string> PacketParser::getTsharkFieldArgs() {
    return {
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "ip.proto",
        "-e", "ipv6.nxt",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };
}

bool PacketParser::parseLine(std::string line, std::shared_ptr<Packet> packet) {
    if (line.empty() || !packet) {
        return false;
    }
    if (line.back() == '\n') {
        line.pop_back();
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    std::vector<std::string> fields;
    size_t start = 0;
    size_t end = std::string::npos;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start));

    if (fields.size() < 18) {
        return false;
    }

    int frameNumber = 0;
    int len = 0;
    int capLen = 0;
    double timestamp = 0.0;
    if (!ParseInt(fields[0], frameNumber)
        || !ParseDouble(fields[1], timestamp)
        || !ParseInt(fields[2], len)
        || !ParseInt(fields[3], capLen)
        || len < 0
        || capLen < 0) {
        return false;
    }

    packet->frame_number = frameNumber;
    packet->time = timestamp;
    packet->len = static_cast<uint32_t>(len);
    packet->cap_len = static_cast<uint32_t>(capLen);
    packet->src_mac = fields[4];
    packet->dst_mac = fields[5];
    packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
    packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];

    if (!fields[10].empty() || !fields[11].empty()) {
        int protoNumber = 0;
        if (!ParseInt(fields[10].empty() ? fields[11] : fields[10], protoNumber)
            || protoNumber < 0
            || protoNumber > std::numeric_limits<uint8_t>::max()) {
            return false;
        }
        uint8_t transProtoNumber = static_cast<uint8_t>(protoNumber);
        auto it = kIpProtoMap.find(transProtoNumber);
        if (it != kIpProtoMap.end()) {
            packet->trans_proto = it->second;
        }
    }

    if (!fields[12].empty() || !fields[13].empty()) {
        if (!ParseUInt16(fields[12].empty() ? fields[13] : fields[12], packet->src_port)) {
            return false;
        }
    }

    if (!fields[14].empty() || !fields[15].empty()) {
        if (!ParseUInt16(fields[14].empty() ? fields[15] : fields[14], packet->dst_port)) {
            return false;
        }
    }
    packet->protocol = fields[16];
    packet->info = fields[17];

    return true;
}
