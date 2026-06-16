#include "packet_parser.h"

#include <cstdint>
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

    packet->frame_number = std::stoi(fields[0]);
    packet->time = std::stod(fields[1]);
    packet->len = std::stoi(fields[2]);
    packet->cap_len = std::stoi(fields[3]);
    packet->src_mac = fields[4];
    packet->dst_mac = fields[5];
    packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
    packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];

    if (!fields[10].empty() || !fields[11].empty()) {
        uint8_t transProtoNumber = static_cast<uint8_t>(std::stoi(fields[10].empty() ? fields[11] : fields[10]));
        auto it = kIpProtoMap.find(transProtoNumber);
        if (it != kIpProtoMap.end()) {
            packet->trans_proto = it->second;
        }
    }

    if (!fields[12].empty() || !fields[13].empty()) {
        packet->src_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
    }

    if (!fields[14].empty() || !fields[15].empty()) {
        packet->dst_port = std::stoi(fields[14].empty() ? fields[15] : fields[14]);
    }
    packet->protocol = fields[16];
    packet->info = fields[17];

    return true;
}
