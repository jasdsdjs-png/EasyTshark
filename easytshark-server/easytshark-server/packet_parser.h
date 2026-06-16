#ifndef EASYTSHARK_PACKET_PARSER_H
#define EASYTSHARK_PACKET_PARSER_H

#include "tshark_datatype.h"

#include <memory>
#include <string>
#include <vector>

class PacketParser {
public:
    static std::vector<std::string> getTsharkFieldArgs();
    static bool parseLine(std::string line, std::shared_ptr<Packet> packet);
};

#endif // EASYTSHARK_PACKET_PARSER_H
