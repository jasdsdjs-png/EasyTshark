#ifndef EASYTSHARK_PACKET_PARSER_H
#define EASYTSHARK_PACKET_PARSER_H

#include "tshark_datatype.h"

#include <memory>
#include <string>
#include <vector>

// 解析 tshark 文本输出为 Packet 结构。
class PacketParser {
public:
    // 返回 tshark 导出包列表时需要的字段参数。
    static std::vector<std::string> getTsharkFieldArgs();
    // 将一行制表符分隔的 tshark 输出解析到 Packet。
    static bool parseLine(std::string line, std::shared_ptr<Packet> packet);
};

#endif // EASYTSHARK_PACKET_PARSER_H
