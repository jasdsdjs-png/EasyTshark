#include "../easytshark-server/packet_parser.h"
#include "../easytshark-server/session_aggregator.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

int g_failed = 0;

void Expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "[FAIL] " << message << std::endl;
        ++g_failed;
    }
    else {
        std::cout << "[ OK ] " << message << std::endl;
    }
}

std::shared_ptr<Packet> ParseSamplePacket(int frameNumber, const std::string& srcIp,
    const std::string& dstIp, uint16_t srcPort, uint16_t dstPort, const std::string& appProto) {
    auto packet = std::make_shared<Packet>();
    std::string line =
        std::to_string(frameNumber) + "\t"
        "1710000000.123\t"
        "128\t"
        "128\t"
        "00:11:22:33:44:55\t"
        "66:77:88:99:aa:bb\t"
        + srcIp + "\t"
        "\t"
        + dstIp + "\t"
        "\t"
        "6\t"
        "\t"
        + std::to_string(srcPort) + "\t"
        "\t"
        + std::to_string(dstPort) + "\t"
        "\t"
        + appProto + "\t"
        "sample tcp flow";

    Expect(PacketParser::parseLine(line, packet), "packet parser accepts tshark field line");
    return packet;
}

void TestPacketParser() {
    auto packet = ParseSamplePacket(7, "192.168.1.10", "93.184.216.34", 54321, 443, "TLS");
    Expect(packet->frame_number == 7, "packet parser reads frame number");
    Expect(packet->len == 128 && packet->cap_len == 128, "packet parser reads lengths");
    Expect(packet->src_ip == "192.168.1.10", "packet parser reads source ip");
    Expect(packet->dst_ip == "93.184.216.34", "packet parser reads destination ip");
    Expect(packet->trans_proto == "TCP", "packet parser maps ip proto to TCP");
    Expect(packet->src_port == 54321 && packet->dst_port == 443, "packet parser reads tcp ports");
    Expect(packet->protocol == "TLS", "packet parser reads application protocol");
}

void TestSessionAggregator() {
    SessionAggregator aggregator;
    auto first = ParseSamplePacket(1, "10.0.0.2", "10.0.0.8", 50000, 80, "HTTP");
    auto second = ParseSamplePacket(2, "10.0.0.8", "10.0.0.2", 80, 50000, "HTTP");

    auto session1 = aggregator.processPacket(first);
    auto session2 = aggregator.processPacket(second);

    Expect(session1 != nullptr, "session aggregator creates tcp session");
    Expect(session1 == session2, "session aggregator treats reverse tuple as same session");
    Expect(aggregator.packetCount() == 2, "session aggregator stores packet cache");
    Expect(aggregator.sessionCount() == 1, "session aggregator stores one session");
    Expect(session1->packet_count == 2, "session aggregator counts packets from initialized state");
    Expect(session1->total_bytes == 256, "session aggregator sums bytes");
    Expect(first->belong_session_id == session1->session_id, "session aggregator links first packet");
    Expect(second->belong_session_id == session1->session_id, "session aggregator links second packet");
}

} // namespace

int main() {
    TestPacketParser();
    TestSessionAggregator();

    if (g_failed != 0) {
        std::cerr << g_failed << " backend self-test assertion(s) failed." << std::endl;
        return 1;
    }

    std::cout << "All backend self-tests passed." << std::endl;
    return 0;
}
