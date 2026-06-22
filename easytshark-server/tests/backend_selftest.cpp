#include "../easytshark-server/analysis_thread_pool.h"
#include "../easytshark-server/packet_parser.h"
#include "../easytshark-server/pagehelper.h"
#include "../easytshark-server/session_aggregator.h"
#include "../easytshark-server/storage_queue.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
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

std::string MakeTsharkLine(int frameNumber, const std::string& srcIp, const std::string& dstIp,
    uint16_t srcPort, uint16_t dstPort, const std::string& appProto, int ipProto = 6,
    bool ipv6 = false) {
    return std::to_string(frameNumber) + "\t"
        "1710000000.123\t"
        "128\t"
        "128\t"
        "00:11:22:33:44:55\t"
        "66:77:88:99:aa:bb\t"
        + (ipv6 ? std::string() : srcIp) + "\t"
        + (ipv6 ? srcIp : std::string()) + "\t"
        + (ipv6 ? std::string() : dstIp) + "\t"
        + (ipv6 ? dstIp : std::string()) + "\t"
        + (ipv6 ? std::string() : std::to_string(ipProto)) + "\t"
        + (ipv6 ? std::to_string(ipProto) : std::string()) + "\t"
        + std::to_string(srcPort) + "\t"
        "\t"
        + std::to_string(dstPort) + "\t"
        "\t"
        + appProto + "\t"
        "sample flow";
}

std::shared_ptr<Packet> ParseSamplePacket(int frameNumber, const std::string& srcIp,
    const std::string& dstIp, uint16_t srcPort, uint16_t dstPort, const std::string& appProto,
    int ipProto = 6) {
    auto packet = std::make_shared<Packet>();
    Expect(PacketParser::parseLine(MakeTsharkLine(frameNumber, srcIp, dstIp, srcPort, dstPort, appProto, ipProto), packet),
        "packet parser accepts tshark field line");
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

    auto ipv6Packet = std::make_shared<Packet>();
    Expect(PacketParser::parseLine(MakeTsharkLine(8, "2001:db8::1", "2001:db8::2", 5353, 53, "DNS", 17, true), ipv6Packet),
        "packet parser accepts ipv6 tshark field line");
    Expect(ipv6Packet->src_ip == "2001:db8::1" && ipv6Packet->dst_ip == "2001:db8::2", "packet parser reads ipv6 addresses");
    Expect(ipv6Packet->trans_proto == "UDP", "packet parser maps ipv6 next header to UDP");

    auto badPacket = std::make_shared<Packet>();
    Expect(!PacketParser::parseLine("bad\tline", badPacket), "packet parser rejects short field line");
    Expect(!PacketParser::parseLine("x\t1710000000.123\t128\t128\t\t\t1.1.1.1\t\t2.2.2.2\t\t6\t\t1\t\t2\t\tTCP\tbad", badPacket),
        "packet parser rejects non-numeric frame number");
    Expect(!PacketParser::parseLine("1\t1710000000.123\t128\t128\t\t\t1.1.1.1\t\t2.2.2.2\t\t6\t\t70000\t\t2\t\tTCP\tbad", badPacket),
        "packet parser rejects out-of-range port");
}

void TestAnalysisThreadPool() {
    AnalysisThreadPool pool(1, 1);
    std::atomic<bool> releaseFirst{ false };
    std::atomic<bool> firstStarted{ false };
    std::atomic<bool> secondRan{ false };

    Expect(pool.submit([&]() {
        firstStarted = true;
        while (!releaseFirst.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }), "analysis thread pool accepts first active task");

    for (int i = 0; i < 100 && !firstStarted.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    Expect(firstStarted.load(), "analysis thread pool starts worker task");

    Expect(pool.submit([&]() { secondRan = true; }), "analysis thread pool accepts one queued task");
    Expect(!pool.submit([]() {}), "analysis thread pool rejects task when bounded queue is full");

    auto saturated = pool.metrics();
    Expect(saturated.workerCount == 1, "analysis thread pool reports worker count");
    Expect(saturated.queueLimit == 1, "analysis thread pool reports queue limit");
    Expect(saturated.queuedTasks == 1, "analysis thread pool reports queued task");
    Expect(saturated.rejectedTasks == 1, "analysis thread pool records rejected task");

    releaseFirst = true;
    for (int i = 0; i < 100 && !secondRan.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    Expect(secondRan.load(), "analysis thread pool drains queued task");

    pool.shutdown();
    auto stopped = pool.metrics();
    Expect(stopped.stopping, "analysis thread pool reports stopped state");
    Expect(stopped.completedTasks == 2, "analysis thread pool counts completed tasks");
    Expect(!pool.submit([]() {}), "analysis thread pool rejects submit after shutdown");
}

void TestAnalysisThreadPoolSurvivesTaskException() {
    AnalysisThreadPool pool(1, 4);
    std::atomic<bool> ranAfterThrow{ false };
    Expect(pool.submit([]() { throw std::runtime_error("expected test exception"); }), "analysis thread pool accepts throwing task");
    Expect(pool.submit([&]() { ranAfterThrow = true; }), "analysis thread pool accepts task after throwing task");
    for (int i = 0; i < 100 && !ranAfterThrow.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    Expect(ranAfterThrow.load(), "analysis thread pool keeps worker alive after task exception");
    pool.shutdown();
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

    auto udpFirst = ParseSamplePacket(3, "10.0.0.3", "10.0.0.9", 53000, 53, "DNS", 17);
    auto udpSecond = ParseSamplePacket(4, "10.0.0.9", "10.0.0.3", 53, 53000, "DNS", 17);
    auto udpSession1 = aggregator.processPacket(udpFirst);
    auto udpSession2 = aggregator.processPacket(udpSecond);
    Expect(udpSession1 != nullptr && udpSession1 == udpSession2, "session aggregator treats reverse udp tuple as same session");
}

void TestStorageQueue() {
    const std::string dbPath = "backend_selftest_storage.db";
    std::remove(dbPath.c_str());
    auto db = std::make_shared<TsharkDatabase>(dbPath);
    StorageQueue queue(8, 2);
    std::atomic<bool> stopFlag{ false };
    queue.start(db, stopFlag);

    auto packet1 = ParseSamplePacket(10, "192.0.2.1", "198.51.100.1", 12345, 80, "HTTP");
    auto packet2 = ParseSamplePacket(11, "192.0.2.1", "198.51.100.1", 12345, 80, "HTTP");
    queue.enqueue(packet1, nullptr, stopFlag);
    queue.enqueue(packet2, nullptr, stopFlag);
    queue.stop(stopFlag);

    Expect(queue.parsedPackets() == 2, "storage queue counts parsed packets");
    Expect(queue.storedPackets() == 2, "storage queue drains remaining packets on stop");
    Expect(queue.peakPendingPackets() >= 1, "storage queue reports peak pending packets");
    std::remove(dbPath.c_str());
    std::remove((dbPath + "-wal").c_str());
    std::remove((dbPath + "-shm").c_str());
}

void TestPageHelperSqlWhitelist() {
    auto* page = PageHelper::getPageAndOrder();
    page->pageNum = 1;
    page->pageSize = 20;
    page->orderBy = "frame_number;DROP TABLE t_packets";
    page->descOrAsc = "desc";
    const auto unsafeSql = PageHelper::getPageSql();
    Expect(unsafeSql.find("DROP") == std::string::npos && unsafeSql.find("ORDER BY") == std::string::npos,
        "page helper rejects unsafe order by column");

    page->orderBy = "frame_number";
    page->descOrAsc = "DESC";
    const auto safeSql = PageHelper::getPageSql();
    Expect(safeSql.find("ORDER BY frame_number desc") != std::string::npos,
        "page helper allows whitelisted order by column");
    page->reset();
}

} // namespace

int main() {
    TestAnalysisThreadPool();
    TestAnalysisThreadPoolSurvivesTaskException();
    TestPacketParser();
    TestSessionAggregator();
    TestStorageQueue();
    TestPageHelperSqlWhitelist();

    if (g_failed != 0) {
        std::cerr << g_failed << " backend self-test assertion(s) failed." << std::endl;
        return 1;
    }

    std::cout << "All backend self-tests passed." << std::endl;
    return 0;
}
