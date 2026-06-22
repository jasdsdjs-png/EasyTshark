#ifndef EASYTSHARK_SESSION_AGGREGATOR_H
#define EASYTSHARK_SESSION_AGGREGATOR_H

#include "tshark_datatype.h"

#include <functional>
#include <map>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

// 根据五元组把数据包聚合为会话，并提供线程安全读取。
class SessionAggregator {
public:
    // 清空所有包和会话缓存。
    void clear();
    // 处理一个数据包，创建或更新其所属会话。
    std::shared_ptr<Session> processPacket(std::shared_ptr<Packet> packet);
    // 按帧号查找已解析的数据包。
    bool getPacket(uint32_t frameNumber, std::shared_ptr<Packet>& packet) const;
    // 按会话 ID 查找聚合会话。
    bool getSession(uint32_t sessionId, std::shared_ptr<Session>& session) const;
    // 返回当前缓存的数据包数量。
    size_t packetCount() const;
    // 返回当前聚合出的会话数量。
    size_t sessionCount() const;

    // 遍历所有数据包并对每个包调用 visitor。
    void forEachPacket(const std::function<void(const std::shared_ptr<Packet>&)>& visitor) const;
    // 遍历所有会话并对每个会话调用 visitor。
    void forEachSession(const std::function<void(const std::shared_ptr<Session>&)>& visitor) const;

private:
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
    std::unordered_map<FiveTuple, std::shared_ptr<Session>, FiveTupleHash> sessionMap;
    std::map<uint32_t, std::shared_ptr<Session>> sessionIdMap;
    mutable std::shared_mutex stateLock;
};

#endif // EASYTSHARK_SESSION_AGGREGATOR_H
