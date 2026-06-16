#ifndef EASYTSHARK_SESSION_AGGREGATOR_H
#define EASYTSHARK_SESSION_AGGREGATOR_H

#include "tshark_datatype.h"

#include <functional>
#include <map>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

class SessionAggregator {
public:
    void clear();
    std::shared_ptr<Session> processPacket(std::shared_ptr<Packet> packet);
    bool getPacket(uint32_t frameNumber, std::shared_ptr<Packet>& packet) const;
    bool getSession(uint32_t sessionId, std::shared_ptr<Session>& session) const;
    size_t packetCount() const;
    size_t sessionCount() const;

    void forEachPacket(const std::function<void(const std::shared_ptr<Packet>&)>& visitor) const;
    void forEachSession(const std::function<void(const std::shared_ptr<Session>&)>& visitor) const;

private:
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
    std::unordered_map<FiveTuple, std::shared_ptr<Session>, FiveTupleHash> sessionMap;
    std::map<uint32_t, std::shared_ptr<Session>> sessionIdMap;
    mutable std::shared_mutex stateLock;
};

#endif // EASYTSHARK_SESSION_AGGREGATOR_H
