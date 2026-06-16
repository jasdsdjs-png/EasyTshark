#include "session_aggregator.h"

#include <mutex>

void SessionAggregator::clear() {
    std::unique_lock<std::shared_mutex> lock(stateLock);
    allPackets.clear();
    sessionMap.clear();
    sessionIdMap.clear();
}

std::shared_ptr<Session> SessionAggregator::processPacket(std::shared_ptr<Packet> packet) {
    std::unique_lock<std::shared_mutex> lock(stateLock);

    allPackets.insert(std::make_pair(packet->frame_number, packet));

    if (packet->trans_proto != "TCP" && packet->trans_proto != "UDP") {
        return nullptr;
    }

    FiveTuple tuple{ packet->src_ip, packet->dst_ip, packet->src_port, packet->dst_port, packet->trans_proto };
    std::shared_ptr<Session> session;
    auto it = sessionMap.find(tuple);
    if (it == sessionMap.end()) {
        session = std::make_shared<Session>();
        session->session_id = static_cast<uint32_t>(sessionMap.size() + 1);
        session->ip1 = packet->src_ip;
        session->ip2 = packet->dst_ip;
        session->ip1_location = packet->src_location;
        session->ip2_location = packet->dst_location;
        session->ip1_port = packet->src_port;
        session->ip2_port = packet->dst_port;
        session->start_time = packet->time;
        session->end_time = packet->time;
        session->trans_proto = packet->trans_proto;
        if (packet->protocol != "TCP" && packet->protocol != "UDP") {
            session->app_proto = packet->protocol;
        }

        sessionMap.insert(std::make_pair(tuple, session));
        sessionIdMap.insert(std::make_pair(session->session_id, session));
    }
    else {
        session = it->second;
        session->end_time = packet->time;
        if (packet->protocol != "TCP" && packet->protocol != "UDP") {
            session->app_proto = packet->protocol;
        }
    }

    session->packet_count++;
    session->total_bytes += packet->len;
    packet->belong_session_id = session->session_id;

    if (session->ip1 == packet->src_ip) {
        session->ip1_send_packets_count++;
        session->ip1_send_bytes_count += packet->len;
    }
    else {
        session->ip2_send_packets_count++;
        session->ip2_send_bytes_count += packet->len;
    }

    return session;
}

bool SessionAggregator::getPacket(uint32_t frameNumber, std::shared_ptr<Packet>& packet) const {
    std::shared_lock<std::shared_mutex> lock(stateLock);
    auto it = allPackets.find(frameNumber);
    if (it == allPackets.end()) {
        return false;
    }
    packet = it->second;
    return true;
}

bool SessionAggregator::getSession(uint32_t sessionId, std::shared_ptr<Session>& session) const {
    std::shared_lock<std::shared_mutex> lock(stateLock);
    auto it = sessionIdMap.find(sessionId);
    if (it == sessionIdMap.end()) {
        return false;
    }
    session = it->second;
    return true;
}

size_t SessionAggregator::packetCount() const {
    std::shared_lock<std::shared_mutex> lock(stateLock);
    return allPackets.size();
}

size_t SessionAggregator::sessionCount() const {
    std::shared_lock<std::shared_mutex> lock(stateLock);
    return sessionIdMap.size();
}

void SessionAggregator::forEachPacket(const std::function<void(const std::shared_ptr<Packet>&)>& visitor) const {
    std::shared_lock<std::shared_mutex> lock(stateLock);
    for (const auto& item : allPackets) {
        visitor(item.second);
    }
}

void SessionAggregator::forEachSession(const std::function<void(const std::shared_ptr<Session>&)>& visitor) const {
    std::shared_lock<std::shared_mutex> lock(stateLock);
    for (const auto& item : sessionIdMap) {
        visitor(item.second);
    }
}
