#ifndef EASYTSHARK_STORAGE_QUEUE_H
#define EASYTSHARK_STORAGE_QUEUE_H

#include "tshark_database.hpp"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

class StorageQueue {
public:
    StorageQueue(size_t maxPendingPackets = 50000, size_t maxStoreBatchSize = 2000);

    void start(std::shared_ptr<TsharkDatabase> storage, std::atomic<bool>& stopFlag);
    void stop(std::atomic<bool>& stopFlag);
    void clear();
    void enqueue(std::shared_ptr<Packet> packet, std::shared_ptr<Session> session, std::atomic<bool>& stopFlag);
    void notifyAll();

    uint64_t parsedPackets() const;
    uint64_t storedPackets() const;
    uint64_t wakeups() const;
    uint64_t backpressureWaits() const;
    size_t pendingPackets() const;
    size_t pendingSessions() const;
    size_t queueLimit() const;
    size_t batchLimit() const;

private:
    void run(std::atomic<bool>& stopFlag);
    bool drainOnce();

    std::shared_ptr<TsharkDatabase> storage;
    std::vector<std::shared_ptr<Packet>> packetsToStore;
    std::unordered_set<std::shared_ptr<Session>> sessionsToStore;
    std::mutex lock;
    std::condition_variable cv;
    std::shared_ptr<std::thread> workerThread;
    const size_t maxPendingPackets;
    const size_t maxStoreBatchSize;
    std::atomic<uint64_t> parsedPacketsCount{ 0 };
    std::atomic<uint64_t> storedPacketsCount{ 0 };
    std::atomic<uint64_t> storageWakeups{ 0 };
    std::atomic<uint64_t> storageBackpressureWaits{ 0 };
    std::atomic<size_t> pendingPacketGauge{ 0 };
    std::atomic<size_t> pendingSessionGauge{ 0 };
};

#endif // EASYTSHARK_STORAGE_QUEUE_H
