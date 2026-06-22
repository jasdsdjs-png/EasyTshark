#include "storage_queue.h"

#include <algorithm>
#include <chrono>

StorageQueue::StorageQueue(size_t maxPendingPackets, size_t maxStoreBatchSize)
    : maxPendingPackets(maxPendingPackets), maxStoreBatchSize(maxStoreBatchSize) {
}

void StorageQueue::start(std::shared_ptr<TsharkDatabase> nextStorage, std::atomic<bool>& stopFlag) {
    storage = nextStorage;
    workerThread = std::make_shared<std::thread>(&StorageQueue::run, this, std::ref(stopFlag));
}

void StorageQueue::stop(std::atomic<bool>& stopFlag) {
    stopFlag = true;
    notifyAll();
    if (workerThread && workerThread->joinable()) {
        workerThread->join();
    }
    workerThread.reset();
}

void StorageQueue::clear() {
    std::unique_lock<std::mutex> queueLock(lock);
    packetsToStore.clear();
    sessionsToStore.clear();
    pendingPacketGauge = 0;
    pendingSessionGauge = 0;
    peakPendingPacketGauge = 0;
    peakPendingSessionGauge = 0;
    parsedPacketsCount = 0;
    storedPacketsCount = 0;
    storageWakeups = 0;
    storageBackpressureWaits = 0;
}

void StorageQueue::enqueue(std::shared_ptr<Packet> packet, std::shared_ptr<Session> session, std::atomic<bool>& stopFlag) {
    {
        std::unique_lock<std::mutex> queueLock(lock);
        while (!stopFlag.load() && packetsToStore.size() >= maxPendingPackets) {
            storageBackpressureWaits++;
            cv.wait_for(queueLock, std::chrono::milliseconds(200));
        }
        if (stopFlag.load()) {
            return;
        }
        packetsToStore.push_back(packet);
        if (session) {
            sessionsToStore.insert(session);
        }
        pendingPacketGauge = packetsToStore.size();
        pendingSessionGauge = sessionsToStore.size();
        peakPendingPacketGauge = (std::max)(peakPendingPacketGauge.load(), pendingPacketGauge.load());
        peakPendingSessionGauge = (std::max)(peakPendingSessionGauge.load(), pendingSessionGauge.load());
    }
    parsedPacketsCount++;
    cv.notify_one();
}

void StorageQueue::notifyAll() {
    cv.notify_all();
}

uint64_t StorageQueue::parsedPackets() const {
    return parsedPacketsCount.load();
}

uint64_t StorageQueue::storedPackets() const {
    return storedPacketsCount.load();
}

uint64_t StorageQueue::wakeups() const {
    return storageWakeups.load();
}

uint64_t StorageQueue::backpressureWaits() const {
    return storageBackpressureWaits.load();
}

size_t StorageQueue::pendingPackets() const {
    return pendingPacketGauge.load();
}

size_t StorageQueue::pendingSessions() const {
    return pendingSessionGauge.load();
}

size_t StorageQueue::peakPendingPackets() const {
    return peakPendingPacketGauge.load();
}

size_t StorageQueue::peakPendingSessions() const {
    return peakPendingSessionGauge.load();
}

size_t StorageQueue::queueLimit() const {
    return maxPendingPackets;
}

size_t StorageQueue::batchLimit() const {
    return maxStoreBatchSize;
}

void StorageQueue::run(std::atomic<bool>& stopFlag) {
    while (true) {
        {
            std::unique_lock<std::mutex> queueLock(lock);
            cv.wait_for(queueLock, std::chrono::milliseconds(500), [this, &stopFlag]() {
                return stopFlag.load()
                    || packetsToStore.size() >= maxStoreBatchSize
                    || !sessionsToStore.empty();
            });
            storageWakeups++;
        }

        while (drainOnce()) {
        }

        if (stopFlag.load()) {
            std::unique_lock<std::mutex> queueLock(lock);
            if (packetsToStore.empty() && sessionsToStore.empty()) {
                break;
            }
        }
    }
}

bool StorageQueue::drainOnce() {
    std::vector<std::shared_ptr<Packet>> packetBatch;
    std::unordered_set<std::shared_ptr<Session>> sessionBatch;
    {
        std::unique_lock<std::mutex> queueLock(lock);
        if (packetsToStore.empty() && sessionsToStore.empty()) {
            return false;
        }

        size_t batchSize = (std::min)(maxStoreBatchSize, packetsToStore.size());
        packetBatch.insert(packetBatch.end(), packetsToStore.begin(), packetsToStore.begin() + batchSize);
        packetsToStore.erase(packetsToStore.begin(), packetsToStore.begin() + batchSize);

        sessionBatch.swap(sessionsToStore);
        pendingPacketGauge = packetsToStore.size();
        pendingSessionGauge = sessionsToStore.size();
    }

    if (!packetBatch.empty() && storage) {
        if (storage->storePackets(packetBatch)) {
            storedPacketsCount.fetch_add(packetBatch.size());
        }
    }
    if (!sessionBatch.empty() && storage) {
        storage->storeAndUpdateSessions(sessionBatch);
    }
    cv.notify_all();
    return true;
}



