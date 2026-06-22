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

// 将解析线程产生的包和会话批量写入 SQLite，提供背压保护。
class StorageQueue {
public:
    // 创建带最大积压包数和批量写入大小的存储队列。
    StorageQueue(size_t maxPendingPackets = 50000, size_t maxStoreBatchSize = 2000);

    // 绑定数据库并启动后台写入线程。
    void start(std::shared_ptr<TsharkDatabase> storage, std::atomic<bool>& stopFlag);
    // 请求停止并等待写入线程退出。
    void stop(std::atomic<bool>& stopFlag);
    // 清空待写入队列和统计计数。
    void clear();
    // 入队一个包及其会话，队列满时按 stopFlag 等待背压释放。
    void enqueue(std::shared_ptr<Packet> packet, std::shared_ptr<Session> session, std::atomic<bool>& stopFlag);
    // 唤醒所有等待队列状态变化的线程。
    void notifyAll();

    // 返回已解析入队的数据包总数。
    uint64_t parsedPackets() const;
    // 返回已成功写库的数据包总数。
    uint64_t storedPackets() const;
    // 返回存储线程被唤醒的次数。
    uint64_t wakeups() const;
    // 返回生产者因队列满而等待的次数。
    uint64_t backpressureWaits() const;
    // 返回当前等待写库的数据包数量。
    size_t pendingPackets() const;
    // 返回本轮运行中队列达到过的最大待写包数。
    size_t peakPendingPackets() const;
    // 返回当前等待写库的会话数量。
    size_t pendingSessions() const;
    // 返回本轮运行中队列达到过的最大待写会话数。
    size_t peakPendingSessions() const;
    // 返回队列允许的最大积压包数。
    size_t queueLimit() const;
    // 返回单次批量写库的最大包数。
    size_t batchLimit() const;

private:
    // 后台写入线程主循环。
    void run(std::atomic<bool>& stopFlag);
    // 从队列取出一批数据并写入数据库。
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
    std::atomic<size_t> peakPendingPacketGauge{ 0 };
    std::atomic<size_t> peakPendingSessionGauge{ 0 };
};

#endif // EASYTSHARK_STORAGE_QUEUE_H


