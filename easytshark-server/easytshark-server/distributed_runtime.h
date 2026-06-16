#ifndef EASYTSHARK_DISTRIBUTED_RUNTIME_H
#define EASYTSHARK_DISTRIBUTED_RUNTIME_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "rapidjson/document.h"

namespace grpc {
class Server;
}

struct DistributedTaskSnapshot {
    std::string taskId;
    std::string status;
    std::string filePath;
    int totalBatches = 0;
    int totalPackets = 0;
    int progress = 0;
    std::string workerId;
    std::string dbPath;
    std::string message;
    int64_t createdAtMs = 0;
    int64_t startedAtMs = 0;
    int64_t finishedAtMs = 0;
};

class DistributedRuntime {
public:
    explicit DistributedRuntime(std::string workDir);
    ~DistributedRuntime();

    bool startWorker(const std::string& listenAddress);
    void stopWorker();

    void configureWorkers(const std::vector<std::string>& workers);
    std::vector<std::string> getWorkerAddresses() const;
    bool hasWorkers() const;

    std::string submitAnalyzeTask(const std::string& pcapPath);
    bool cancelTask(const std::string& taskId);
    bool activateTask(const std::string& taskId);
    bool waitForTask(const std::string& taskId, uint32_t timeoutMs);
    void heartbeatWorkers();
    void recordAnalyzeRpc();

    void writeWorkersJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) const;
    void writeMetricsJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) const;
    void writeTaskStatusJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) const;
    bool writeTaskStatusJson(const std::string& taskId, rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) const;
    std::shared_ptr<class TsharkManager> getActiveAnalysisManager() const;

private:
    void schedulerLoop();
    void heartbeatLoop();
    void runLocalAnalyzeTask(const std::string& taskId);
    void updateTaskStatus(const std::string& taskId, const std::string& status, const std::string& message, int progress);
    void finishTask(const std::string& taskId, const std::string& status, const std::string& message);

    std::string workDir_;
    mutable std::mutex mutex_;
    std::condition_variable taskCv_;
    std::queue<std::string> pendingTasks_;
    std::vector<std::string> workerAddresses_;
    std::unordered_map<std::string, bool> workerOnline_;
    std::unordered_map<std::string, int64_t> workerLastHeartbeatMs_;
    std::unordered_map<std::string, DistributedTaskSnapshot> tasks_;
    std::unordered_map<std::string, std::shared_ptr<class TsharkManager>> completedManagers_;
    std::shared_ptr<class TsharkManager> activeAnalysisManager_;
    std::thread schedulerThread_;
    std::thread heartbeatThread_;
    std::atomic<bool> schedulerRunning_{true};
    std::atomic<bool> heartbeatRunning_{true};

    std::unique_ptr<grpc::Server> workerServer_;
    std::thread workerServerThread_;
    std::atomic<bool> workerRunning_{false};
    std::atomic<uint64_t> rpcAnalyzeCalls_{0};
    std::atomic<uint64_t> rpcHeartbeatCalls_{0};
    std::atomic<uint64_t> submittedTasks_{0};
    std::atomic<uint64_t> completedTasks_{0};
    std::atomic<uint64_t> failedTasks_{0};
    std::atomic<uint64_t> canceledTasks_{0};
};

std::vector<std::string> SplitWorkerAddresses(const std::string& value);

#endif
