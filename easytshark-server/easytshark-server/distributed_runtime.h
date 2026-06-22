#ifndef EASYTSHARK_DISTRIBUTED_RUNTIME_H
#define EASYTSHARK_DISTRIBUTED_RUNTIME_H

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis_thread_pool.h"
#include "rapidjson/document.h"

// 离线分析任务的状态快照，用于接口返回和指标展示。
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

// Kept as DistributedRuntime for API compatibility. It now represents the
// local C++17 concurrent analysis runtime rather than a gRPC worker runtime.
// 本地并发离线分析运行时，负责任务排队、取消、激活和指标输出。
class DistributedRuntime {
public:
    // 创建运行时，并初始化本地分析线程池。
    explicit DistributedRuntime(std::string workDir, size_t workerCount = 0, size_t queueLimit = 64);
    // 析构时停止后台分析线程池。
    ~DistributedRuntime();

    // 保存兼容旧接口的 worker 标签列表。
    void configureWorkers(const std::vector<std::string>& workers);
    // 返回已配置的 worker 标签。
    std::vector<std::string> getWorkerAddresses() const;
    // 判断是否配置了 worker 标签。
    bool hasWorkers() const;

    // 提交离线 pcap 分析任务并返回任务 ID。
    std::string submitAnalyzeTask(const std::string& pcapPath);
    // 请求取消排队中或运行中的分析任务。
    bool cancelTask(const std::string& taskId);
    // 将已完成任务的数据集切换为当前查询数据源。
    bool activateTask(const std::string& taskId);
    // 等待任务完成、失败或取消，直到超时。
    bool waitForTask(const std::string& taskId, uint32_t timeoutMs);

    // 将 worker 标签列表写入 JSON 数组。
    void writeWorkersJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) const;
    // 将运行时和线程池指标写入 JSON 对象。
    void writeMetricsJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) const;
    // 将所有分析任务状态写入 JSON 数组。
    void writeTaskStatusJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) const;
    // 将指定任务状态写入 JSON，任务不存在时返回 false。
    bool writeTaskStatusJson(const std::string& taskId, rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) const;
    // Returns the active manager for the selected completed dataset.
    std::shared_ptr<class TsharkManager> getActiveAnalysisManager() const;

private:
    // 在线程池中执行指定离线分析任务。
    void runLocalAnalyzeTask(const std::string& taskId);
    // 更新任务状态、消息和进度。
    void updateTaskStatus(const std::string& taskId, const std::string& status, const std::string& message, int progress);
    // 标记任务结束并维护完成/失败/取消计数。
    void finishTask(const std::string& taskId, const std::string& status, const std::string& message);
    // 判断任务是否已经进入取消状态。
    bool isTaskCanceled(const std::string& taskId) const;
    // 在已持锁状态下从排队列表移除任务。
    void removeQueuedTaskLocked(const std::string& taskId);

    std::string workDir_;
    mutable std::mutex mutex_;
    std::vector<std::string> configuredWorkerLabels_;
    std::deque<std::string> queuedTaskIds_;
    std::unordered_map<std::string, DistributedTaskSnapshot> tasks_;
    std::unordered_map<std::string, std::shared_ptr<class TsharkManager>> runningManagers_;
    std::unordered_map<std::string, std::shared_ptr<class TsharkManager>> completedManagers_;
    std::shared_ptr<class TsharkManager> activeAnalysisManager_;
    AnalysisThreadPool analysisPool_;

    std::atomic<uint64_t> submittedTasks_{ 0 };
    std::atomic<uint64_t> completedTasks_{ 0 };
    std::atomic<uint64_t> failedTasks_{ 0 };
    std::atomic<uint64_t> canceledTasks_{ 0 };
};

// 按逗号拆分 worker 标签配置字符串。
std::vector<std::string> SplitWorkerAddresses(const std::string& value);

#endif
