#ifndef EASYTSHARK_ANALYSIS_THREAD_POOL_H
#define EASYTSHARK_ANALYSIS_THREAD_POOL_H

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// 固定大小的后台分析线程池，带队列上限和运行指标。
class AnalysisThreadPool {
public:
    struct Metrics {
        size_t workerCount = 0;
        size_t queueLimit = 0;
        size_t queuedTasks = 0;
        uint64_t activeTasks = 0;
        uint64_t submittedTasks = 0;
        uint64_t completedTasks = 0;
        uint64_t rejectedTasks = 0;
        bool stopping = false;
    };

    // 创建指定工作线程数和排队上限的线程池。
    AnalysisThreadPool(size_t workerCount, size_t queueLimit);
    // 析构时停止线程池并等待工作线程退出。
    ~AnalysisThreadPool();

    AnalysisThreadPool(const AnalysisThreadPool&) = delete;
    AnalysisThreadPool& operator=(const AnalysisThreadPool&) = delete;

    // 提交一个异步任务；队列已满或正在停止时返回 false。
    bool submit(std::function<void()> task);
    // 通知所有工作线程退出，并等待它们完成。
    void shutdown();
    // 返回线程池当前队列、任务数和停止状态快照。
    Metrics metrics() const;

private:
    // 工作线程主循环，从队列取任务并执行。
    void workerLoop();

    const size_t queueLimit_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    bool stopping_ = false;

    std::atomic<uint64_t> activeTasks_{ 0 };
    std::atomic<uint64_t> submittedTasks_{ 0 };
    std::atomic<uint64_t> completedTasks_{ 0 };
    std::atomic<uint64_t> rejectedTasks_{ 0 };
};

#endif // EASYTSHARK_ANALYSIS_THREAD_POOL_H
