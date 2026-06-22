#include "analysis_thread_pool.h"

#include <algorithm>

AnalysisThreadPool::AnalysisThreadPool(size_t workerCount, size_t queueLimit)
    : queueLimit_(std::max<size_t>(1, queueLimit)) {
    workerCount = std::max<size_t>(1, workerCount);
    workers_.reserve(workerCount);
    for (size_t i = 0; i < workerCount; ++i) {
        workers_.emplace_back(&AnalysisThreadPool::workerLoop, this);
    }
}

AnalysisThreadPool::~AnalysisThreadPool() {
    shutdown();
}

bool AnalysisThreadPool::submit(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_ || tasks_.size() >= queueLimit_) {
            rejectedTasks_++;
            return false;
        }
        tasks_.push(std::move(task));
        submittedTasks_++;
    }
    cv_.notify_one();
    return true;
}

void AnalysisThreadPool::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) {
            return;
        }
        stopping_ = true;
    }
    cv_.notify_all();
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

AnalysisThreadPool::Metrics AnalysisThreadPool::metrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Metrics snapshot;
    snapshot.workerCount = workers_.size();
    snapshot.queueLimit = queueLimit_;
    snapshot.queuedTasks = tasks_.size();
    snapshot.activeTasks = activeTasks_.load();
    snapshot.submittedTasks = submittedTasks_.load();
    snapshot.completedTasks = completedTasks_.load();
    snapshot.rejectedTasks = rejectedTasks_.load();
    snapshot.stopping = stopping_;
    return snapshot;
}

void AnalysisThreadPool::workerLoop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]() {
                return stopping_ || !tasks_.empty();
            });
            if (stopping_ && tasks_.empty()) {
                return;
            }
            task = std::move(tasks_.front());
            tasks_.pop();
        }

        activeTasks_++;
        try {
            task();
        }
        catch (...) {
            // Task bodies own status reporting; keep worker threads alive.
        }
        activeTasks_--;
        completedTasks_++;
    }
}
