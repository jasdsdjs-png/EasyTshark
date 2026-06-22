#include "distributed_runtime.h"

#include <algorithm>
#include <chrono>
#include <direct.h>
#include <sstream>
#include <thread>
#include <utility>

#include "loguru/loguru.hpp"
#include "misc_util.hpp"
#include "tshark_manager.h"

namespace {

constexpr size_t kDefaultQueueLimit = 64;

size_t DefaultWorkerCount() {
    const auto hardware = std::thread::hardware_concurrency();
    if (hardware == 0) {
        return 2;
    }
    return std::max<size_t>(2, std::min<size_t>(hardware / 2, 8));
}

void AddString(rapidjson::Value& obj, const char* name, const std::string& value,
    rapidjson::Document::AllocatorType& allocator) {
    obj.AddMember(rapidjson::Value(name, allocator).Move(),
        rapidjson::Value(value.c_str(), allocator).Move(), allocator);
}

} // namespace

std::vector<std::string> SplitWorkerAddresses(const std::string& value) {
    std::vector<std::string> workers;
    std::stringstream ss(value);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) {
            workers.push_back(item);
        }
    }
    return workers;
}

DistributedRuntime::DistributedRuntime(std::string workDir, size_t workerCount, size_t queueLimit)
    : workDir_(std::move(workDir)),
      analysisPool_(workerCount == 0 ? DefaultWorkerCount() : workerCount,
          queueLimit == 0 ? kDefaultQueueLimit : queueLimit) {
    _mkdir((workDir_ + "/data").c_str());
    _mkdir((workDir_ + "/data/tasks").c_str());
}

DistributedRuntime::~DistributedRuntime() {
    analysisPool_.shutdown();
}

void DistributedRuntime::configureWorkers(const std::vector<std::string>& workers) {
    std::lock_guard<std::mutex> lock(mutex_);
    configuredWorkerLabels_ = workers;
}

std::vector<std::string> DistributedRuntime::getWorkerAddresses() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return configuredWorkerLabels_;
}

bool DistributedRuntime::hasWorkers() const {
    return analysisPool_.metrics().workerCount > 0;
}

std::string DistributedRuntime::submitAnalyzeTask(const std::string& pcapPath) {
    std::string taskId = "task-" + std::to_string(MiscUtil::getCurrentTimeMillis());
    DistributedTaskSnapshot snapshot;
    snapshot.taskId = taskId;
    snapshot.status = "QUEUED";
    snapshot.filePath = pcapPath;
    snapshot.progress = 0;
    snapshot.workerId = "queued";
    snapshot.message = "analysis task queued";
    snapshot.createdAtMs = MiscUtil::getCurrentTimeMillis();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        tasks_[taskId] = snapshot;
        queuedTaskIds_.push_back(taskId);
    }

    bool accepted = analysisPool_.submit([this, taskId]() {
        runLocalAnalyzeTask(taskId);
    });
    if (!accepted) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            removeQueuedTaskLocked(taskId);
        }
        finishTask(taskId, "FAILED", "analysis thread pool queue is full");
        failedTasks_++;
        return "";
    }

    submittedTasks_++;
    return taskId;
}

bool DistributedRuntime::cancelTask(const std::string& taskId) {
    std::shared_ptr<TsharkManager> runningManager;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(taskId);
        if (it == tasks_.end()) {
            return false;
        }
        if (it->second.status == "DONE" || it->second.status == "FAILED" || it->second.status == "CANCELED") {
            return false;
        }
        removeQueuedTaskLocked(taskId);
        auto runningIt = runningManagers_.find(taskId);
        if (runningIt != runningManagers_.end()) {
            runningManager = runningIt->second;
        }
        it->second.status = "CANCELED";
        it->second.message = "analysis task canceled";
        it->second.progress = 100;
        it->second.finishedAtMs = MiscUtil::getCurrentTimeMillis();
        canceledTasks_++;
    }

    if (runningManager) {
        runningManager->requestStop();
    }
    return true;
}

bool DistributedRuntime::activateTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto taskIt = tasks_.find(taskId);
    auto managerIt = completedManagers_.find(taskId);
    if (taskIt == tasks_.end() || managerIt == completedManagers_.end() || taskIt->second.status != "DONE") {
        return false;
    }
    activeAnalysisManager_ = managerIt->second;
    taskIt->second.message = "task activated as current dataset";
    return true;
}

bool DistributedRuntime::waitForTask(const std::string& taskId, uint32_t timeoutMs) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = tasks_.find(taskId);
            if (it == tasks_.end()) {
                return false;
            }
            if (it->second.status == "DONE") {
                return true;
            }
            if (it->second.status == "FAILED" || it->second.status == "CANCELED") {
                return false;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

void DistributedRuntime::runLocalAnalyzeTask(const std::string& taskId) {
    std::string pcapPath;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(taskId);
        removeQueuedTaskLocked(taskId);
        if (it == tasks_.end() || it->second.status == "CANCELED") {
            return;
        }
        pcapPath = it->second.filePath;
        it->second.status = "RUNNING";
        it->second.progress = 5;
        it->second.startedAtMs = MiscUtil::getCurrentTimeMillis();
        it->second.workerId = "analysis-thread-" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        it->second.message = "local C++ analysis worker running";
    }

    try {
        std::string taskDir = workDir_ + "/data/tasks/" + taskId;
        _mkdir(taskDir.c_str());
        std::string dbPath = taskDir + "/packets.db";
        auto manager = std::make_shared<TsharkManager>(workDir_, dbPath);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = tasks_.find(taskId);
            if (it == tasks_.end() || it->second.status == "CANCELED") {
                return;
            }
            runningManagers_[taskId] = manager;
        }

        updateTaskStatus(taskId, "RUNNING", "tshark parsing packets with async storage queue", 20);
        bool ok = manager->analysisFile(pcapPath);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            runningManagers_.erase(taskId);
        }
        if (isTaskCanceled(taskId)) {
            return;
        }
        if (!ok) {
            failedTasks_++;
            finishTask(taskId, "FAILED", "tshark analyzer failed");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            completedManagers_[taskId] = manager;
            auto& task = tasks_[taskId];
            task.status = "DONE";
            task.progress = 100;
            task.dbPath = dbPath;
            task.message = "analysis completed";
            task.finishedAtMs = MiscUtil::getCurrentTimeMillis();
            completedTasks_++;
        }
    }
    catch (const std::exception& e) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            runningManagers_.erase(taskId);
        }
        failedTasks_++;
        finishTask(taskId, "FAILED", e.what());
    }
}

void DistributedRuntime::updateTaskStatus(const std::string& taskId, const std::string& status,
    const std::string& message, int progress) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end() || it->second.status == "CANCELED") {
        return;
    }
    it->second.status = status;
    it->second.message = message;
    it->second.progress = progress;
}

void DistributedRuntime::finishTask(const std::string& taskId, const std::string& status,
    const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) {
        return;
    }
    it->second.status = status;
    it->second.message = message;
    it->second.progress = 100;
    it->second.finishedAtMs = MiscUtil::getCurrentTimeMillis();
}

bool DistributedRuntime::isTaskCanceled(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(taskId);
    return it != tasks_.end() && it->second.status == "CANCELED";
}

void DistributedRuntime::removeQueuedTaskLocked(const std::string& taskId) {
    queuedTaskIds_.erase(std::remove(queuedTaskIds_.begin(), queuedTaskIds_.end(), taskId), queuedTaskIds_.end());
}

void DistributedRuntime::writeWorkersJson(rapidjson::Value& out,
    rapidjson::Document::AllocatorType& allocator) const {
    out.SetArray();
    auto metrics = analysisPool_.metrics();
    std::vector<std::string> labels;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        labels = configuredWorkerLabels_;
    }

    for (size_t i = 0; i < metrics.workerCount; ++i) {
        rapidjson::Value obj(rapidjson::kObjectType);
        const std::string id = "analysis-worker-" + std::to_string(i);
        AddString(obj, "id", id, allocator);
        AddString(obj, "kind", "local_thread", allocator);
        AddString(obj, "label", i < labels.size() ? labels[i] : id, allocator);
        obj.AddMember("online", !metrics.stopping, allocator);
        obj.AddMember("max_parallel_tasks", 1, allocator);
        out.PushBack(obj, allocator);
    }
}

void DistributedRuntime::writeMetricsJson(rapidjson::Value& out,
    rapidjson::Document::AllocatorType& allocator) const {
    out.SetObject();
    auto pool = analysisPool_.metrics();
    rapidjson::Value threadPool(rapidjson::kObjectType);
    threadPool.AddMember("workers", static_cast<uint64_t>(pool.workerCount), allocator);
    threadPool.AddMember("active", static_cast<uint64_t>(pool.activeTasks), allocator);
    threadPool.AddMember("queued", static_cast<uint64_t>(pool.queuedTasks), allocator);
    threadPool.AddMember("queue_limit", static_cast<uint64_t>(pool.queueLimit), allocator);
    threadPool.AddMember("submitted", static_cast<uint64_t>(pool.submittedTasks), allocator);
    threadPool.AddMember("completed", static_cast<uint64_t>(pool.completedTasks), allocator);
    threadPool.AddMember("rejected", static_cast<uint64_t>(pool.rejectedTasks), allocator);
    threadPool.AddMember("stopping", pool.stopping, allocator);
    out.AddMember("analysis_thread_pool", threadPool, allocator);

    out.AddMember("submitted_tasks", static_cast<uint64_t>(submittedTasks_.load()), allocator);
    out.AddMember("completed_tasks", static_cast<uint64_t>(completedTasks_.load()), allocator);
    out.AddMember("failed_tasks", static_cast<uint64_t>(failedTasks_.load()), allocator);
    out.AddMember("canceled_tasks", static_cast<uint64_t>(canceledTasks_.load()), allocator);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        out.AddMember("queued_tasks", static_cast<uint64_t>(queuedTaskIds_.size()), allocator);
        out.AddMember("task_count", static_cast<uint64_t>(tasks_.size()), allocator);
        out.AddMember("active_dataset", activeAnalysisManager_ != nullptr, allocator);
    }
}

void DistributedRuntime::writeTaskStatusJson(rapidjson::Value& out,
    rapidjson::Document::AllocatorType& allocator) const {
    out.SetArray();
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& item : tasks_) {
        rapidjson::Value obj(rapidjson::kObjectType);
        const auto& task = item.second;
        AddString(obj, "task_id", task.taskId, allocator);
        AddString(obj, "status", task.status, allocator);
        AddString(obj, "file_path", task.filePath, allocator);
        AddString(obj, "worker_id", task.workerId, allocator);
        AddString(obj, "db_path", task.dbPath, allocator);
        AddString(obj, "message", task.message, allocator);
        obj.AddMember("progress", task.progress, allocator);
        obj.AddMember("total_batches", task.totalBatches, allocator);
        obj.AddMember("total_packets", task.totalPackets, allocator);
        obj.AddMember("created_at_ms", task.createdAtMs, allocator);
        obj.AddMember("started_at_ms", task.startedAtMs, allocator);
        obj.AddMember("finished_at_ms", task.finishedAtMs, allocator);
        out.PushBack(obj, allocator);
    }
}

bool DistributedRuntime::writeTaskStatusJson(const std::string& taskId, rapidjson::Value& out,
    rapidjson::Document::AllocatorType& allocator) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) {
        return false;
    }

    out.SetObject();
    const auto& task = it->second;
    AddString(out, "task_id", task.taskId, allocator);
    AddString(out, "status", task.status, allocator);
    AddString(out, "file_path", task.filePath, allocator);
    AddString(out, "worker_id", task.workerId, allocator);
    AddString(out, "db_path", task.dbPath, allocator);
    AddString(out, "message", task.message, allocator);
    out.AddMember("progress", task.progress, allocator);
    out.AddMember("total_batches", task.totalBatches, allocator);
    out.AddMember("total_packets", task.totalPackets, allocator);
    out.AddMember("created_at_ms", task.createdAtMs, allocator);
    out.AddMember("started_at_ms", task.startedAtMs, allocator);
    out.AddMember("finished_at_ms", task.finishedAtMs, allocator);
    return true;
}

std::shared_ptr<TsharkManager> DistributedRuntime::getActiveAnalysisManager() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeAnalysisManager_;
}
