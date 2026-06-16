#include "distributed_runtime.h"

#include <chrono>
#include <direct.h>
#include <sstream>
#include <utility>

#include "grpcpp/grpcpp.h"
#include "loguru/loguru.hpp"
#include "misc_util.hpp"
#include "proto/easytshark_worker.grpc.pb.h"
#include "tshark_manager.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

namespace {

constexpr int kDefaultWorkerMaxTasks = 2;
constexpr int kWorkerHeartbeatIntervalMs = 5000;
constexpr int kGrpcDeadlineMs = 1500;

class WorkerRegistryServiceImpl final : public easytshark::grpc::WorkerRegistry::Service {
public:
    explicit WorkerRegistryServiceImpl(DistributedRuntime* runtime) : runtime_(runtime) {}

    Status RegisterWorker(ServerContext*, const easytshark::grpc::WorkerInfo* request,
        easytshark::grpc::RegisterReply* reply) override {
        reply->set_accepted(true);
        reply->set_message("worker registered: " + request->worker_id());
        return Status::OK;
    }

    Status Heartbeat(ServerContext*, const easytshark::grpc::WorkerHeartbeat* request,
        easytshark::grpc::HeartbeatReply* reply) override {
        (void)runtime_;
        reply->set_accepted(true);
        reply->set_message("heartbeat accepted: " + request->worker_id());
        return Status::OK;
    }

private:
    DistributedRuntime* runtime_;
};

class PacketAnalyzeServiceImpl final : public easytshark::grpc::PacketAnalyzeService::Service {
public:
    explicit PacketAnalyzeServiceImpl(DistributedRuntime* runtime) : runtime_(runtime) {}

    Status AnalyzePacketRange(ServerContext*, const easytshark::grpc::AnalyzeTask* request,
        grpc::ServerWriter<easytshark::grpc::AnalyzeBatch>* writer) override {
        runtime_->recordAnalyzeRpc();
        easytshark::grpc::AnalyzeBatch batch;
        batch.set_task_id(request->task_id());
        batch.set_sequence(1);
        batch.set_progress(100);
        batch.set_error_message("");
        writer->Write(batch);
        return Status::OK;
    }

    Status CancelTask(ServerContext*, const easytshark::grpc::TaskId* request,
        easytshark::grpc::CancelReply* reply) override {
        reply->set_canceled(true);
        reply->set_message("cancel accepted: " + request->task_id());
        return Status::OK;
    }

private:
    DistributedRuntime* runtime_;
};

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

DistributedRuntime::DistributedRuntime(std::string workDir) : workDir_(std::move(workDir)) {
    _mkdir((workDir_ + "/data").c_str());
    _mkdir((workDir_ + "/data/tasks").c_str());
    schedulerThread_ = std::thread(&DistributedRuntime::schedulerLoop, this);
    heartbeatThread_ = std::thread(&DistributedRuntime::heartbeatLoop, this);
}

DistributedRuntime::~DistributedRuntime() {
    schedulerRunning_ = false;
    heartbeatRunning_ = false;
    taskCv_.notify_all();
    if (schedulerThread_.joinable()) {
        schedulerThread_.join();
    }
    if (heartbeatThread_.joinable()) {
        heartbeatThread_.join();
    }
    stopWorker();
}

bool DistributedRuntime::startWorker(const std::string& listenAddress) {
    if (workerRunning_) {
        return true;
    }

    auto registryService = std::make_shared<WorkerRegistryServiceImpl>(this);
    auto analyzeService = std::make_shared<PacketAnalyzeServiceImpl>(this);

    ServerBuilder builder;
    builder.AddListeningPort(listenAddress, grpc::InsecureServerCredentials());
    builder.RegisterService(registryService.get());
    builder.RegisterService(analyzeService.get());

    workerServer_ = builder.BuildAndStart();
    if (!workerServer_) {
        LOG_F(ERROR, "gRPC worker failed to listen on %s", listenAddress.c_str());
        return false;
    }

    workerRunning_ = true;
    workerServerThread_ = std::thread([this, registryService, analyzeService, listenAddress]() {
        LOG_F(INFO, "EasyTshark gRPC worker is running on %s", listenAddress.c_str());
        workerServer_->Wait();
        workerRunning_ = false;
    });
    return true;
}

void DistributedRuntime::stopWorker() {
    if (workerServer_) {
        workerServer_->Shutdown();
    }
    if (workerServerThread_.joinable()) {
        workerServerThread_.join();
    }
    workerServer_.reset();
    workerRunning_ = false;
}

void DistributedRuntime::configureWorkers(const std::vector<std::string>& workers) {
    std::lock_guard<std::mutex> lock(mutex_);
    workerAddresses_ = workers;
    for (const auto& address : workers) {
        if (workerOnline_.find(address) == workerOnline_.end()) {
            workerOnline_[address] = false;
            workerLastHeartbeatMs_[address] = 0;
        }
    }
}

std::vector<std::string> DistributedRuntime::getWorkerAddresses() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return workerAddresses_;
}

bool DistributedRuntime::hasWorkers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !workerAddresses_.empty();
}

std::string DistributedRuntime::submitAnalyzeTask(const std::string& pcapPath) {
    std::string taskId = "task-" + std::to_string(MiscUtil::getCurrentTimeMillis());
    DistributedTaskSnapshot snapshot;
    snapshot.taskId = taskId;
    snapshot.status = "QUEUED";
    snapshot.filePath = pcapPath;
    snapshot.progress = 0;
    snapshot.workerId = "local";
    snapshot.message = "analysis task queued";
    snapshot.createdAtMs = MiscUtil::getCurrentTimeMillis();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        tasks_[taskId] = snapshot;
        pendingTasks_.push(taskId);
        submittedTasks_++;
    }
    taskCv_.notify_one();
    return taskId;
}

bool DistributedRuntime::cancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) {
        return false;
    }
    if (it->second.status == "DONE" || it->second.status == "FAILED" || it->second.status == "CANCELED") {
        return false;
    }
    it->second.status = "CANCELED";
    it->second.message = "analysis task canceled";
    it->second.progress = 100;
    it->second.finishedAtMs = MiscUtil::getCurrentTimeMillis();
    canceledTasks_++;
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
            if (it->second.status == "FAILED") {
                return false;
            }
            if (it->second.status == "CANCELED") {
                return false;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

void DistributedRuntime::schedulerLoop() {
    while (schedulerRunning_) {
        std::string taskId;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            taskCv_.wait(lock, [this]() {
                return !schedulerRunning_ || !pendingTasks_.empty();
            });
            if (!schedulerRunning_) {
                break;
            }
            taskId = pendingTasks_.front();
            pendingTasks_.pop();
            auto it = tasks_.find(taskId);
            if (it != tasks_.end() && it->second.status == "CANCELED") {
                continue;
            }
        }
        runLocalAnalyzeTask(taskId);
    }
}

void DistributedRuntime::heartbeatLoop() {
    while (heartbeatRunning_) {
        heartbeatWorkers();
        std::this_thread::sleep_for(std::chrono::milliseconds(kWorkerHeartbeatIntervalMs));
    }
}

void DistributedRuntime::runLocalAnalyzeTask(const std::string& taskId) {
    std::string pcapPath;
    bool workersConfigured = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(taskId);
        if (it == tasks_.end()) {
            return;
        }
        if (it->second.status == "CANCELED") {
            return;
        }
        pcapPath = it->second.filePath;
        workersConfigured = !workerAddresses_.empty();
        it->second.status = "RUNNING";
        it->second.progress = 5;
        it->second.startedAtMs = MiscUtil::getCurrentTimeMillis();
        it->second.message = workersConfigured
            ? "workers configured; local task store is source of truth for this build"
            : "local analyzer running";
    }

    try {
        std::string taskDir = workDir_ + "/data/tasks/" + taskId;
        _mkdir(taskDir.c_str());
        std::string dbPath = taskDir + "/packets.db";
        auto manager = std::make_shared<TsharkManager>(workDir_, dbPath);

        updateTaskStatus(taskId, "RUNNING", "tshark parsing packets", 20);
        bool ok = manager->analysisFile(pcapPath);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto taskIt = tasks_.find(taskId);
            if (taskIt != tasks_.end() && taskIt->second.status == "CANCELED") {
                return;
            }
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
        failedTasks_++;
        finishTask(taskId, "FAILED", e.what());
    }
}

void DistributedRuntime::updateTaskStatus(const std::string& taskId, const std::string& status,
    const std::string& message, int progress) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) {
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

void DistributedRuntime::recordAnalyzeRpc() {
    rpcAnalyzeCalls_++;
}

void DistributedRuntime::heartbeatWorkers() {
    auto workers = getWorkerAddresses();
    for (const auto& address : workers) {
        auto channel = grpc::CreateChannel(address, grpc::InsecureChannelCredentials());
        auto stub = easytshark::grpc::WorkerRegistry::NewStub(channel);
        easytshark::grpc::WorkerHeartbeat request;
        request.set_worker_id(address);
        request.set_parsed_packets(0);
        request.set_running_tasks(0);
        easytshark::grpc::HeartbeatReply reply;
        ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(kGrpcDeadlineMs));
        const auto status = stub->Heartbeat(&context, request, &reply);
        rpcHeartbeatCalls_++;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            workerOnline_[address] = status.ok() && reply.accepted();
            if (workerOnline_[address]) {
                workerLastHeartbeatMs_[address] = MiscUtil::getCurrentTimeMillis();
            }
        }
    }
}

void DistributedRuntime::writeWorkersJson(rapidjson::Value& out,
    rapidjson::Document::AllocatorType& allocator) const {
    out.SetArray();
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& address : workerAddresses_) {
        rapidjson::Value obj(rapidjson::kObjectType);
        AddString(obj, "address", address, allocator);
        obj.AddMember("max_parallel_tasks", kDefaultWorkerMaxTasks, allocator);
        auto onlineIt = workerOnline_.find(address);
        obj.AddMember("online", onlineIt != workerOnline_.end() && onlineIt->second, allocator);
        auto heartbeatIt = workerLastHeartbeatMs_.find(address);
        obj.AddMember("last_heartbeat_ms",
            heartbeatIt == workerLastHeartbeatMs_.end() ? static_cast<int64_t>(0) : heartbeatIt->second,
            allocator);
        out.PushBack(obj, allocator);
    }
}

void DistributedRuntime::writeMetricsJson(rapidjson::Value& out,
    rapidjson::Document::AllocatorType& allocator) const {
    out.SetObject();
    out.AddMember("worker_mode_running", workerRunning_.load(), allocator);
    out.AddMember("rpc_analyze_calls", static_cast<uint64_t>(rpcAnalyzeCalls_.load()), allocator);
    out.AddMember("rpc_heartbeat_calls", static_cast<uint64_t>(rpcHeartbeatCalls_.load()), allocator);
    out.AddMember("submitted_tasks", static_cast<uint64_t>(submittedTasks_.load()), allocator);
    out.AddMember("completed_tasks", static_cast<uint64_t>(completedTasks_.load()), allocator);
    out.AddMember("failed_tasks", static_cast<uint64_t>(failedTasks_.load()), allocator);
    out.AddMember("canceled_tasks", static_cast<uint64_t>(canceledTasks_.load()), allocator);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        out.AddMember("worker_count", static_cast<uint32_t>(workerAddresses_.size()), allocator);
        out.AddMember("queued_tasks", static_cast<uint32_t>(pendingTasks_.size()), allocator);
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

    const auto& task = it->second;
    out.SetObject();
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
