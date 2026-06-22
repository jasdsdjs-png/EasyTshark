#include <iostream>
#include <algorithm>
#include <clocale>
#include "loguru/loguru.hpp"
#include "httplib/httplib.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include "tshark_manager.h"
#include "pagehelper.h"
#include "controller/packet_controller.hpp"
#include "controller/adaptor_controller.hpp"
#include "controller/session_controller.hpp"
#include "controller/stats_controller.hpp"
#include "distributed_runtime.h"

#ifdef _WIN32
#include <windows.h>
#endif

std::shared_ptr<TsharkManager> g_ptrTsharkManager;
std::shared_ptr<DistributedRuntime> g_ptrDistributedRuntime;

// Reads a command-line option in --flag or --name=value form.
std::string getArgValue(int argc, char* argv[], const std::string& name, const std::string& defaultValue = "") {
    const std::string prefix = name + "=";
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == name) {
            return "true";
        }
        if (arg.find(prefix) == 0) {
            return arg.substr(prefix.size());
        }
    }
    return defaultValue;
}

// Reads an unsigned size option and falls back when parsing fails.
size_t getSizeArgValue(int argc, char* argv[], const std::string& name, size_t defaultValue) {
    std::string value = getArgValue(argc, argv, name, "");
    if (value.empty()) {
        return defaultValue;
    }
    try {
        return static_cast<size_t>(std::stoull(value));
    }
    catch (const std::exception&) {
        return defaultValue;
    }
}

// Configures the Windows console for UTF-8 log output.
void configureUtf8Output() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    setlocale(LC_ALL, ".UTF-8");
}

// Initializes per-request paging before route handlers run.
httplib::Server::HandlerResponse before_request(const httplib::Request& req, httplib::Response& res) {
    LOG_F(INFO, "Request received for %s", req.path.c_str());

    PageAndOrder* pageAndOrder = PageHelper::getPageAndOrder();
    pageAndOrder->pageNum = BaseController::getIntParam(req, "pageNum", 1);
    pageAndOrder->pageSize = BaseController::getIntParam(req, "pageSize", 100);
    pageAndOrder->orderBy = BaseController::getStringParam(req, "orderBy", "");
    pageAndOrder->descOrAsc = BaseController::getStringParam(req, "descOrAsc", "asc");
    return httplib::Server::HandlerResponse::Unhandled;
}

// Applies CORS headers for the local React frontend.
void setCorsHeaders(const httplib::Request& req, httplib::Response& res) {
    std::string origin;
    auto originIt = req.headers.find("Origin");
    if (originIt != req.headers.end()) {
        origin = originIt->second;
    }

    if (origin == "http://localhost:3000" || origin == "http://127.0.0.1:3000") {
        res.set_header("Access-Control-Allow-Origin", origin);
    }
    else {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:3000");
    }

    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    res.set_header("Access-Control-Allow-Credentials", "true");
}

// Adds post-route CORS headers and logs response status.
void after_response(const httplib::Request& req, httplib::Response& res) {
    if (req.method != "OPTIONS") {
        setCorsHeaders(req, res);
    }
    LOG_F(INFO, "Received response with status %d", res.status);
}

// Initializes Loguru and writes full logs to app.log.
void InitLog(int argc, char* argv[]) {
    loguru::init(argc, argv);
    loguru::add_file("app.log", loguru::Append, loguru::Verbosity_MAX);
}

int main(int argc, char* argv[]) {
    configureUtf8Output();
    InitLog(argc, argv);

    std::string currentExePath = ProcessUtil::getExecutableDir();

    std::string role = getArgValue(argc, argv, "--role", "gateway");
    if (role == "worker") {
        LOG_F(ERROR, "--role=worker has been removed. Use --analysis-workers=N for local C++ analysis concurrency.");
        return -1;
    }

    size_t analysisWorkers = getSizeArgValue(argc, argv, "--analysis-workers", 0);
    size_t analysisQueueLimit = getSizeArgValue(argc, argv, "--analysis-queue", 64);
    g_ptrDistributedRuntime = std::make_shared<DistributedRuntime>(currentExePath, analysisWorkers, analysisQueueLimit);

    // Reads the UI process id so the backend can exit with the UI.
    std::string pidParam = getArgValue(argc, argv, "--uipid", "");
    if (pidParam.empty()) {
        LOG_F(ERROR, "usage: tshark_server --uipid=xxx [--analysis-workers=N] [--analysis-queue=N]");
        return -1;
    }

    PID_T pid = std::stoi(pidParam);
    if (!ProcessUtil::isProcessRunning(pid)) {
        LOG_F(ERROR, "UI process does not exist, tshark_server will exit");
        return -1;
    }

    // Watches the UI process and stops the HTTP service when the UI exits.
    std::thread uiMonitorThread([&]() {
        while (true) {
            if (!ProcessUtil::isProcessRunning(pid)) {
                LOG_F(INFO, "Detected UI process exit");
                return;
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
     });

    g_ptrTsharkManager = std::make_shared<TsharkManager>(currentExePath);
    std::string workerLabels = getArgValue(argc, argv, "--analysis-worker-labels", "");
    if (workerLabels.empty()) {
        workerLabels = getArgValue(argc, argv, "--workers", "");
        if (!workerLabels.empty()) {
            LOG_F(INFO, "--workers is deprecated; using it as local analysis worker labels only");
        }
    }
    if (!workerLabels.empty()) {
        g_ptrDistributedRuntime->configureWorkers(SplitWorkerAddresses(workerLabels));
    }

    // Creates the HTTP server and gives it a bounded worker pool.
    httplib::Server server;
    server.new_task_queue = [] {
        auto workerCount = std::max<size_t>(4, std::thread::hardware_concurrency());
        return new httplib::ThreadPool(workerCount, workerCount * 128);
    };
    server.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
        setCorsHeaders(req, res);
        res.status = 200;
        });

    server.set_pre_routing_handler(before_request);
    server.set_post_routing_handler(after_response);

    // Creates controllers and lets each controller register its routes.
    std::vector<std::shared_ptr<BaseController>> controllerList;
    controllerList.push_back(std::make_shared<PacketController>(server, g_ptrTsharkManager, g_ptrDistributedRuntime));
    controllerList.push_back(std::make_shared<SessionController>(server, g_ptrTsharkManager));
    controllerList.push_back(std::make_shared<AdaptorController>(server, g_ptrTsharkManager, g_ptrDistributedRuntime));
    controllerList.push_back(std::make_shared<StatsController>(server, g_ptrTsharkManager));
    for (auto controller : controllerList) {
        controller->registerRoute();
    }

    // Runs HTTP serving on a separate thread while main waits for the UI.
    std::thread serverThread([&]() {
        LOG_F(INFO, "tshark_server is running on http://127.0.0.1:8080");
        server.listen("127.0.0.1", 8080);
        });

    uiMonitorThread.join();

    server.stop();
    serverThread.join();

    // Cleans up capture, analysis, and adapter-monitor resources.
    g_ptrTsharkManager->reset();

    return 0;
}
