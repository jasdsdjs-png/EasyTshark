#include <iostream>
#include <algorithm>
#include "loguru/loguru.hpp"
#include "httplib/httplib.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include "tshark_manager.h"
#include "pagehelper.h"
#include "loguru/loguru.hpp"
#include "controller/packet_controller.hpp"
#include "controller/adaptor_controller.hpp"
#include "controller/session_controller.hpp"
#include "controller/stats_controller.hpp"
#include "distributed_runtime.h"

std::shared_ptr<TsharkManager> g_ptrTsharkManager;
std::shared_ptr<DistributedRuntime> g_ptrDistributedRuntime;

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


httplib::Server::HandlerResponse before_request(const httplib::Request& req, httplib::Response& res) {
    LOG_F(INFO, "Request received for %s", req.path.c_str());

    // 提取分页参数
    PageAndOrder* pageAndOrder = PageHelper::getPageAndOrder();
    pageAndOrder->pageNum = BaseController::getIntParam(req, "pageNum", 1);
    pageAndOrder->pageSize = BaseController::getIntParam(req, "pageSize", 100);
    pageAndOrder->orderBy = BaseController::getStringParam(req, "orderBy", "");
    pageAndOrder->descOrAsc = BaseController::getStringParam(req, "descOrAsc", "asc");
    return httplib::Server::HandlerResponse::Unhandled;
}

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

void after_response(const httplib::Request& req, httplib::Response& res) {
    if (req.method != "OPTIONS") {
        setCorsHeaders(req, res);
    }
    LOG_F(INFO, "Received response with status %d", res.status);
}

void InitLog(int argc, char* argv[]) {
    // 初始化 Loguru
    loguru::init(argc, argv);

    // 设置日志文件路径
    loguru::add_file("app.log", loguru::Append, loguru::Verbosity_MAX);
}


int main(int argc, char* argv[]) {

    setlocale(LC_ALL, "zh_CN.UTF-8");

    InitLog(argc, argv);

    std::string currentExePath = ProcessUtil::getExecutableDir();
    g_ptrDistributedRuntime = std::make_shared<DistributedRuntime>(currentExePath);

    std::string role = getArgValue(argc, argv, "--role", "gateway");
    if (role == "worker") {
        std::string listenAddress = getArgValue(argc, argv, "--listen", "127.0.0.1:50051");
        if (!g_ptrDistributedRuntime->startWorker(listenAddress)) {
            return -1;
        }
        LOG_F(INFO, "EasyTshark gRPC worker mode is running on %s", listenAddress.c_str());
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
        return 0;
    }


    // 提取UI进程参数
    std::string pidParam = getArgValue(argc, argv, "--uipid", "");
    if (pidParam.empty()) {
        LOG_F(ERROR, "usage: tshark_server --uipid=xxx [--workers=host:port,...]");
        return -1;
    }

    PID_T pid = std::stoi(pidParam);
    if (!ProcessUtil::isProcessRunning(pid)) {
        LOG_F(ERROR, "UI进程不存在，tshark_server将退出");
        return -1;
    }

    // 启动UI监控线程
    std::thread uiMonitorThread([&]() {
        while (true) {
            if (!ProcessUtil::isProcessRunning(pid)) {
                LOG_F(INFO, "检测到UI进程已退出");
                return;
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
     });


    g_ptrTsharkManager = std::make_shared<TsharkManager>(currentExePath);
    std::string workers = getArgValue(argc, argv, "--workers", "");
    if (!workers.empty()) {
        g_ptrDistributedRuntime->configureWorkers(SplitWorkerAddresses(workers));
    }

    // 创建一个 HTTP 服务器对象
    httplib::Server server;
    server.new_task_queue = [] {
        auto workerCount = std::max<size_t>(4, std::thread::hardware_concurrency());
        return new httplib::ThreadPool(workerCount, workerCount * 128);
    };
    server.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
        setCorsHeaders(req, res);
        res.status = 200;
        });

    // 设置钩子函数
    server.set_pre_routing_handler(before_request);
    server.set_post_routing_handler(after_response);


    // 创建Controller并注册路由
    std::vector<std::shared_ptr<BaseController>> controllerList;
    controllerList.push_back(std::make_shared<PacketController>(server, g_ptrTsharkManager, g_ptrDistributedRuntime));
    controllerList.push_back(std::make_shared<SessionController>(server, g_ptrTsharkManager));
    controllerList.push_back(std::make_shared<AdaptorController>(server, g_ptrTsharkManager, g_ptrDistributedRuntime));
    controllerList.push_back(std::make_shared<StatsController>(server, g_ptrTsharkManager));
    for (auto controller : controllerList) {
        controller->registerRoute();
    }

    // 在另一个线程中启动HTTP服务
    std::thread serverThread([&]() {
        LOG_F(INFO, "tshark_server is running on http://127.0.0.1:8080");
        server.listen("127.0.0.1", 8080);
        });


    // 等待UI进程退出
    uiMonitorThread.join();

    // UI进程退出后，HTTP服务即关闭
    server.stop();
    serverThread.join();

    // 如果还在抓包或者监控网卡流量，将其关闭
    g_ptrTsharkManager->reset();

    return 0;
}
