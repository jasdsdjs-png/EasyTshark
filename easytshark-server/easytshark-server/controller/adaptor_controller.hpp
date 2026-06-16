
#ifndef TSHARK_SERVER_ADAPTOR_CONTROLLER_HPP
#define TSHARK_SERVER_ADAPTOR_CONTROLLER_HPP
#include "base_controller.hpp"

// 网卡相关的接口
class AdaptorController : public BaseController {
public:
    AdaptorController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager,
        std::shared_ptr<DistributedRuntime> distributedRuntime = nullptr)
        :BaseController(server, tsharkManager, distributedRuntime)
    {
    }

    virtual void registerRoute() {

        __server.Get("/api/getWorkStatus", [this](const httplib::Request& req, httplib::Response& res) {
            getWorkStatus(req, res);
            });

        __server.Post("/api/startCapture", [this](const httplib::Request& req, httplib::Response& res) {
            startCapture(req, res);
            });

        __server.Get("/api/stopCapture", [this](const httplib::Request& req, httplib::Response& res) {
            stopCapture(req, res);
            });

        __server.Get("/api/startMonitorAdaptersFlowTrend", [this](const httplib::Request& req, httplib::Response& res) {
            startMonitorAdaptersFlowTrend(req, res);
            });

        __server.Get("/api/stopMonitorAdaptersFlowTrend", [this](const httplib::Request& req, httplib::Response& res) {
            stopMonitorAdaptersFlowTrend(req, res);
            });

        __server.Get("/api/getAdaptersFlowTrendData", [this](const httplib::Request& req, httplib::Response& res) {
            getAdaptersFlowTrendData(req, res);
            });

        __server.Get("/api/getBackendMetrics", [this](const httplib::Request& req, httplib::Response& res) {
            getBackendMetrics(req, res);
            });

        __server.Get("/api/getWorkerList", [this](const httplib::Request& req, httplib::Response& res) {
            getWorkerList(req, res);
            });

        __server.Get("/api/getDistributedTaskStatus", [this](const httplib::Request& req, httplib::Response& res) {
            getDistributedTaskStatus(req, res);
            });
    }

    // 获取工作状态
    void getWorkStatus(const httplib::Request& req, httplib::Response& res) {
        try {
            WORK_STATUS workStatus = __tsharkManager->getWorkStatus();
            rapidjson::Document resDoc;
            rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
            resDoc.SetObject();
            resDoc.AddMember("workStatus", workStatus, allocator);
            sendJsonResponse(res, resDoc);
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 开始抓包
    void startCapture(const httplib::Request& req, httplib::Response& res) {
        try {
            if (req.body.empty()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 检查当前状态是否允许抓包
            if (__tsharkManager->getWorkStatus() != STATUS_IDLE) {
                return sendErrorResponse(res, ERROR_STATUS_WRONG);
            }

            // 使用 RapidJSON 解析 JSON
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 提取网卡名称
            if (!doc.HasMember("adapterName")) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }
            std::string adapterName = doc["adapterName"].GetString();
            if (adapterName.empty()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 开始抓包
            if (__tsharkManager->startCapture(adapterName)) {
                sendSuccessResponse(res);
            }
            else {
                sendErrorResponse(res, ERROR_TSHARK_WRONG);
            }
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 停止抓包
    void stopCapture(const httplib::Request& req, httplib::Response& res) {
        try {
            if (__tsharkManager->getWorkStatus() == STATUS_CAPTURING) {
                __tsharkManager->stopCapture();
                sendSuccessResponse(res);
            }
            else {
                sendErrorResponse(res, ERROR_STATUS_WRONG);
            }
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 开始监控网卡流量
    void startMonitorAdaptersFlowTrend(const httplib::Request& req, httplib::Response& res) {
        try {
            if (__tsharkManager->getWorkStatus() == STATUS_IDLE) {
                __tsharkManager->startMonitorAdaptersFlowTrend();
                sendSuccessResponse(res);
            }
            else if (__tsharkManager->getWorkStatus() == STATUS_MONITORING) {
                sendSuccessResponse(res);
            }
            else {
                sendErrorResponse(res, ERROR_STATUS_WRONG);
            }
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }


    // 停止监控网卡流量
    void stopMonitorAdaptersFlowTrend(const httplib::Request& req, httplib::Response& res) {
        try {
            if (__tsharkManager->getWorkStatus() == STATUS_MONITORING) {
                __tsharkManager->stopMonitorAdaptersFlowTrend();
                sendSuccessResponse(res);
            }
            else {
                sendErrorResponse(res, ERROR_SUCCESS);
            }
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 获取网卡流量数据
    void getAdaptersFlowTrendData(const httplib::Request& req, httplib::Response& res) {

        try {
            std::map<std::string, std::map<long, long>> flowTrendData;
            __tsharkManager->getAdaptersFlowTrendData(flowTrendData);

            rapidjson::Document resDoc;
            rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
            resDoc.SetObject();

            // 添加 "code" 和 "msg"
            resDoc.AddMember("code", ERROR_SUCCESS, allocator);
            resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);

            // 构建 "data"
            rapidjson::Value dataObject(rapidjson::kObjectType);
            for (const auto &adaptorItem : flowTrendData) {
                rapidjson::Value adaptorDataList(rapidjson::kArrayType);
                for (const auto &timeItem : adaptorItem.second) {
                    rapidjson::Value timeObj(rapidjson::kObjectType);
                    timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
                    timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
                    adaptorDataList.PushBack(timeObj, allocator);
                }

                dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
            }

            resDoc.AddMember("data", dataObject, allocator);

            // 序列化为 JSON 字符串
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            resDoc.Accept(writer);

            // 设置响应内容
            res.set_content(buffer.GetString(), "application/json");
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void getBackendMetrics(const httplib::Request& req, httplib::Response& res) {
        try {
            rapidjson::Document dataDoc;
            rapidjson::Document::AllocatorType& allocator = dataDoc.GetAllocator();
            dataDoc.SetObject();
            dataDoc.AddMember("http_worker_pool_enabled", true, allocator);

            rapidjson::Value tshark(rapidjson::kObjectType);
            __tsharkManager->writeMetricsJson(tshark, allocator);
            dataDoc.AddMember("tshark", tshark, allocator);

            rapidjson::Value distributed(rapidjson::kObjectType);
            if (__distributedRuntime) {
                __distributedRuntime->writeMetricsJson(distributed, allocator);
            }
            dataDoc.AddMember("distributed", distributed, allocator);
            sendJsonResponse(res, dataDoc);
        }
        catch (const std::exception& e) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void getWorkerList(const httplib::Request& req, httplib::Response& res) {
        try {
            rapidjson::Document dataDoc;
            rapidjson::Document::AllocatorType& allocator = dataDoc.GetAllocator();
            dataDoc.SetObject();
            rapidjson::Value workers(rapidjson::kArrayType);
            if (__distributedRuntime) {
                __distributedRuntime->writeWorkersJson(workers, allocator);
            }
            dataDoc.AddMember("workers", workers, allocator);
            sendJsonResponse(res, dataDoc);
        }
        catch (const std::exception& e) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void getDistributedTaskStatus(const httplib::Request& req, httplib::Response& res) {
        try {
            rapidjson::Document dataDoc;
            rapidjson::Document::AllocatorType& allocator = dataDoc.GetAllocator();
            dataDoc.SetObject();
            rapidjson::Value tasks(rapidjson::kArrayType);
            if (__distributedRuntime) {
                __distributedRuntime->writeTaskStatusJson(tasks, allocator);
            }
            dataDoc.AddMember("tasks", tasks, allocator);
            sendJsonResponse(res, dataDoc);
        }
        catch (const std::exception& e) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }
};

#endif //TSHARK_SERVER_ADAPTOR_CONTROLLER_HPP
