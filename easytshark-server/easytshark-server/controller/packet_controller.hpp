//
// Created by xuanyuan on 2025/02/16.
//

#ifndef TSHARK_SERVER_PACKET_CONTROLLER_HPP
#define TSHARK_SERVER_PACKET_CONTROLLER_HPP

#include <memory>
#include <fstream>
#include <cctype>
#include <algorithm>

#include "base_controller.hpp"


// 数据包列表、详情、文件上传和离线分析任务接口。
class PacketController : public BaseController {
public:
    PacketController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager,
        std::shared_ptr<DistributedRuntime> distributedRuntime = nullptr)
        : BaseController(server, tsharkManager, distributedRuntime)
    {
    }

    // 注册数据包查询、文件分析和任务管理路由。
    virtual void registerRoute() {

        __server.Post("/api/getPacketList", [this](const httplib::Request& req, httplib::Response& res) {
            getPacketList(req, res);
        });

        __server.Post("/api/analysisFile", [this](const httplib::Request& req, httplib::Response& res) {
            analysisiFile(req, res);
        });

        __server.Post("/api/uploadAnalysisFile", [this](const httplib::Request& req, httplib::Response& res) {
            uploadAnalysisFile(req, res);
        });

        __server.Post("/api/getPacketDetail", [this](const httplib::Request& req, httplib::Response& res) {
            getPacketDetail(req, res);
        });

        __server.Post("/api/savePacket", [this](const httplib::Request& req, httplib::Response& res) {
            savePacket(req, res);
        });

        __server.Post("/api/analysisTasks", [this](const httplib::Request& req, httplib::Response& res) {
            createAnalysisTask(req, res);
        });

        __server.Get(R"(/api/analysisTasks/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
            getAnalysisTask(req, res);
        });

        __server.Post(R"(/api/analysisTasks/([^/]+)/activate)", [this](const httplib::Request& req, httplib::Response& res) {
            activateAnalysisTask(req, res);
        });

        __server.Post(R"(/api/analysisTasks/([^/]+)/cancel)", [this](const httplib::Request& req, httplib::Response& res) {
            cancelAnalysisTask(req, res);
        });
    }


    // 获取数据包列表
    void getPacketList(const httplib::Request &req, httplib::Response &res) {

        // 获取 JSON 数据中的字段
        try {

            QueryCondition queryCondition;
            if (!parseQueryCondition(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用 tSharkManager 的方法获取数据
            int total = 0;
            std::vector<std::shared_ptr<Packet>> packetList;
            __tsharkManager->queryPackets(queryCondition, packetList, total);
            sendDataList(res, packetList, total);
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 上传并分析离线数据包，供普通浏览器页面使用
    void uploadAnalysisFile(const httplib::Request& req, httplib::Response& res) {
        try {
            std::string uploadPath;
            if (!saveUploadedFile(req, uploadPath)) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            sendAnalysisTaskAccepted(res, submitAnalysisTask(uploadPath));
        }
        catch (const std::exception& e) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }


    // 分析离线数据包
    void analysisiFile(const httplib::Request& req, httplib::Response& res) {
        try {
            if (req.body.empty()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 使用 RapidJSON 解析 JSON
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 提取数据包文件路径
            std::string filePath = doc["filePath"].GetString();
            if (!MiscUtil::fileExists(filePath.c_str())) {
                return sendErrorResponse(res, ERROR_FILE_NOTFOUND);
            }

            sendAnalysisTaskAccepted(res, submitAnalysisTask(filePath));
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 获取数据包详情
    void getPacketDetail(const httplib::Request& req, httplib::Response& res) {

        try {

            if (req.body.empty()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 使用 RapidJSON 解析 JSON
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 提取数据包编号参数
            uint32_t frameNumber = doc["frameNumber"].GetInt();

            // 获取数据包详情
            rapidjson::Document dataDoc;
            __tsharkManager->getPacketDetailInfo(frameNumber, dataDoc);

            sendJsonResponse(res, dataDoc);
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_PARAMETER_WRONG);
        }
    }


    // 保存当前数据包
    void savePacket(const httplib::Request& req, httplib::Response& res) {

        try {

            if (req.body.empty()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 使用 RapidJSON 解析 JSON
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 提取保存路径和过滤器
            std::string savePath;
            if (doc.HasMember("savePath") && doc["savePath"].IsString()) {
                savePath = doc["savePath"].GetString();
            }
            if (savePath.empty()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            if (__tsharkManager->savePacket(savePath)) {
                sendSuccessResponse(res);
            }
            else {
                sendErrorResponse(res, ERROR_FILE_SAVE_FAILED);
            }
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_PARAMETER_WRONG);
        }
    }

    // 创建异步离线分析任务，支持上传文件或传入本地路径。
    void createAnalysisTask(const httplib::Request& req, httplib::Response& res) {
        try {
            std::string filePath;
            if (req.has_file("file")) {
                if (!saveUploadedFile(req, filePath)) {
                    return sendErrorResponse(res, ERROR_FILE_SAVE_FAILED);
                }
            }
            else {
                if (req.body.empty()) {
                    return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                }
                rapidjson::Document doc;
                if (doc.Parse(req.body.c_str()).HasParseError() || !doc.HasMember("filePath") || !doc["filePath"].IsString()) {
                    return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                }
                filePath = doc["filePath"].GetString();
                if (!MiscUtil::fileExists(filePath.c_str())) {
                    return sendErrorResponse(res, ERROR_FILE_NOTFOUND);
                }
            }

            std::string taskId = submitAnalysisTask(filePath);
            sendAnalysisTaskAccepted(res, taskId);
        }
        catch (const std::exception&) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 查询指定离线分析任务的状态。
    void getAnalysisTask(const httplib::Request& req, httplib::Response& res) {
        try {
            if (!__distributedRuntime || req.matches.size() < 2) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }
            std::string taskId = req.matches[1].str();
            rapidjson::Document dataDoc;
            auto& allocator = dataDoc.GetAllocator();
            if (!__distributedRuntime->writeTaskStatusJson(taskId, dataDoc, allocator)) {
                return sendErrorResponse(res, ERROR_FILE_NOTFOUND);
            }
            sendJsonResponse(res, dataDoc);
        }
        catch (const std::exception&) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 激活已完成任务，使前端查询切换到该任务数据集。
    void activateAnalysisTask(const httplib::Request& req, httplib::Response& res) {
        try {
            if (!__distributedRuntime || req.matches.size() < 2) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }
            std::string taskId = req.matches[1].str();
            if (!__distributedRuntime->activateTask(taskId)) {
                return sendErrorResponse(res, ERROR_STATUS_WRONG);
            }
            __tsharkManager->setActiveAnalysisManager(__distributedRuntime->getActiveAnalysisManager());
            sendSuccessResponse(res);
        }
        catch (const std::exception&) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 取消排队中或运行中的离线分析任务。
    void cancelAnalysisTask(const httplib::Request& req, httplib::Response& res) {
        try {
            if (!__distributedRuntime || req.matches.size() < 2) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }
            std::string taskId = req.matches[1].str();
            if (!__distributedRuntime->cancelTask(taskId)) {
                return sendErrorResponse(res, ERROR_STATUS_WRONG);
            }
            sendSuccessResponse(res);
        }
        catch (const std::exception&) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

private:
    // 返回异步分析任务已入队的统一响应。
    void sendAnalysisTaskAccepted(httplib::Response& res, const std::string& taskId) {
        if (taskId.empty()) {
            return sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }

        rapidjson::Document dataDoc;
        auto& allocator = dataDoc.GetAllocator();
        dataDoc.SetObject();
        dataDoc.AddMember("taskId", rapidjson::Value(taskId.c_str(), allocator), allocator);
        dataDoc.AddMember("status", rapidjson::Value("QUEUED", allocator), allocator);
        dataDoc.AddMember("async", true, allocator);
        sendJsonResponse(res, dataDoc);
    }

    // 校验并保存上传的 pcap/pcapng/cap 文件。
    bool saveUploadedFile(const httplib::Request& req, std::string& uploadPath) {
        if (!req.has_file("file")) {
            return false;
        }

        const auto& file = req.get_file_value("file");
        constexpr size_t kMaxUploadBytes = 1024ULL * 1024ULL * 1024ULL;
        if (file.content.empty() || file.content.size() > kMaxUploadBytes) {
            return false;
        }

        std::string filename = file.filename.empty() ? "upload.pcap" : file.filename;
        size_t slashPos = filename.find_last_of("/\\");
        if (slashPos != std::string::npos) {
            filename = filename.substr(slashPos + 1);
        }
        for (auto& ch : filename) {
            if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '.' && ch != '_' && ch != '-') {
                ch = '_';
            }
        }

        std::string lowerFilename = filename;
        std::transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::tolower);
        if (!(lowerFilename.size() >= 5 && lowerFilename.substr(lowerFilename.size() - 5) == ".pcap")
            && !(lowerFilename.size() >= 7 && lowerFilename.substr(lowerFilename.size() - 7) == ".pcapng")
            && !(lowerFilename.size() >= 4 && lowerFilename.substr(lowerFilename.size() - 4) == ".cap")) {
            return false;
        }

        std::string uploadDir = MiscUtil::getDefaultDataDir() + "uploads/";
        if (!MiscUtil::createDirectory(uploadDir)) {
            return false;
        }

        uploadPath = uploadDir
            + "upload_"
            + std::to_string(MiscUtil::getCurrentTimeMillis())
            + "_"
            + filename;

        std::ofstream out(uploadPath, std::ios::binary);
        if (!out) {
            return false;
        }
        out.write(file.content.data(), file.content.size());
        return true;
    }

    // 向分析运行时提交离线文件任务。
    std::string submitAnalysisTask(const std::string& filePath) {
        if (!__distributedRuntime) {
            return "";
        }
        return __distributedRuntime->submitAnalyzeTask(filePath);
    }
};


#endif //TSHARK_SERVER_PACKET_CONTROLLER_HPP
