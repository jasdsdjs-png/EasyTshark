//
// Created by xuanyuan on 2025/02/16.
//

#ifndef TSHARK_SERVER_PACKET_CONTROLLER_HPP
#define TSHARK_SERVER_PACKET_CONTROLLER_HPP

#include <memory>
#include <fstream>
#include <cctype>

#include "base_controller.hpp"


// 数据包相关的接口
class PacketController : public BaseController {
public:
    PacketController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager)
        : BaseController(server, tsharkManager)
    {
    }

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
            if (!req.has_file("file")) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            const auto& file = req.get_file_value("file");
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

            std::string uploadPath = "upload_"
                + std::to_string(MiscUtil::getCurrentTimeMillis())
                + "_"
                + filename;

            std::ofstream out(uploadPath, std::ios::binary);
            if (!out) {
                return sendErrorResponse(res, ERROR_FILE_SAVE_FAILED);
            }
            out.write(file.content.data(), file.content.size());
            out.close();

            if (__tsharkManager->analysisFile(uploadPath)) {
                sendSuccessResponse(res);
            }
            else {
                sendErrorResponse(res, ERROR_TSHARK_WRONG);
            }
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

            // 开始分析
            if (__tsharkManager->analysisFile(filePath)) {
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
};


#endif //TSHARK_SERVER_PACKET_CONTROLLER_HPP
