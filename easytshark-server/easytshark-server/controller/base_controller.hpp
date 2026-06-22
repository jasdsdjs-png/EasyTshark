
#ifndef TSHARK_SERVER_BASE_CONTROLLER_HPP
#define TSHARK_SERVER_BASE_CONTROLLER_HPP
#include "httplib/httplib.h"
#include "../tshark_datatype.h"
#include "../tshark_errorcode.hpp"
#include "../tshark_manager.h"
#include "../distributed_runtime.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include <iostream>
#include <limits>
#include <memory>

// HTTP Controller 基类，提供路由注册约定和统一 JSON 响应工具。
class BaseController {
public:
    BaseController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager,
        std::shared_ptr<DistributedRuntime> distributedRuntime = nullptr)
        :__server(server)
        ,__tsharkManager(tsharkManager)
        ,__distributedRuntime(distributedRuntime) {
    }
    // 注册当前 Controller 管理的 HTTP 路由。
    virtual void registerRoute() = 0;

protected:
    httplib::Server& __server;
    std::shared_ptr<TsharkManager> __tsharkManager;
    std::shared_ptr<DistributedRuntime> __distributedRuntime;

public:
    // 从 URL 查询参数中提取整数，缺失时使用默认值。
    static int getIntParam(const httplib::Request &req, std::string paramName, int defaultValue = 0) {
        auto it = req.params.find(paramName);
        if (it == req.params.end()) {
            return defaultValue;
        }
        try {
            size_t consumed = 0;
            long parsed = std::stol(it->second, &consumed, 10);
            if (consumed != it->second.size()
                || parsed < std::numeric_limits<int>::min()
                || parsed > std::numeric_limits<int>::max()) {
                return defaultValue;
            }
            return static_cast<int>(parsed);
        }
        catch (const std::exception&) {
            return defaultValue;
        }
    }

    // 从 URL 查询参数中提取字符串，缺失时使用默认值。
    static std::string getStringParam(const httplib::Request &req, std::string paramName, std::string defaultValue = "") {
        std::string value = defaultValue;
        auto it = req.params.find(paramName);
        if (it != req.params.end()) {
            value = it->second;
        }
        return value;
    }

protected:

    // 以统一分页列表格式返回数据数组。
    template<typename Data>
    void sendDataList(httplib::Response &res, std::vector<std::shared_ptr<Data>>& dataList, int total) {
        /**
         * 返回数据格式：
         * {
         *     "code": 0,
         *     "msg": "操作成功",
         *     "data" [] / {}
         * }
         */
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();

        // 添加 "code" 和 "msg"
        resDoc.AddMember("code", ERROR_SUCCESS, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);
        resDoc.AddMember("total", total, allocator);

        // 构建 "data" 数组
        rapidjson::Value dataArray(rapidjson::kArrayType);
        for (const auto& data : dataList) {
            rapidjson::Value obj(rapidjson::kObjectType);
            data->toJsonObj(obj, allocator);
            assert(obj.IsObject());
            dataArray.PushBack(obj, allocator);
        }

        resDoc.AddMember("data", dataArray, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        // 设置响应内容
        res.set_content(buffer.GetString(), "application/json");
    }

    // 以统一成功格式返回 JSON 对象。
    void sendJsonResponse(httplib::Response& res, rapidjson::Document& dataDoc) {
        /**
         * 返回数据格式：
         * {
         *     "code": 0,
         *     "msg": "操作成功",
         *     "data" [] / {}
         * }
         */
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", ERROR_SUCCESS, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);
        resDoc.AddMember("data", dataDoc, allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }


    // 返回不带 data 字段的成功响应。
    void sendSuccessResponse(httplib::Response& res) {
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", 0, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }


    // 按错误码返回统一错误响应。
    void sendErrorResponse(httplib::Response &res, int errorCode) {
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", errorCode, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(errorCode).c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    // 从请求体 JSON 中解析通用查询条件。
    bool parseQueryCondition(const httplib::Request& req, QueryCondition &queryCondition) {

        try {

            // 检查是否有 body 数据
            if (req.body.empty()) {
                throw std::runtime_error("Request body is empty");
            }

            // 使用 RapidJSON 解析 JSON
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError()) {
                throw std::runtime_error("Failed to parse JSON");
            }

            // 验证是否是 JSON 对象
            if (!doc.IsObject()) {
                throw std::runtime_error("Invalid JSON format, expected an object");
            }

            // 提取字段并赋值到 QueryCondition 中
            if (doc.HasMember("ip") && doc["ip"].IsString()) {
                queryCondition.ip = doc["ip"].GetString();
            }

            if (doc.HasMember("port")) {
                if (!doc["port"].IsUint() || doc["port"].GetUint() > std::numeric_limits<uint16_t>::max()) {
                    return false;
                }
                queryCondition.port = static_cast<uint16_t>(doc["port"].GetUint());
            }

            if (doc.HasMember("proto")) {
                if (!doc["proto"].IsString()) {
                    return false;
                }
                queryCondition.proto = doc["proto"].GetString();
            }

            if (doc.HasMember("session_id")) {
                if (!doc["session_id"].IsUint()) {
                    return false;
                }
                queryCondition.session_id = doc["session_id"].GetUint();
            }

        } catch (std::exception &) {
            std::cout << "parse parameter error" << std::endl;
            return false;
        }

        return true;
    }
};



#endif //TSHARK_SERVER_PACKET_CONTROLLER_HPP


