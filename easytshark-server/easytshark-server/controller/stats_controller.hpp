//
// Created by xuanyuan on 2024/12/6.
//

#ifndef TSHARK_SERVER_STATS_CONTROLLER_HPP
#define TSHARK_SERVER_STATS_CONTROLLER_HPP
#include "base_controller.hpp"
#include "../proto_list.hpp"

// IP、协议、国家维度通信统计接口。
class StatsController : public BaseController {
public:
    StatsController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager)
        :BaseController(server, tsharkManager)
    {
    }

    // 注册各类统计查询路由。
    virtual void registerRoute() {

        __server.Post("/api/getIPStatsList", [this](const httplib::Request& req, httplib::Response& res) {
            getIPStatsList(req, res);
        });

        __server.Post("/api/getProtoStatsList", [this](const httplib::Request& req, httplib::Response& res) {
            getProtoStatsList(req, res);
        });

        __server.Post("/api/getCountryStatsList", [this](const httplib::Request& req, httplib::Response& res) {
            getCountryStatsList(req, res);
            });
    }

    // 获取IP统计列表
    void getIPStatsList(const httplib::Request &req, httplib::Response &res) {

        try {
            // 提取 URL 查询参数
            auto queryParams = req.params;
            int pageNum = getIntParam(req, "pageNum", 1);
            int pageSize = getIntParam(req, "pageSize",  100);

            QueryCondition queryCondition;
            if (!parseQueryCondition(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用 tSharkManager 的方法获取数据
            std::vector<std::shared_ptr<IPStatsInfo>> ipStatsList;
            int total = 0;
            __tsharkManager->getIPStatsList(queryCondition, ipStatsList, total);
            sendDataList(res, ipStatsList, total);
        } catch (const std::exception &e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 获取协议统计列表
    void getProtoStatsList(const httplib::Request &req, httplib::Response &res) {

        try {
            // 提取 URL 查询参数
            auto queryParams = req.params;
            int pageNum = getIntParam(req, "pageNum", 1);
            int pageSize = getIntParam(req, "pageSize",  100);

            QueryCondition queryCondition;
            if (!parseQueryCondition(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用 tSharkManager 的方法获取数据
            std::vector< std::shared_ptr<ProtoStatsInfo>> protoStatsList;
            int total = 0;
            __tsharkManager->getProtoStatsList(queryCondition, protoStatsList, total);

            // 填充协议描述
            for (auto &item : protoStatsList) {
                item->proto_description = protoList.getProtoDesc(item->proto);
            }

            sendDataList(res, protoStatsList, total);
        } catch (const std::exception &e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 获取国家统计列表
    void getCountryStatsList(const httplib::Request& req, httplib::Response& res) {

        try {
            // 提取 URL 查询参数
            auto queryParams = req.params;
            int pageNum = getIntParam(req, "pageNum", 1);
            int pageSize = getIntParam(req, "pageSize", 100);

            QueryCondition queryCondition;
            if (!parseQueryCondition(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用 tSharkManager 的方法获取数据
            std::vector< std::shared_ptr<CountryStatsInfo>> countryStatsList;
            int total = 0;
            __tsharkManager->getCountryStatsList(queryCondition, countryStatsList, total);
            sendDataList(res, countryStatsList, total);
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

private:
    ProtoList protoList;
};

#endif //TSHARK_SERVER_STATS_CONTROLLER_HPP
