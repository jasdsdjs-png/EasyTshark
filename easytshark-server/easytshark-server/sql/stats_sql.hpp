//
// Created by xuanyuan on 2024/12/7.
//

#ifndef TSHARK_SERVER_STATS_SQL_HPP
#define TSHARK_SERVER_STATS_SQL_HPP

#include <string>
#include <sstream>
#include <iostream>
#include "../tshark_datatype.h"
#include "loguru/loguru.hpp"
#include "../pagehelper.h"

// 统计接口使用的 SQL 构造器。
class StatsSQL {
public:

    // 构造 IP 维度统计分页查询 SQL。
    static std::string buildIPStatsQuerySQL(QueryCondition &condition) {

        std::string sql;
        std::stringstream ss;
        ss << R"SQL(
            SELECT
                ip,
                location,
                MIN(start_time) AS earliest_time,
                MAX(end_time) AS latest_time,
                GROUP_CONCAT(DISTINCT port) AS ports,
                GROUP_CONCAT(DISTINCT trans_proto) AS trans_protos,
                GROUP_CONCAT(DISTINCT app_proto) AS app_protos,
                SUM(sent_packets) AS total_sent_packets,
                SUM(sent_bytes) AS total_sent_bytes,
                SUM(recv_packets) AS total_recv_packets,
                SUM(recv_bytes) AS total_recv_bytes,
                SUM(tcp_sessions) AS tcp_session_count,
                SUM(udp_sessions) AS udp_session_count
            FROM (
                SELECT
                    ip1 AS ip,
                    ip1_location AS location,
                    start_time,
                    end_time,
                    ip1_port AS port,
                    trans_proto,
                    app_proto,
                    ip1_send_packets_count AS sent_packets,
                    ip1_send_bytes_count AS sent_bytes,
                    ip2_send_packets_count AS recv_packets,
                    ip2_send_bytes_count AS recv_bytes,
                    CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions,
                    CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions
                FROM t_sessions
                UNION ALL
                SELECT
                    ip2 AS ip,
                    ip2_location AS location,
                    start_time,
                    end_time,
                    ip2_port AS port,
                    trans_proto,
                    app_proto,
                    ip2_send_packets_count AS sent_packets,
                    ip2_send_bytes_count AS sent_bytes,
                    ip1_send_packets_count AS recv_packets,
                    ip1_send_bytes_count AS recv_bytes,
                    CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions,
                    CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions
                FROM t_sessions
            ) t
        )SQL";

        ss << " WHERE (? = '' OR app_proto LIKE ? OR trans_proto LIKE ?)";
        ss << " AND (? = '' OR ip = ?)";
        ss << " AND (? = 0 OR port = ?)";

        ss << " GROUP BY ip";
        ss << PageHelper::getPageSql();
        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());

        return sql;
    }

    // 构造 IP 维度统计总数 SQL。
    static std::string buildIPStatsQuerySQL_Count(QueryCondition &condition) {
        std::string sql = buildIPStatsQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        std::cout << "[BUILD SQL]: " << countSql << std::endl;
        return countSql;
    }

    // 构造协议维度统计分页查询 SQL。
    static std::string buildProtoStatsQuerySQL(QueryCondition &condition) {

        std::string sql;
        std::stringstream ss;
        ss << R"SQL(
            SELECT
                protocol,
                SUM(packet_count) AS totalPackets,
                SUM(total_bytes) AS total_bytes,
                COUNT(DISTINCT session_id) AS sessionCount
            FROM (
                SELECT session_id, trans_proto AS protocol, packet_count, total_bytes
                FROM t_sessions
                WHERE trans_proto IS NOT NULL AND trans_proto != ''
                UNION ALL
                SELECT session_id, app_proto AS protocol, packet_count, total_bytes
                FROM t_sessions
                WHERE app_proto IS NOT NULL AND app_proto != ''
            ) AS combined
            GROUP BY protocol
        )SQL";

        ss << PageHelper::getPageSql();

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());

        return sql;
    }

    // 构造协议维度统计总数 SQL。
    static std::string buildProtoStatsQuerySQL_Count(QueryCondition &condition) {
        std::string sql = buildProtoStatsQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }


    // 构造国家维度统计分页查询 SQL。
    static std::string buildCountryStatsQuerySQL(QueryCondition& condition) {

        std::string sql;
        std::stringstream ss;
        ss << R"SQL(
            SELECT 
                country,
                COUNT(DISTINCT ip) AS ipCount,
                SUM(packet_count) AS totalPackets,
                SUM(total_bytes) AS total_bytes,
                COUNT(DISTINCT session_id) AS sessionCount
            FROM (
                SELECT 
                    session_id,
                    ip1 AS ip,
                    CASE WHEN INSTR(ip1_location, '-') > 0 
                         THEN SUBSTR(ip1_location, 1, INSTR(ip1_location, '-') - 1) 
                         ELSE ip1_location END AS country,
                    packet_count,
                    total_bytes
                FROM t_sessions
                UNION ALL
                SELECT 
                    session_id,
                    ip2 AS ip,
                    CASE WHEN INSTR(ip2_location, '-') > 0 
                         THEN SUBSTR(ip2_location, 1, INSTR(ip2_location, '-') - 1) 
                         ELSE ip2_location END AS country,
                    packet_count,
                    total_bytes
                FROM t_sessions
            ) t
            GROUP BY country
        )SQL";

        ss << PageHelper::getPageSql();

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());

        return sql;
    }

    // 构造国家维度统计总数 SQL。
    static std::string buildCountryStatsQuerySQL_Count(QueryCondition& condition) {
        std::string sql = buildCountryStatsQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }
};

#endif //TSHARK_SERVER_STATS_SQL_HPP
