//
// Created by xuanyuan on 2024/12/7.
//

#ifndef TSHARK_SERVER_PACKET_SQL_HPP
#define TSHARK_SERVER_PACKET_SQL_HPP

#include <string>
#include <sstream>
#include <iostream>
#include "../tshark_datatype.h"
#include "../pagehelper.h"
#include "loguru/loguru.hpp"

class PacketSQL {
public:
    static std::string buildPacketQuerySQL(QueryCondition &condition) {

        std::string sql;
        std::stringstream ss;
        ss << "SELECT * FROM t_packets";

        ss << " WHERE (? = '' OR src_ip = ? OR dst_ip = ?)";
        ss << " AND (? = 0 OR src_port = ? OR dst_port = ?)";
        ss << " AND (? = '' OR protocol = ?)";
        ss << " AND (? = 0 OR belong_session_id = ?)";

        ss << PageHelper::getPageSql();

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildPacketQuerySQL_Count(QueryCondition& condition) {
        std::string sql = buildPacketQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }
};

#endif //TSHARK_SERVER_PACKET_SQL_HPP
