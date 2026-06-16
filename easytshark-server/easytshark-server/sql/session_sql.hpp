

#ifndef TSHARK_SERVER_SESSION_SQL_HPP
#define TSHARK_SERVER_SESSION_SQL_HPP

#include <string>
#include <sstream>
#include <iostream>
#include "../tshark_datatype.h"
#include "loguru/loguru.hpp"

class SessionSQL {
public:
    static std::string buildSessionQuerySQL(QueryCondition &condition) {

        std::string sql;
        std::stringstream ss;
        ss << "SELECT * FROM t_sessions";

        ss << " WHERE (? = '' OR app_proto LIKE ? OR trans_proto LIKE ?)";
        ss << " AND (? = '' OR ip1 = ? OR ip2 = ?)";
        ss << " AND (? = 0 OR ip1_port = ? OR ip2_port = ?)";
        ss << " AND (? = 0 OR session_id = ?)";

        ss << PageHelper::getPageSql();

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildSessionQuerySQL_Count(QueryCondition& condition) {
        std::string sql = buildSessionQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return countSql;
    }
};

#endif //TSHARK_SERVER_SESSION_SQL_HPP
