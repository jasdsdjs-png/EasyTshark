//
// Created by xuanyuan on 24-10-26.
//

#ifndef TSHARK_DATABASE_H
#define TSHARK_DATABASE_H

#include <iostream>
#include <list>
#include <string>
#include <sstream>
#include <mutex>
#include <chrono>
#include "sqlite3/sqlite3.h"
#include <stdexcept>
#include "tshark_datatype.h"
#include "misc_util.hpp"
#include <unordered_set>
#include "loguru/loguru.hpp"
#include "sql/packet_sql.hpp"
#include "sql/session_sql.hpp"
#include "sql/stats_sql.hpp"


// 数据库类
class TsharkDatabase {
public:
    // 构造函数，初始化数据库并创建表
    TsharkDatabase(const std::string &dbName) {

        // 删除之前的旧文件（如果有的话）
        remove(dbName.c_str());

        this->dbName = dbName;

        // 打开写连接
        if (sqlite3_open(dbName.c_str(), &db) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database");
        }
        sqlite3_busy_timeout(db, 5000);
        sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

        createPacketTable();
        createSessionTable();

        // 独立读连接用于分页/统计查询，配合 WAL 降低读写互相阻塞。
        if (sqlite3_open_v2(dbName.c_str(), &readDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to open read database");
        }
        sqlite3_busy_timeout(readDb, 5000);
    }

    // 析构函数，关闭数据库连接
    ~TsharkDatabase() {
        if (db) {
            sqlite3_close(db);
        }
        if (readDb) {
            sqlite3_close(readDb);
        }
    }


    // 存储数据包信息到表中
    bool storePackets(std::vector<std::shared_ptr<Packet>>& packets) {
        std::lock_guard<std::mutex> lock(dbMutex);

        // 开启事务
        sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

        // SQL 插入语句
        std::string insertSQL = R"(
            INSERT INTO t_packets (
                frame_number, time, cap_len, len, src_mac, dst_mac, src_ip, src_location, src_port,
                dst_ip, dst_location, dst_port, protocol, info, file_offset, belong_session_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, insertSQL.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare insert statement");
        }

        // 遍历列表并插入数据
        bool hasError = false;
        for (const auto& packet : packets) {
            sqlite3_bind_int(stmt, 1, packet->frame_number);
            sqlite3_bind_double(stmt, 2, packet->time);
            sqlite3_bind_int(stmt, 3, packet->cap_len);
            sqlite3_bind_int(stmt, 4, packet->len);
            sqlite3_bind_text(stmt, 5, packet->src_mac.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 6, packet->dst_mac.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 7, packet->src_ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 8, packet->src_location.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 9, packet->src_port);
            sqlite3_bind_text(stmt, 10, packet->dst_ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 11, packet->dst_location.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 12, packet->dst_port);
            sqlite3_bind_text(stmt, 13, packet->protocol.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 14, packet->info.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 15, packet->file_offset);
            sqlite3_bind_int(stmt, 16, packet->belong_session_id);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                
                const char* errmsg = sqlite3_errmsg(db);  // db是你的数据库连接
                LOG_F(ERROR, "Failed to execute insert statement: %s", errmsg);
                hasError = true;
                break;
            }

            sqlite3_reset(stmt); // 重置语句以便下一次绑定
        }

        if (!hasError) {

            // 结束事务
            if (sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK) {
                hasError = true;
            }

            // 释放语句
            sqlite3_finalize(stmt);
        }

        return !hasError;
    }

    // 存储会话信息到表中
    void storeAndUpdateSessions(std::unordered_set<std::shared_ptr<Session>>& sessions) {
        std::lock_guard<std::mutex> lock(dbMutex);

        // 开启事务
        sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

        // SQL UPSERT 语句
        std::string upsertSQL = R"(
            INSERT INTO t_sessions (
                session_id, ip1, ip1_location, ip1_port, ip2, ip2_location, ip2_port,
                trans_proto, app_proto, start_time, end_time,
                ip1_send_packets_count, ip1_send_bytes_count, ip2_send_packets_count, ip2_send_bytes_count,
                packet_count, total_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                trans_proto = excluded.trans_proto,
                app_proto = excluded.app_proto,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                ip1_send_packets_count = excluded.ip1_send_packets_count,
                ip1_send_bytes_count = excluded.ip1_send_bytes_count,
                ip2_send_packets_count = excluded.ip2_send_packets_count,
                ip2_send_bytes_count = excluded.ip2_send_bytes_count,
                packet_count = excluded.packet_count,
                total_bytes = excluded.total_bytes
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, upsertSQL.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare UPSERT statement");
        }

        // 遍历列表并插入或更新数据
        for (const auto& session : sessions) {
            sqlite3_bind_int(stmt, 1, session->session_id);
            sqlite3_bind_text(stmt, 2, session->ip1.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, session->ip1_location.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 4, session->ip1_port);
            sqlite3_bind_text(stmt, 5, session->ip2.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 6, session->ip2_location.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 7, session->ip2_port);
            sqlite3_bind_text(stmt, 8, session->trans_proto.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 9, session->app_proto.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_double(stmt, 10, session->start_time);
            sqlite3_bind_double(stmt, 11, session->end_time);
            sqlite3_bind_int(stmt, 12, session->ip1_send_packets_count);
            sqlite3_bind_int(stmt, 13, session->ip1_send_bytes_count);
            sqlite3_bind_int(stmt, 14, session->ip2_send_packets_count);
            sqlite3_bind_int(stmt, 15, session->ip2_send_bytes_count);
            sqlite3_bind_int(stmt, 16, session->packet_count);
            sqlite3_bind_int(stmt, 17, session->total_bytes);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                throw std::runtime_error("Failed to execute UPSERT statement");
            }

            sqlite3_reset(stmt); // 重置语句以便下一次绑定
        }

        // 结束事务
        sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);

        // 释放语句
        sqlite3_finalize(stmt);
    }


    // 从数据库查询数据包分页数据
    bool queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>> &packetList, int& total) {
        std::lock_guard<std::mutex> lock(readDbMutex);
        sqlite3_stmt *stmt = nullptr, *countStmt = nullptr;
        std::string sql = PacketSQL::buildPacketQuerySQL(queryConditon);
        auto queryStart = std::chrono::steady_clock::now();
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            LOG_F(ERROR, "Failed to prepare statement: %s", sqlite3_errmsg(readDb));
            return false;
        }

        bindPacketQueryCondition(stmt, queryConditon);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::shared_ptr<Packet> packet = std::make_shared<Packet>();
            packet->frame_number = sqlite3_column_int(stmt, 0);
            packet->time = sqlite3_column_double(stmt, 1);
            packet->cap_len = sqlite3_column_int(stmt, 2);
            packet->len = sqlite3_column_int(stmt, 3);
            packet->src_mac = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            packet->dst_mac = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            packet->src_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            packet->src_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            packet->src_port = sqlite3_column_int(stmt, 8);
            packet->dst_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
            packet->dst_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
            packet->dst_port = sqlite3_column_int(stmt, 11);
            packet->protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
            packet->info = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
            packet->file_offset = sqlite3_column_int(stmt, 14);
            packet->belong_session_id = sqlite3_column_int(stmt, 15);
            packetList.push_back(packet);
        }

        sqlite3_finalize(stmt);

        // 再查询总数total
        sql = PacketSQL::buildPacketQuerySQL_Count(queryConditon);
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &countStmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }
        bindPacketQueryCondition(countStmt, queryConditon);
        // 执行查询并获取结果
        if (sqlite3_step(countStmt) == SQLITE_ROW) {
            total = sqlite3_column_int(countStmt, 0);
        }

        sqlite3_finalize(countStmt);

        logSlowQuery("queryPackets", queryStart, sql);
        return true;
    }

    // 从数据库查询会话分页数据
    bool querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total) {
        std::lock_guard<std::mutex> lock(readDbMutex);
        sqlite3_stmt* stmt = nullptr, * countStmt = nullptr;
        std::string sql = SessionSQL::buildSessionQuerySQL(condition);
        auto queryStart = std::chrono::steady_clock::now();

        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }
        bindSessionQueryCondition(stmt, condition);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::shared_ptr<Session> session = std::make_shared<Session>();
            session->session_id = sqlite3_column_int(stmt, 0);
            session->ip1 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            session->ip1_port = sqlite3_column_int(stmt, 2);
            session->ip1_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            session->ip2 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            session->ip2_port = sqlite3_column_int(stmt, 5);
            session->ip2_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            session->trans_proto = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            session->app_proto = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            session->start_time = sqlite3_column_double(stmt, 9);
            session->end_time = sqlite3_column_double(stmt, 10);
            session->ip1_send_packets_count = sqlite3_column_int(stmt, 11);
            session->ip1_send_bytes_count = sqlite3_column_int(stmt, 12);
            session->ip2_send_packets_count = sqlite3_column_int(stmt, 13);
            session->ip2_send_bytes_count = sqlite3_column_int(stmt, 14);
            session->packet_count = sqlite3_column_int(stmt, 15);
            session->total_bytes = sqlite3_column_int(stmt, 16);

            sessionList.push_back(session);
        }

        sqlite3_finalize(stmt);

        // 再查询总数total
        sql = SessionSQL::buildSessionQuerySQL_Count(condition);
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &countStmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }
        bindSessionQueryCondition(countStmt, condition);
        // 执行查询并获取结果
        if (sqlite3_step(countStmt) == SQLITE_ROW) {
            total = sqlite3_column_int(countStmt, 0);
        }

        sqlite3_finalize(countStmt);
        logSlowQuery("querySessions", queryStart, sql);
        return true;
    }

    // IP统计查询-查询列表数据
    bool queryIPStats(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>>& ipStatsList, int& total) {
        std::lock_guard<std::mutex> lock(readDbMutex);

        sqlite3_stmt* stmt = nullptr, * countStmt = nullptr;
        std::string sql = StatsSQL::buildIPStatsQuerySQL(condition);
        auto queryStart = std::chrono::steady_clock::now();
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }
        bindIPStatsQueryCondition(stmt, condition);

        // 执行查询并输出结果
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::shared_ptr<IPStatsInfo> ipStatsInfo = std::make_shared<IPStatsInfo>();
            ipStatsInfo->ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            ipStatsInfo->location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            ipStatsInfo->earliest_time = sqlite3_column_double(stmt, 2);
            ipStatsInfo->latest_time = sqlite3_column_double(stmt, 3);
            // 处理ports
            std::string portsStr(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)));
            auto portVecStr = MiscUtil::splitString(portsStr, ',');
            ipStatsInfo->ports = MiscUtil::toIntVector(portVecStr);

            // 处理transProtos和appProtos
            std::string transProtosStr(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)));
            std::string appProtosStr(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6)));
            ipStatsInfo->protocols = MiscUtil::splitString(transProtosStr + "," + appProtosStr, ',');

            ipStatsInfo->total_sent_packets = sqlite3_column_int(stmt, 7);
            ipStatsInfo->total_sent_bytes = sqlite3_column_int(stmt, 8);
            ipStatsInfo->total_recv_packets = sqlite3_column_int(stmt, 9);
            ipStatsInfo->total_recv_bytes = sqlite3_column_int(stmt, 10);
            ipStatsInfo->tcp_session_count = sqlite3_column_int(stmt, 11);
            ipStatsInfo->udp_session_count = sqlite3_column_int(stmt, 12);

            ipStatsList.push_back(ipStatsInfo);
        }

        sqlite3_finalize(stmt);

        // 再查询总数total
        sql = StatsSQL::buildIPStatsQuerySQL_Count(condition);
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &countStmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }
        bindIPStatsQueryCondition(countStmt, condition);
        // 执行查询并获取结果
        if (sqlite3_step(countStmt) == SQLITE_ROW) {
            total = sqlite3_column_int(countStmt, 0);
        }

        sqlite3_finalize(countStmt);
        logSlowQuery("queryIPStats", queryStart, sql);
        return true;
    }

    // 协议统计查询-查询列表数据
    bool queryProtoStats(QueryCondition& condition, std::vector<std::shared_ptr<ProtoStatsInfo>>& protoStatsList, int& total) {
        std::lock_guard<std::mutex> lock(readDbMutex);

        sqlite3_stmt* stmt = nullptr, * countStmt = nullptr;
        std::string sql = StatsSQL::buildProtoStatsQuerySQL(condition);
        auto queryStart = std::chrono::steady_clock::now();
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }

        // 执行查询并输出结果
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::shared_ptr<ProtoStatsInfo> protoStatsInfo = std::make_shared<ProtoStatsInfo>();
            protoStatsInfo->proto = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            protoStatsInfo->total_packets = sqlite3_column_int(stmt, 1);
            protoStatsInfo->total_bytes = sqlite3_column_int(stmt, 2);
            protoStatsInfo->session_count = sqlite3_column_int(stmt, 3);

            protoStatsList.push_back(protoStatsInfo);
        }

        sqlite3_finalize(stmt);

        // 再查询总数total
        sql = StatsSQL::buildProtoStatsQuerySQL_Count(condition);
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &countStmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }
        // 执行查询并获取结果
        if (sqlite3_step(countStmt) == SQLITE_ROW) {
            total = sqlite3_column_int(countStmt, 0);
        }

        sqlite3_finalize(countStmt);
        logSlowQuery("queryProtoStats", queryStart, sql);
        return true;
    }


    // 国家统计查询-查询列表数据
    bool queryCountryStats(QueryCondition& condition, std::vector<std::shared_ptr<CountryStatsInfo>>& countryStatsList, int& total) {
        std::lock_guard<std::mutex> lock(readDbMutex);

        sqlite3_stmt* stmt = nullptr, * countStmt = nullptr;
        std::string sql = StatsSQL::buildCountryStatsQuerySQL(condition);
        auto queryStart = std::chrono::steady_clock::now();
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }

        // 执行查询并输出结果
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::shared_ptr<CountryStatsInfo> countryStatsInfo = std::make_shared<CountryStatsInfo>();
            countryStatsInfo->country = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            countryStatsInfo->ipCount = sqlite3_column_int(stmt, 1);
            countryStatsInfo->total_packets = sqlite3_column_int(stmt, 2);
            countryStatsInfo->total_bytes = sqlite3_column_int(stmt, 3);
            countryStatsInfo->session_count = sqlite3_column_int(stmt, 4);

            if (countryStatsInfo->country.empty()) {
                countryStatsInfo->country = "未知";
            }

            countryStatsList.push_back(countryStatsInfo);
        }

        sqlite3_finalize(stmt);

        // 再查询总数total
        sql = StatsSQL::buildCountryStatsQuerySQL_Count(condition);
        if (sqlite3_prepare_v2(readDb, sql.c_str(), -1, &countStmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(readDb) << std::endl;
            return false;
        }
        // 执行查询并获取结果
        if (sqlite3_step(countStmt) == SQLITE_ROW) {
            total = sqlite3_column_int(countStmt, 0);
        }

        sqlite3_finalize(countStmt);
        logSlowQuery("queryCountryStats", queryStart, sql);
        return true;
    }


private:

    static void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
        sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT);
    }

    static void bindPacketQueryCondition(sqlite3_stmt* stmt, const QueryCondition& condition) {
        bindText(stmt, 1, condition.ip);
        bindText(stmt, 2, condition.ip);
        bindText(stmt, 3, condition.ip);
        sqlite3_bind_int(stmt, 4, condition.port);
        sqlite3_bind_int(stmt, 5, condition.port);
        sqlite3_bind_int(stmt, 6, condition.port);
        bindText(stmt, 7, condition.proto);
        bindText(stmt, 8, condition.proto);
        sqlite3_bind_int(stmt, 9, condition.session_id);
        sqlite3_bind_int(stmt, 10, condition.session_id);
    }

    static void bindSessionQueryCondition(sqlite3_stmt* stmt, const QueryCondition& condition) {
        const std::string protoLike = "%" + condition.proto + "%";
        bindText(stmt, 1, condition.proto);
        bindText(stmt, 2, protoLike);
        bindText(stmt, 3, protoLike);
        bindText(stmt, 4, condition.ip);
        bindText(stmt, 5, condition.ip);
        bindText(stmt, 6, condition.ip);
        sqlite3_bind_int(stmt, 7, condition.port);
        sqlite3_bind_int(stmt, 8, condition.port);
        sqlite3_bind_int(stmt, 9, condition.port);
        sqlite3_bind_int(stmt, 10, condition.session_id);
        sqlite3_bind_int(stmt, 11, condition.session_id);
    }

    static void bindIPStatsQueryCondition(sqlite3_stmt* stmt, const QueryCondition& condition) {
        const std::string protoLike = "%" + condition.proto + "%";
        bindText(stmt, 1, condition.proto);
        bindText(stmt, 2, protoLike);
        bindText(stmt, 3, protoLike);
        bindText(stmt, 4, condition.ip);
        bindText(stmt, 5, condition.ip);
        sqlite3_bind_int(stmt, 6, condition.port);
        sqlite3_bind_int(stmt, 7, condition.port);
    }

    static void logSlowQuery(const char* name, std::chrono::steady_clock::time_point started, const std::string& sql) {
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        if (elapsedMs >= 200) {
            LOG_F(WARNING, "[SLOW SQL] %s took %lld ms: %s", name, static_cast<long long>(elapsedMs), sql.c_str());
        }
    }

    // 创建数据包的表
    bool createPacketTable() {
        // 检查表是否存在，若不存在则创建
        /*
        * struct Packet {
            int frame_number;
            double time;
            uint32_t cap_len;
            uint32_t len;
            std::string src_mac;
            std::string dst_mac;
            std::string src_ip;
            std::string src_location;
            uint16_t src_port;
            std::string dst_ip;
            std::string dst_location;
            uint16_t dst_port;
            std::string protocol;
            std::string info;
            uint32_t file_offset;
            uint32_t belong_session_id;
        };
        */
        std::string createTableSQL = R"(
            CREATE TABLE IF NOT EXISTS t_packets (
                frame_number INTEGER PRIMARY KEY,
                time REAL,
                cap_len INTEGER,
                len INTEGER,
                src_mac TEXT,
                dst_mac TEXT,
                src_ip TEXT,
                src_location TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_location TEXT,
                dst_port INTEGER,
                protocol TEXT,
                info TEXT,
                file_offset INTEGER,
                belong_session_id INTEGER
            );
        )";

        if (sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
            LOG_F(ERROR, "Failed to create table t_packets");
            return false;
        }
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON t_packets(src_ip);", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON t_packets(dst_ip);", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_packets_ports ON t_packets(src_port, dst_port);", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_packets_session ON t_packets(belong_session_id);", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_packets_protocol ON t_packets(protocol);", nullptr, nullptr, nullptr);

        return true;
    }

    // 创建会话表
    void createSessionTable() {
        // 检查表是否存在，若不存在则创建
        std::string createTableSQL = R"(
            CREATE TABLE IF NOT EXISTS t_sessions (
                session_id INTEGER PRIMARY KEY,
                ip1 TEXT,
                ip1_port INTEGER,
                ip1_location TEXT,
                ip2 TEXT,
                ip2_port INTEGER,
                ip2_location TEXT,
                trans_proto TEXT,
                app_proto TEXT,
                start_time REAL,
                end_time REAL,
                ip1_send_packets_count INTEGER,
                ip1_send_bytes_count INTEGER,
                ip2_send_packets_count INTEGER,
                ip2_send_bytes_count INTEGER,
                packet_count INTEGER,
                total_bytes INTEGER
            );
        )";

        if (sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to create table t_sessions");
        }
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_sessions_ip1 ON t_sessions(ip1);", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_sessions_ip2 ON t_sessions(ip2);", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_sessions_proto ON t_sessions(trans_proto, app_proto);", nullptr, nullptr, nullptr);

        // 清空表数据
        std::string clearTableSQL = "DELETE FROM t_sessions;";
        if (sqlite3_exec(db, clearTableSQL.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to clear table t_sessions");
        }
    }

private:
    sqlite3* db = nullptr; // SQLite 数据库连接
    sqlite3* readDb = nullptr;
    std::string dbName;
    std::mutex dbMutex;
    std::mutex readDbMutex;
};


#endif //TSHARK_DATABASE_H
