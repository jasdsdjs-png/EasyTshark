#ifndef PAGE_HELPER_H
#define PAGE_HELPER_H

#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <set>

class PageAndOrder {
public:
    void reset() {
        pageNum = 0;
        pageSize = 0;
        orderBy = "";
        descOrAsc = "";
    }
    int pageNum = 0;
    int pageSize = 0;
    std::string orderBy;
    std::string descOrAsc;
};

class PageHelper {
public:
    static PageAndOrder* getPageAndOrder() {
        return &pageAndOrder;
    }

    static std::string getPageSql() {
        std::stringstream ss;
        const std::string orderBy = sanitizeOrderBy(pageAndOrder.orderBy);
        const std::string descOrAsc = sanitizeDescOrAsc(pageAndOrder.descOrAsc);
        if (!orderBy.empty()) {
            ss << " ORDER BY " << orderBy << " " << descOrAsc;
        }
        int pageNum = std::max(1, pageAndOrder.pageNum);
        int pageSize = std::min(std::max(1, pageAndOrder.pageSize), 1000);
        int offset = (pageNum - 1) * pageSize;
        ss << " LIMIT " << pageSize << " OFFSET " << offset << ";";

        return ss.str();
    }

private:
    static std::string sanitizeOrderBy(const std::string& value) {
        static const std::set<std::string> allowedColumns = {
            "frame_number", "time", "cap_len", "len", "src_ip", "src_port",
            "dst_ip", "dst_port", "protocol", "belong_session_id",
            "session_id", "ip1", "ip1_port", "ip2", "ip2_port",
            "trans_proto", "app_proto", "start_time", "end_time",
            "packet_count", "total_bytes", "ip", "country", "proto"
        };
        return allowedColumns.find(value) == allowedColumns.end() ? "" : value;
    }

    static std::string sanitizeDescOrAsc(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
        return value == "desc" ? "desc" : "asc";
    }

    static thread_local PageAndOrder pageAndOrder;
};

#endif
