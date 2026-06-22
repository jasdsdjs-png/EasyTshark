#ifndef PAGE_HELPER_H
#define PAGE_HELPER_H

#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <set>

// 当前请求线程使用的分页和排序参数。
class PageAndOrder {
public:
    // 重置分页和排序参数。
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

// 生成分页 SQL 片段，并限制可排序字段。
class PageHelper {
public:
    // 获取当前线程的分页排序参数。
    static PageAndOrder* getPageAndOrder() {
        return &pageAndOrder;
    }

    // 根据分页排序参数生成安全的 LIMIT/OFFSET/ORDER BY SQL。
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
    // 校验排序字段是否在允许列表中。
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

    // 标准化排序方向，只允许 asc 或 desc。
    static std::string sanitizeDescOrAsc(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
        return value == "desc" ? "desc" : "asc";
    }

    static thread_local PageAndOrder pageAndOrder;
};

#endif
