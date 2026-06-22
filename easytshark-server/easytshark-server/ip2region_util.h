//
// Created by xuanyuan on 2024/10/17.
//

#ifndef IP2REGION_UTIL_H
#define IP2REGION_UTIL_H

#include "ip2region/xdb_search.h"

#include <string>
#include <memory>

// ip2region 查询工具，负责初始化 xdb 数据并解析 IP 归属地。
class IP2RegionUtil {
public:
    // 加载 ip2region xdb 数据文件。
    static bool init(const std::string& xdbFilePath);
    // 查询 IP 的归属地文本。
    static std::string getIpLocation(const std::string& ip);

private:
    // 将 ip2region 原始结果整理为前端展示格式。
    static std::string parseLocation(const std::string& input);
    static std::shared_ptr<xdb_search_t> xdbPtr;
};

#endif //IP2REGION_UTIL_H
