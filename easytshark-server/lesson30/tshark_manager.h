//
// Created by xuanyuan on 2025/2/16.
//

#ifndef TSHARKMANAGER_H
#define TSHARKMANAGER_H
#include "tshark_datatype.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"
#include "process_util.hpp"
#include "tshark_translate.hpp"
#include "tshark_database.hpp"
#include "tshark_datatype.h"
#include "network_stats_util.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <thread>
#include <set>
#include <map>
#include <unordered_map>
#include <mutex>

enum WORK_STATUS {
    STATUS_IDLE = 0,                    // 空闲状态
    STATUS_ANALYSIS_FILE = 1,           // 离线分析文件中
    STATUS_CAPTURING = 2,               // 在线采集抓包中
    STATUS_MONITORING = 3               // 监控网卡流量中
};


class TsharkManager {

public:
    TsharkManager(std::string workDir);
    ~TsharkManager();

    // 重置数据
    void reset();

    WORK_STATUS getWorkStatus();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 开始抓包
    bool startCapture(std::string adapterName);

    // 停止抓包
    bool stopCapture();

    // 打印所有数据包的信息
    void printAllPackets();

    // 打印所有会话的信息
    void printAllSessions();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

    // 枚举网卡列表
    std::vector<AdapterInfo> getNetworkAdapters();

    // 开始监控所有网卡流量统计数据
    void startMonitorAdaptersFlowTrend();

    // 停止监控所有网卡流量统计数据
    void stopMonitorAdaptersFlowTrend();

    // 获取所有网卡流量统计数据
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

    // 清空流量监控数据
    void clearFlowTrendData();

    // 获取数据包详细信息
    bool getPacketDetailInfo(uint32_t frameNumber, rapidjson::Document& detailJson);

    // 文件格式转换为PCAP格式
    bool convertToPcap(const std::string& inputFile, const std::string& outputFile);

    // 保存当前数据包
    bool savePacket(std::string savePath);

    
    // -----------------------------数据查询相关接口-----------------------------------
    void queryPackets(QueryCondition &queryConditon, std::vector<std::shared_ptr<Packet>> &packets, int& total);

    // 查询会话列表数据
    void querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>> &sessionList, int& total);

    // 查询IP通信统计列表数据
    bool getIPStatsList(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>> &ipStatsList, int& total);

    // 查询协议统计列表数据
    bool getProtoStatsList(QueryCondition& condition, std::vector<std::shared_ptr<ProtoStatsInfo>> &protoStatsList, int& total);

    // 查询国家统计列表数据
    bool getCountryStatsList(QueryCondition& condition, std::vector<std::shared_ptr<CountryStatsInfo>> &countryStatsList, int& total);

    // 获取会话数据流
    DataStreamCountInfo getSessionDataStream(uint32_t sessionId, std::vector<DataStreamItem>& dataStreamList);


private:

    // 在线采集数据包的工作线程
    void captureWorkThreadEntry(std::string adapterName);

    // 后台负责监控网卡流量数据的工作线程函数
    void adapterFlowTrendMonitorThreadEntry();

    // 解析每一行
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

    // 处理每一个数据包
    void processPacket(std::shared_ptr<Packet> packet);

    // 负责存储数据包的线程函数
    void storageThreadEntry();

private:

    // 工作状态
    WORK_STATUS workStatus = STATUS_IDLE;
    std::recursive_mutex workStatusLock;

    std::string workDir;
    std::string tsharkPath;
    std::string editcapPath;


    // 在线分析线程
    std::shared_ptr<std::thread> captureWorkThread;

    // 在线抓包的tshark进程PID
    PID_T captureTsharkPid;

    // 是否停止抓包的标记
    bool stopFlag;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;

    // 会话表
    std::unordered_map<FiveTuple, std::shared_ptr<Session>, FiveTupleHash> sessionMap;
    std::map<uint32_t, std::shared_ptr<Session>> sessionIdMap;

    // 等待存储入库的数据
    std::vector<std::shared_ptr<Packet>> packetsTobeStore;

    // 等待存储入库的会话列表，使用unordered_set，自动去重
    std::unordered_set<std::shared_ptr<Session>> sessionSetTobeStore;

    // 访问待存储数据的锁
    std::mutex storeLock;

    // 存储线程，负责将获取到的数据包和会话信息存储入库
    std::shared_ptr<std::thread> storageThread;

    // 数据库存储
    std::shared_ptr<TsharkDatabase> storage;

    // 字段翻译工具
    TsharkTranslator translator;


    // -----------------------------以下与网卡流量趋势监控有关-----------------------------------
    std::shared_ptr<std::thread> adapterFlowTrendMonitorThread;

    std::map<std::string, std::map<long, long>> adapterFlowTrendDataMap;

    // 访问上面流量趋势数据的锁
    std::recursive_mutex adapterFlowTrendMapLock;

    std::atomic<bool> adapterFlowTrendMonitorStopFlag{ true };

    // 网卡流量监控的开始时间
    long adapterFlowTrendMonitorStartTime = 0;
};



#endif //TSHARKMANAGER_H
