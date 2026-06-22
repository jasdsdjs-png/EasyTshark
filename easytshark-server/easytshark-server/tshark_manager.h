#ifndef TSHARKMANAGER_H
#define TSHARKMANAGER_H

#include "ip2region_util.h"
#include "process_util.hpp"
#include "rapidjson/document.h"
#include "tshark_database.hpp"
#include "tshark_datatype.h"
#include "tshark_translate.hpp"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class AdapterFlowMonitor;
class SessionAggregator;
class StorageQueue;
class TsharkCommandService;

enum WORK_STATUS {
    STATUS_IDLE = 0,
    STATUS_ANALYSIS_FILE = 1,
    STATUS_CAPTURING = 2,
    STATUS_MONITORING = 3
};

// 后端核心编排器：管理抓包、离线分析、会话聚合、存储和查询。
class TsharkManager {
public:
    // 创建管理器，初始化工具路径、数据库和辅助组件。
    TsharkManager(std::string workDir, std::string dbPath = "");
    // 析构时释放抓包、分析和存储资源。
    ~TsharkManager();

    // 停止当前工作并重置到空闲状态。
    void reset();
    // 获取当前抓包、分析或监控状态。
    WORK_STATUS getWorkStatus();

    // 同步分析指定 pcap 文件并写入数据库。
    bool analysisFile(std::string filePath);
    // 请求正在运行的抓包或分析流程停止。
    void requestStop();
    // 使用指定网卡启动实时抓包。
    bool startCapture(std::string adapterName);
    // 停止实时抓包并完成文件分析入库。
    bool stopCapture();

    // 调试输出当前缓存或数据库中的全部数据包。
    void printAllPackets();
    // 调试输出当前缓存或数据库中的全部会话。
    void printAllSessions();

    // 读取指定帧号的数据包十六进制原始内容。
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

    // 枚举本机可用于抓包的网卡。
    std::vector<AdapterInfo> getNetworkAdapters();
    // 启动网卡流量趋势监控。
    void startMonitorAdaptersFlowTrend();
    // 停止网卡流量趋势监控。
    void stopMonitorAdaptersFlowTrend();
    // 获取网卡流量趋势快照。
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);
    // 清空网卡流量趋势数据。
    void clearFlowTrendData();

    // 获取指定帧号的协议树详情 JSON。
    bool getPacketDetailInfo(uint32_t frameNumber, rapidjson::Document& detailJson);
    // 调用 editcap 将输入文件转换为 pcap。
    bool convertToPcap(const std::string& inputFile, const std::string& outputFile);
    // 保存当前抓包或分析文件到指定路径。
    bool savePacket(std::string savePath);

    // 写出当前管理器的工作和存储指标。
    void writeMetricsJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator);

    // 设置当前查询使用的离线分析管理器。
    void setActiveAnalysisManager(std::shared_ptr<TsharkManager> manager);
    // 返回当前查询使用的离线分析管理器。
    std::shared_ptr<TsharkManager> getActiveAnalysisManager();

    // 按查询条件分页获取数据包列表。
    void queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>>& packets, int& total);
    // 按查询条件分页获取会话列表。
    void querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total);
    // 查询 IP 维度统计列表。
    bool getIPStatsList(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>>& ipStatsList, int& total);
    // 查询协议维度统计列表。
    bool getProtoStatsList(QueryCondition& condition, std::vector<std::shared_ptr<ProtoStatsInfo>>& protoStatsList, int& total);
    // 查询国家维度统计列表。
    bool getCountryStatsList(QueryCondition& condition, std::vector<std::shared_ptr<CountryStatsInfo>>& countryStatsList, int& total);
    // 获取指定会话的双向数据流内容和计数。
    DataStreamCountInfo getSessionDataStream(uint32_t sessionId, std::vector<DataStreamItem>& dataStreamList);

private:
    // 实时抓包工作线程入口。
    void captureWorkThreadEntry(std::string adapterName);
    // 聚合并入队保存单个解析后的数据包。
    void processPacket(std::shared_ptr<Packet> packet);

    WORK_STATUS workStatus = STATUS_IDLE;
    std::recursive_mutex workStatusLock;

    std::string workDir;
    std::string dbPath;
    std::string currentFilePath;

    std::shared_ptr<TsharkManager> activeAnalysisManager;
    std::recursive_mutex activeAnalysisManagerLock;

    std::shared_ptr<std::thread> captureWorkThread;
    PID_T captureTsharkPid = 0;
    PID_T analysisTsharkPid = 0;
    std::atomic<bool> stopFlag{ true };
    std::atomic<uint64_t> lastAnalysisDurationMs{ 0 };
    std::atomic<uint64_t> lastAnalysisPacketCount{ 0 };
    std::atomic<uint64_t> lastAnalysisStoredPackets{ 0 };
    std::atomic<uint64_t> lastAnalysisPacketsPerSecond{ 0 };

    std::shared_ptr<TsharkDatabase> storage;
    TsharkTranslator translator;

    std::unique_ptr<TsharkCommandService> commandService;
    std::unique_ptr<SessionAggregator> sessionAggregator;
    std::unique_ptr<StorageQueue> storageQueue;
    std::unique_ptr<AdapterFlowMonitor> adapterFlowMonitor;
};

#endif // TSHARKMANAGER_H

