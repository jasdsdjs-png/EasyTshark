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

class TsharkManager {
public:
    TsharkManager(std::string workDir, std::string dbPath = "");
    ~TsharkManager();

    void reset();
    WORK_STATUS getWorkStatus();

    bool analysisFile(std::string filePath);
    bool startCapture(std::string adapterName);
    bool stopCapture();

    void printAllPackets();
    void printAllSessions();

    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

    std::vector<AdapterInfo> getNetworkAdapters();
    void startMonitorAdaptersFlowTrend();
    void stopMonitorAdaptersFlowTrend();
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);
    void clearFlowTrendData();

    bool getPacketDetailInfo(uint32_t frameNumber, rapidjson::Document& detailJson);
    bool convertToPcap(const std::string& inputFile, const std::string& outputFile);
    bool savePacket(std::string savePath);

    void writeMetricsJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator);

    void setActiveAnalysisManager(std::shared_ptr<TsharkManager> manager);
    std::shared_ptr<TsharkManager> getActiveAnalysisManager();

    void queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>>& packets, int& total);
    void querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total);
    bool getIPStatsList(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>>& ipStatsList, int& total);
    bool getProtoStatsList(QueryCondition& condition, std::vector<std::shared_ptr<ProtoStatsInfo>>& protoStatsList, int& total);
    bool getCountryStatsList(QueryCondition& condition, std::vector<std::shared_ptr<CountryStatsInfo>>& countryStatsList, int& total);
    DataStreamCountInfo getSessionDataStream(uint32_t sessionId, std::vector<DataStreamItem>& dataStreamList);

private:
    void captureWorkThreadEntry(std::string adapterName);
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
    std::atomic<bool> stopFlag{ true };

    std::shared_ptr<TsharkDatabase> storage;
    TsharkTranslator translator;

    std::unique_ptr<TsharkCommandService> commandService;
    std::unique_ptr<SessionAggregator> sessionAggregator;
    std::unique_ptr<StorageQueue> storageQueue;
    std::unique_ptr<AdapterFlowMonitor> adapterFlowMonitor;
};

#endif // TSHARKMANAGER_H
