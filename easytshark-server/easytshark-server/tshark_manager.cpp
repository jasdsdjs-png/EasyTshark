#include "tshark_manager.h"

#include "adapter_flow_monitor.h"
#include "misc_util.hpp"
#include "packet_parser.h"
#include "session_aggregator.h"
#include "storage_queue.h"
#include "third_library/loguru/loguru.hpp"
#include "tshark_command_service.h"

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#define EASYTSHARK_FCLOSE fclose

TsharkManager::TsharkManager(std::string workDir, std::string dbPath) {
    this->workDir = workDir;
    this->dbPath = dbPath.empty() ? (this->workDir + "/mytshark.db") : dbPath;
    std::string xdbPath = workDir + "ip2region.xdb";

    commandService = std::make_unique<TsharkCommandService>(workDir);
    sessionAggregator = std::make_unique<SessionAggregator>();
    storageQueue = std::make_unique<StorageQueue>();
    adapterFlowMonitor = std::make_unique<AdapterFlowMonitor>();

    storage = std::make_shared<TsharkDatabase>(this->dbPath);
    IP2RegionUtil::init(xdbPath);
}

TsharkManager::~TsharkManager() {
    stopFlag = true;
    if (storageQueue) {
        storageQueue->stop(stopFlag);
    }
    if (captureTsharkPid != 0) {
        ProcessUtil::Kill(captureTsharkPid);
    }
    if (captureWorkThread && captureWorkThread->joinable()) {
        captureWorkThread->join();
    }
    if (adapterFlowMonitor) {
        adapterFlowMonitor->stop();
    }
}

WORK_STATUS TsharkManager::getWorkStatus() {
    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    return workStatus;
}

void TsharkManager::reset() {
    LOG_F(INFO, "reset called");
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        activeAnalysisManager.reset();
    }

    if (workStatus == STATUS_CAPTURING) {
        stopCapture();
    }
    else if (workStatus == STATUS_MONITORING) {
        stopMonitorAdaptersFlowTrend();
    }
    else {
        stopFlag = true;
        storageQueue->stop(stopFlag);
    }

    if (captureWorkThread && captureWorkThread->joinable()) {
        captureWorkThread->join();
        captureWorkThread.reset();
    }

    workStatus = STATUS_IDLE;
    captureTsharkPid = 0;
    stopFlag = true;
    sessionAggregator->clear();
    storageQueue->clear();

    if (!currentFilePath.empty()) {
        remove(currentFilePath.c_str());
    }
    currentFilePath = "";

    storage.reset();
    std::string dbFullPath = this->dbPath;
    remove(dbFullPath.c_str());
    storage = std::make_shared<TsharkDatabase>(dbFullPath);
}

bool TsharkManager::analysisFile(std::string filePath) {
    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    reset();

    currentFilePath = MiscUtil::getPcapNameByCurrentTimestamp();
    if (!convertToPcap(filePath, currentFilePath)) {
        LOG_F(ERROR, "convert to pcap failed");
        return false;
    }

    std::unique_ptr<FILE, decltype(&EASYTSHARK_FCLOSE)> pipe(commandService->openAnalysisPipe(currentFilePath), EASYTSHARK_FCLOSE);
    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return false;
    }

    workStatus = STATUS_ANALYSIS_FILE;
    stopFlag = false;
    storageQueue->start(storage, stopFlag);

    uint32_t fileOffset = sizeof(PcapHeader);
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!PacketParser::parseLine(buffer, packet)) {
            LOG_F(ERROR, "tshark output parse error: %s", buffer);
            continue;
        }

        packet->file_offset = fileOffset + sizeof(PacketHeader);
        fileOffset = fileOffset + sizeof(PacketHeader) + packet->cap_len;
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        processPacket(packet);
    }

    pipe.reset();
    storageQueue->stop(stopFlag);
    workStatus = STATUS_IDLE;

    LOG_F(INFO, "analysis finished, packet count: %zu", sessionAggregator->packetCount());
    return true;
}

bool TsharkManager::startCapture(std::string adapterName) {
    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    reset();
    LOG_F(INFO, "start capture, adapter: %s", adapterName.c_str());

    stopFlag = false;
    workStatus = STATUS_CAPTURING;
    storageQueue->start(storage, stopFlag);
    captureWorkThread = std::make_shared<std::thread>(&TsharkManager::captureWorkThreadEntry, this, adapterName);
    return true;
}

bool TsharkManager::stopCapture() {
    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    LOG_F(INFO, "stop capture");

    stopFlag = true;
    storageQueue->notifyAll();
    if (captureTsharkPid != 0) {
        ProcessUtil::Kill(captureTsharkPid);
    }

    if (captureWorkThread && captureWorkThread->joinable()) {
        captureWorkThread->join();
        captureWorkThread.reset();
    }

    storageQueue->stop(stopFlag);
    workStatus = STATUS_IDLE;
    return true;
}

void TsharkManager::captureWorkThreadEntry(std::string adapterName) {
    currentFilePath = MiscUtil::getPcapNameByCurrentTimestamp();

    std::unique_ptr<FILE, decltype(&EASYTSHARK_FCLOSE)> pipe(
        commandService->openCapturePipe(adapterName, currentFilePath, &captureTsharkPid),
        EASYTSHARK_FCLOSE
    );
    if (!pipe) {
        LOG_F(ERROR, "Failed to run tshark command!");
        return;
    }

    char buffer[4096];
    uint32_t fileOffset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr && !stopFlag) {
        std::string line = buffer;
        if (line.find("Capturing on") != std::string::npos) {
            continue;
        }

        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!PacketParser::parseLine(line, packet)) {
            LOG_F(ERROR, "tshark output parse error: %s", buffer);
            stopFlag = true;
            break;
        }

        packet->file_offset = fileOffset + sizeof(PacketHeader);
        fileOffset = fileOffset + sizeof(PacketHeader) + packet->cap_len;
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        processPacket(packet);
    }

    if (stopFlag && workStatus == STATUS_CAPTURING) {
        std::unique_lock<std::recursive_mutex> lock(workStatusLock, std::try_to_lock);
        if (lock.owns_lock()) {
            workStatus = STATUS_IDLE;
        }
    }
}

void TsharkManager::processPacket(std::shared_ptr<Packet> packet) {
    std::shared_ptr<Session> session = sessionAggregator->processPacket(packet);
    storageQueue->enqueue(packet, session, stopFlag);
}

void TsharkManager::printAllPackets() {
    sessionAggregator->forEachPacket([](const std::shared_ptr<Packet>& packet) {
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", packet->time, allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);
        std::cout << buffer.GetString() << std::endl;
    });
}

void TsharkManager::printAllSessions() {
    sessionAggregator->forEachSession([](const std::shared_ptr<Session>& session) {
        rapidjson::Document doc(rapidjson::kObjectType);
        session->toJsonObj(doc, doc.GetAllocator());

        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        std::cout << buffer.GetString() << std::endl;
    });
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data) {
    std::shared_ptr<Packet> packet;
    if (!sessionAggregator->getPacket(frameNumber, packet)) {
        std::cerr << "packet not found, frame number: " << frameNumber << std::endl;
        return false;
    }

    std::ifstream file(currentFilePath, std::ios::binary);
    if (!file) {
        std::cerr << "failed to open file: " << currentFilePath << std::endl;
        return false;
    }

    file.seekg(packet->file_offset, std::ios::beg);
    if (!file) {
        std::cerr << "seekg failed, packet offset may be out of file range" << std::endl;
        return false;
    }

    data.resize(packet->cap_len);
    file.read(reinterpret_cast<char*>(data.data()), packet->cap_len);
    return true;
}

std::vector<AdapterInfo> TsharkManager::getNetworkAdapters() {
    return commandService->getNetworkAdapters();
}

void TsharkManager::clearFlowTrendData() {
    adapterFlowMonitor->clear();
}

void TsharkManager::startMonitorAdaptersFlowTrend() {
    reset();
    adapterFlowMonitor->start();
    workStatus = STATUS_MONITORING;
}

void TsharkManager::stopMonitorAdaptersFlowTrend() {
    adapterFlowMonitor->stop();
    workStatus = STATUS_IDLE;
}

void TsharkManager::getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData) {
    adapterFlowMonitor->getData(flowTrendData);
}

bool TsharkManager::getPacketDetailInfo(uint32_t frameNumber, rapidjson::Document& detailJson) {
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        if (activeAnalysisManager) {
            return activeAnalysisManager->getPacketDetailInfo(frameNumber, detailJson);
        }
    }

    return commandService->getPacketDetailInfo(
        currentFilePath,
        frameNumber,
        translator,
        [this](uint32_t packetFrameNumber, std::vector<unsigned char>& packetData) {
            return getPacketHexData(packetFrameNumber, packetData);
        },
        detailJson
    );
}

bool TsharkManager::convertToPcap(const std::string& inputFile, const std::string& outputFile) {
    return commandService->convertToPcap(inputFile, outputFile);
}

void TsharkManager::queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>>& packets, int& total) {
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        if (activeAnalysisManager) {
            activeAnalysisManager->queryPackets(queryConditon, packets, total);
            return;
        }
    }
    storage->queryPackets(queryConditon, packets, total);
}

void TsharkManager::querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total) {
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        if (activeAnalysisManager) {
            activeAnalysisManager->querySessions(condition, sessionList, total);
            return;
        }
    }
    storage->querySessions(condition, sessionList, total);
}

bool TsharkManager::getIPStatsList(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>>& ipStatsList, int& total) {
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        if (activeAnalysisManager) {
            return activeAnalysisManager->getIPStatsList(condition, ipStatsList, total);
        }
    }
    return storage->queryIPStats(condition, ipStatsList, total);
}

bool TsharkManager::getProtoStatsList(QueryCondition& condition, std::vector<std::shared_ptr<ProtoStatsInfo>>& protoStatsList, int& total) {
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        if (activeAnalysisManager) {
            return activeAnalysisManager->getProtoStatsList(condition, protoStatsList, total);
        }
    }
    return storage->queryProtoStats(condition, protoStatsList, total);
}

bool TsharkManager::getCountryStatsList(QueryCondition& condition, std::vector<std::shared_ptr<CountryStatsInfo>>& countryStatsList, int& total) {
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        if (activeAnalysisManager) {
            return activeAnalysisManager->getCountryStatsList(condition, countryStatsList, total);
        }
    }
    return storage->queryCountryStats(condition, countryStatsList, total);
}

DataStreamCountInfo TsharkManager::getSessionDataStream(uint32_t sessionId, std::vector<DataStreamItem>& dataStreamList) {
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        if (activeAnalysisManager) {
            return activeAnalysisManager->getSessionDataStream(sessionId, dataStreamList);
        }
    }

    std::shared_ptr<Session> session;
    if (!sessionAggregator->getSession(sessionId, session)) {
        LOG_F(ERROR, "session %d not found", sessionId);
        return DataStreamCountInfo();
    }

    return commandService->getSessionDataStream(currentFilePath, *session, dataStreamList);
}

bool TsharkManager::savePacket(std::string savePath) {
    {
        std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
        if (activeAnalysisManager) {
            return activeAnalysisManager->savePacket(savePath);
        }
    }
    return MiscUtil::copyFile(currentFilePath, savePath);
}

void TsharkManager::writeMetricsJson(rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator) {
    out.SetObject();
    out.AddMember("work_status", static_cast<int>(getWorkStatus()), allocator);
    out.AddMember("parsed_packets", static_cast<uint64_t>(storageQueue->parsedPackets()), allocator);
    out.AddMember("stored_packets", static_cast<uint64_t>(storageQueue->storedPackets()), allocator);
    out.AddMember("pending_packets", static_cast<uint64_t>(storageQueue->pendingPackets()), allocator);
    out.AddMember("pending_sessions", static_cast<uint64_t>(storageQueue->pendingSessions()), allocator);
    out.AddMember("storage_wakeups", static_cast<uint64_t>(storageQueue->wakeups()), allocator);
    out.AddMember("storage_backpressure_waits", static_cast<uint64_t>(storageQueue->backpressureWaits()), allocator);
    out.AddMember("store_queue_limit", static_cast<uint64_t>(storageQueue->queueLimit()), allocator);
    out.AddMember("store_batch_limit", static_cast<uint64_t>(storageQueue->batchLimit()), allocator);
    out.AddMember("packet_cache_size", static_cast<uint64_t>(sessionAggregator->packetCount()), allocator);
    out.AddMember("session_cache_size", static_cast<uint64_t>(sessionAggregator->sessionCount()), allocator);
}

void TsharkManager::setActiveAnalysisManager(std::shared_ptr<TsharkManager> manager) {
    std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
    activeAnalysisManager = manager;
}

std::shared_ptr<TsharkManager> TsharkManager::getActiveAnalysisManager() {
    std::unique_lock<std::recursive_mutex> lock(activeAnalysisManagerLock);
    return activeAnalysisManager;
}
