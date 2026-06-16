#include "adapter_flow_monitor.h"

#include "network_stats_util.hpp"
#include "third_library/loguru/loguru.hpp"

#include <climits>
#include <chrono>
#include <ctime>

void AdapterFlowMonitor::start() {
    {
        std::unique_lock<std::recursive_mutex> lock(flowTrendMapLock);
        flowTrendDataMap.clear();
        monitorStartTime = static_cast<long>(time(nullptr));
    }

    stopFlag = false;
    workerThread = std::make_shared<std::thread>(&AdapterFlowMonitor::threadEntry, this);
}

void AdapterFlowMonitor::stop() {
    stopFlag = true;
    if (workerThread && workerThread->joinable()) {
        workerThread->join();
    }
    workerThread.reset();
}

void AdapterFlowMonitor::clear() {
    std::unique_lock<std::recursive_mutex> lock(flowTrendMapLock);
    flowTrendDataMap.clear();
}

void AdapterFlowMonitor::getData(std::map<std::string, std::map<long, long>>& flowTrendData) {
    long timeNow = static_cast<long>(time(nullptr));
    long startWindow = timeNow - monitorStartTime > 300 ? timeNow - 300 : monitorStartTime;
    long endWindow = timeNow - monitorStartTime > 300 ? timeNow : monitorStartTime + 300;

    std::unique_lock<std::recursive_mutex> lock(flowTrendMapLock);
    for (const auto& adapterFlowPair : flowTrendDataMap) {
        flowTrendData.insert(std::make_pair(adapterFlowPair.first, std::map<long, long>()));
        for (long t = startWindow; t <= endWindow; t++) {
            auto it = adapterFlowPair.second.find(t);
            flowTrendData[adapterFlowPair.first][t] = it != adapterFlowPair.second.end() ? it->second : 0;
        }
    }
}

void AdapterFlowMonitor::threadEntry() {
    LOG_F(INFO, "start adapter flow monitor thread");

    auto before = NetworkStatsUtil::getSnapshot();
    while (!stopFlag) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto after = NetworkStatsUtil::getSnapshot();
        auto delta = NetworkStatsUtil::calculateDelta(before, after, 1);
        long currentTimestamp = static_cast<long>(time(nullptr));

        {
            std::unique_lock<std::recursive_mutex> lock(flowTrendMapLock);
            for (const auto& adapterCounterPair : delta) {
                unsigned long long totalBytes = adapterCounterPair.second.ibytes + adapterCounterPair.second.obytes;
                long bytesPerSecond = totalBytes > static_cast<unsigned long long>(LONG_MAX)
                    ? LONG_MAX
                    : static_cast<long>(totalBytes);

                std::map<long, long>& trafficPerSecond = flowTrendDataMap[adapterCounterPair.first];
                trafficPerSecond[currentTimestamp] = bytesPerSecond;
                while (trafficPerSecond.size() > 300) {
                    trafficPerSecond.erase(trafficPerSecond.begin());
                }
            }
        }

        before = after;
    }

    LOG_F(INFO, "adapter flow monitor thread finished");
}
