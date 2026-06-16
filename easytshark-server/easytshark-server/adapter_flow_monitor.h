#ifndef EASYTSHARK_ADAPTER_FLOW_MONITOR_H
#define EASYTSHARK_ADAPTER_FLOW_MONITOR_H

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

class AdapterFlowMonitor {
public:
    void start();
    void stop();
    void clear();
    void getData(std::map<std::string, std::map<long, long>>& flowTrendData);

private:
    void threadEntry();

    std::shared_ptr<std::thread> workerThread;
    std::map<std::string, std::map<long, long>> flowTrendDataMap;
    std::recursive_mutex flowTrendMapLock;
    std::atomic<bool> stopFlag{ true };
    long monitorStartTime = 0;
};

#endif // EASYTSHARK_ADAPTER_FLOW_MONITOR_H
