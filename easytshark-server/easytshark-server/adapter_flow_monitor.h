#ifndef EASYTSHARK_ADAPTER_FLOW_MONITOR_H
#define EASYTSHARK_ADAPTER_FLOW_MONITOR_H

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

// 周期采样各网卡流量并维护趋势数据。
class AdapterFlowMonitor {
public:
    // 启动后台采样线程。
    void start();
    // 停止后台采样线程并等待退出。
    void stop();
    // 清空已采集的网卡流量趋势数据。
    void clear();
    // 复制当前流量趋势数据给调用方。
    void getData(std::map<std::string, std::map<long, long>>& flowTrendData);

private:
    // 后台线程入口，定时采样并写入趋势表。
    void threadEntry();

    std::shared_ptr<std::thread> workerThread;
    std::map<std::string, std::map<long, long>> flowTrendDataMap;
    std::recursive_mutex flowTrendMapLock;
    std::atomic<bool> stopFlag{ true };
    long monitorStartTime = 0;
};

#endif // EASYTSHARK_ADAPTER_FLOW_MONITOR_H
