#ifndef EASYTSHARK_TSHARK_COMMAND_SERVICE_H
#define EASYTSHARK_TSHARK_COMMAND_SERVICE_H

#include "process_util.hpp"
#include "rapidjson/document.h"
#include "tshark_datatype.h"
#include "tshark_translate.hpp"

#include <functional>
#include <string>
#include <vector>

// 封装 tshark/editcap 命令构造、执行和输出解析。
class TsharkCommandService {
public:
    // 根据后端工作目录定位 tshark 和 editcap 可执行文件。
    explicit TsharkCommandService(const std::string& workDir);

    // 返回 tshark 可执行文件路径。
    const std::string& tsharkPath() const;
    // 返回 editcap 可执行文件路径。
    const std::string& editcapPath() const;

    // 打开 tshark 离线分析管道并可返回子进程 PID。
    FILE* openAnalysisPipe(const std::string& pcapPath, PID_T* pidOut = nullptr);
    // 打开 tshark 实时抓包管道，把结果写到指定文件。
    FILE* openCapturePipe(const std::string& adapterName, const std::string& outputPath, PID_T* pidOut);
    // 使用 editcap 将输入文件转换为 pcap 格式。
    bool convertToPcap(const std::string& inputFile, const std::string& outputFile);
    // 调用 tshark 枚举本机网卡并解析为 AdapterInfo。
    std::vector<AdapterInfo> getNetworkAdapters();
    // 获取指定数据包的详细协议树并补充十六进制数据。
    bool getPacketDetailInfo(
        const std::string& currentFilePath,
        uint32_t frameNumber,
        TsharkTranslator& translator,
        const std::function<bool(uint32_t, std::vector<unsigned char>&)>& readPacketHex,
        rapidjson::Document& detailJson);
    // 导出指定会话的 TCP/UDP 数据流内容。
    DataStreamCountInfo getSessionDataStream(
        const std::string& currentFilePath,
        const Session& session,
        std::vector<DataStreamItem>& dataStreamList);

private:
    // 将前端网卡名解析为 tshark 可识别的接口名。
    std::string resolveCaptureInterface(const std::string& adapterName);
    // 把参数数组拼接为可执行的命令行。
    std::string buildCommand(const std::vector<std::string>& args) const;
    // 对命令行参数进行安全引用和转义。
    std::string quoteArg(const std::string& arg) const;

    std::string tsharkExePath;
    std::string editcapExePath;
};

#endif // EASYTSHARK_TSHARK_COMMAND_SERVICE_H
