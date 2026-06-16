#ifndef EASYTSHARK_TSHARK_COMMAND_SERVICE_H
#define EASYTSHARK_TSHARK_COMMAND_SERVICE_H

#include "process_util.hpp"
#include "rapidjson/document.h"
#include "tshark_datatype.h"
#include "tshark_translate.hpp"

#include <functional>
#include <string>
#include <vector>

class TsharkCommandService {
public:
    explicit TsharkCommandService(const std::string& workDir);

    const std::string& tsharkPath() const;
    const std::string& editcapPath() const;

    FILE* openAnalysisPipe(const std::string& pcapPath);
    FILE* openCapturePipe(const std::string& adapterName, const std::string& outputPath, PID_T* pidOut);
    bool convertToPcap(const std::string& inputFile, const std::string& outputFile);
    std::vector<AdapterInfo> getNetworkAdapters();
    bool getPacketDetailInfo(
        const std::string& currentFilePath,
        uint32_t frameNumber,
        TsharkTranslator& translator,
        const std::function<bool(uint32_t, std::vector<unsigned char>&)>& readPacketHex,
        rapidjson::Document& detailJson);
    DataStreamCountInfo getSessionDataStream(
        const std::string& currentFilePath,
        const Session& session,
        std::vector<DataStreamItem>& dataStreamList);

private:
    std::string resolveCaptureInterface(const std::string& adapterName);
    std::string buildCommand(const std::vector<std::string>& args) const;
    std::string quoteArg(const std::string& arg) const;

    std::string tsharkExePath;
    std::string editcapExePath;
};

#endif // EASYTSHARK_TSHARK_COMMAND_SERVICE_H
