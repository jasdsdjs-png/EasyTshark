//
// Created by xuanyuan on 24-10-20.
//

#ifndef MISC_UTIL_HPP
#define MISC_UTIL_HPP

#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <random>
#include <iostream>
#include <sys/stat.h>
#include <set>
#include <chrono>
#include <codecvt>
#include <rapidxml/rapidxml.hpp>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

using namespace rapidxml;
using namespace rapidjson;

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <direct.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#define make_dir(path) _mkdir(path.c_str())
#define STAT_STRUCT _stat
#define STAT_FUNC _stat
#else
#include <unistd.h>
#include <iostream>

#define STAT_STRUCT stat
#define STAT_FUNC stat
#define make_dir(path) mkdir(path.c_str(), 0755)
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

class MiscUtil {
public:

    // 获取当前 UNIX 时间戳（精确到毫秒）
    static long long getCurrentTimeMillis() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
        return milliseconds.count();
    }

    static std::string formatTimestamp(long timestamp) {
        // 创建时间结构体
        struct tm *time_info;
        char buffer[20];  // 用于存储格式化后的时间字符串

        // 将时间戳转换为本地时间
        time_t raw_time = static_cast<time_t>(timestamp);
        time_info = localtime(&raw_time);

        // 格式化时间为 YY-MM-DD hh-mm-SS 格式
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);

        // 返回 std::string
        return std::string(buffer);
    }

    // 通过当前时间戳获取一个pcap文件名
    static std::string getPcapNameByCurrentTimestamp(bool isFullPath=true) {
        // 获取当前时间
        std::time_t now = std::time(nullptr);
        std::tm* localTime = std::localtime(&now);

        // 格式化文件名
        char buffer[64];
        std::strftime(buffer, sizeof(buffer), "easytshark_%Y-%m-%d_%H-%M-%S.pcap", localTime);

        return isFullPath ? getDefaultDataDir() + std::string(buffer) : std::string(buffer);
    }

    // 通过当前时间戳获取一个日志名
    static std::string getLogNameByCurrentTimestamp() {
        // 获取当前时间
        std::time_t now = std::time(nullptr);
        std::tm* localTime = std::localtime(&now);

        // 格式化文件名
        char buffer[64];
        std::strftime(buffer, sizeof(buffer), "easytshark_%Y-%m-%d_%H-%M-%S.log", localTime);

        return getDefaultDataDir() + "logs/" + std::string(buffer);
    }


    // 获取数据存储目录
    static std::string getDefaultDataDir() {
        static std::string dir = "";
        if (!dir.empty()) {
            return dir;
        }
#ifdef _WIN32
        dir = std::string(std::getenv("APPDATA")) + "\\easytshark\\";
#else
        dir = std::string(std::getenv("HOME")) + "/easytshark/";
#endif

        createDirectory(dir);
        return dir;
    }

    static bool fileExists(const std::string& path) {
        struct stat info;
        return stat(path.c_str(), &info) == 0;
    }

    static bool directoryExists(const std::string& path) {
        struct stat info;
        return (stat(path.c_str(), &info) == 0 && (info.st_mode & S_IFDIR));
    }

    static bool createDirectory(const std::string& path) {
        // 如果目录已存在，则直接返回 true
        if (directoryExists(path)) {
            return true;
        }

        // 尝试创建父目录
        size_t pos = path.find_last_of("/\\");
        if (pos != std::string::npos) {
            std::string parentDir = path.substr(0, pos);
            if (!createDirectory(parentDir)) {
                return false;
            }
        }

        // 创建当前目录
        if (make_dir(path) == 0) {
            return true;
        } else {
            perror("Error creating directory");
            return false;
        }
    }

    static bool copyFile(const std::string& source, const std::string& destination) {
#ifdef _WIN32
        // Windows 系统使用 CopyFile 函数
    return CopyFile(source.c_str(), destination.c_str(), FALSE);
#else
        // POSIX 系统使用 open/read/write 进行拷贝
        int src = open(source.c_str(), O_RDONLY);
        if (src < 0) return false;

        int dest = open(destination.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dest < 0) {
            close(src);
            return false;
        }

        char buffer[4096];
        ssize_t bytesRead;
        while ((bytesRead = read(src, buffer, sizeof(buffer))) > 0) {
            write(dest, buffer, bytesRead);
        }

        close(src);
        close(dest);
        return true;
#endif
    }

    static bool readFile(const std::string& filename, uint32_t offset, uint32_t size, std::string& outFileContent) {
        std::vector<char> buffer(size);
        // 打开文件（以二进制方式读取）
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            return false;
        }

        // 移动到指定的偏移位置
        file.seekg(offset);
        if (!file) {
            return false;
        }

        // 读取指定大小的数据
        file.read(buffer.data(), size);
        if (!file) {
            return false;
        }

        outFileContent.assign(buffer.data(), size);
        return true;
    }

    // 获取文件大小
    static std::uint32_t getFileSize(const std::string& filePath) {
        struct STAT_STRUCT fileStat;
        if (STAT_FUNC(filePath.c_str(), &fileStat) == 0) {
            return fileStat.st_size;
        } else {
            std::cout << "Error: Could not get file size for " << filePath << std::endl;
            return -1;
        }
    }

    // 将XML转为JSON格式
    static bool xml2JSON(std::string xmlContent, Document &outJsonDoc) {

        // 解析 XML
        xml_document<> doc;
        try {
            doc.parse<0>(&xmlContent[0]);
        }
        catch (const rapidxml::parse_error& e) {
            std::cout << "XML Parsing error: " << e.what() << std::endl;
            return false;
        }

        // 创建 JSON 文档
        outJsonDoc.SetObject();
        Document::AllocatorType& allocator = outJsonDoc.GetAllocator();

        // 获取 XML 根节点
        xml_node<>* root = doc.first_node();
        if (root) {
            // 将根节点转换为 JSON
            Value root_json(kObjectType);
            xml_to_json_recursive(root_json, root, allocator);

            // 将根节点添加到 JSON 文档
            outJsonDoc.AddMember(Value(root->name(), allocator).Move(), root_json, allocator);
        }
        return true;
    }

    // 获得随机字符串
    static std::string getRandomString(size_t length) {
        const std::string chars = "abcdefghijklmnopqrstuvwxyz"
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "0123456789";
        std::random_device rd;  // 用于种子
        std::mt19937 generator(rd());  // 生成器
        std::uniform_int_distribution<> distribution(0, chars.size() - 1);

        std::string randomString;
        for (size_t i = 0; i < length; ++i) {
            randomString += chars[distribution(generator)];
        }

        return randomString;
    }

    // 将set容器中的数据合并为一个字符串
    static std::string convertSetToString(std::set<std::string> dataSets, char delim) {

        std::string result;
        for (auto item : dataSets) {
            if (result.empty()) {
                result = item;
            } else {
                result = result + delim + item;
            }
        }
        return result;
    }

    // 简单的字符串分割函数，用于将"1,2,3"之类的字符串分割为set
    static std::set<std::string> splitString(const std::string &str, char delim) {
        std::set<std::string> result;
        std::istringstream iss(str);
        std::string token;
        while (std::getline(iss, token, delim)) {
            if (!token.empty()) {
                result.insert(token);
            }
        }
        return result;
    }

    // 简单的字符串分割函数，用于将"1,2,3"之类的字符串分割为vector
    static std::vector<std::string> splitStringToVector(const std::string &str, char delim) {
        std::vector<std::string> result;
        std::istringstream iss(str);
        std::string token;
        while (std::getline(iss, token, delim)) {
            if (!token.empty()) {
                result.push_back(token);
            }
        }
        return result;
    }

    // 将分割后的string set转换为int set（用于端口列表）
    static std::set<int> toIntVector(const std::set<std::string>& strs) {
        std::set<int> ints;
        for (auto &s : strs) {
            try {
                ints.insert(std::stoi(s));
            } catch (...) {
                // 如果转换失败，可选择忽略或打印错误信息
            }
        }
        return ints;
    }

#ifdef _WIN32
    static std::wstring ANSIToUnicode(const std::string& str) {
        int size_needed = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
        if (size_needed == 0) {
            return L""; // 转换失败，返回空宽字符串
        }
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wstr[0], size_needed);
        return wstr;
    }

    // UTF-8转ANSI
    static std::string UTF8ToANSIString(const std::string& utf8Str) {
        // 获取UTF-8字符串的长度
        int utf8Length = static_cast<int>(utf8Str.length());

        // 将UTF-8转换为宽字符（UTF-16）
        int wideLength = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, nullptr, 0);
        std::wstring wideStr(wideLength, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, &wideStr[0], wideLength);

        // 将宽字符（UTF-16）转换为ANSI
        int ansiLength = WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, nullptr, 0, nullptr, nullptr);
        std::string ansiStr(ansiLength, '\0');
        WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, &ansiStr[0], ansiLength, nullptr, nullptr);

        return ansiStr;
    }


    // 转换命令行参数：从宽字符数组转换为 ANSI 数组
    static int ConvertCommandLineToArgv(LPCWSTR cmdLineW, char*** argv) {
        LPWSTR* wargv;
        int argc, i;

        wargv = CommandLineToArgvW(cmdLineW, &argc);
        if (wargv == NULL) {
            return -1;  // 解析失败
        }

        // 为 ANSI 版的 argv 分配内存（argc+1 个指针）
        int mallocSize = (argc + 1) * sizeof(char*);
        *argv = (char**)malloc(mallocSize);
        if (*argv == NULL) {
            LocalFree(wargv);
            return -1;  // 内存分配失败
        }

        // 清空分配的内存
        memset(*argv, 0, mallocSize);

        // 将每个宽字符参数转换为 ANSI 字符串
        for (i = 0; i < argc; i++) {
            int len = WideCharToMultiByte(CP_ACP, 0, wargv[i], -1,
                NULL, 0, NULL, NULL);
            if (len == 0) {
                for (int j = 0; j < i; j++) {
                    free((*argv)[j]);
                }
                free(*argv);
                LocalFree(wargv);
                return -1;  // 转换失败
            }

            (*argv)[i] = (char*)malloc(len);
            if ((*argv)[i] == NULL) {
                for (int j = 0; j < i; j++) {
                    free((*argv)[j]);
                }
                free(*argv);
                LocalFree(wargv);
                return -1;
            }
            // 执行转换
            if (WideCharToMultiByte(CP_ACP, 0, wargv[i], -1,
                (*argv)[i], len, NULL, NULL) == 0)
            {
                for (int j = 0; j <= i; j++) {
                    free((*argv)[j]);
                }
                free(*argv);
                LocalFree(wargv);
                return -1;
            }
        }
        
        LocalFree(wargv);
        return argc;
    }

    // 写入dump文件
    static void CreateMiniDump(EXCEPTION_POINTERS* pep) {
        // 获取当前进程句柄
        HANDLE hFile = CreateFile("tshark_server_crash.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateFile failed!" << std::endl;
            return;
        }

        // 获取进程句柄
        HANDLE hProcess = GetCurrentProcess();

        // 创建 dump 文件
        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ExceptionPointers = pep;
        mdei.ThreadId = GetCurrentThreadId();

        BOOL result = MiniDumpWriteDump(
            hProcess,                               // 进程句柄
            GetCurrentProcessId(),                  // 进程ID
            hFile,                                  // 文件句柄
            MiniDumpNormal,                         // dump 类型
            &mdei,                                  // 异常信息
            NULL,                                   // 可选的线程信息
            NULL                                    // 可选的其他信息
        );

        if (!result) {
            std::cerr << "MiniDumpWriteDump failed!" << std::endl;
        }

        CloseHandle(hFile);
    }

#endif

    static void trimEnd(std::string& str) {
        if (str.size() >= 2 && str.substr(str.size() - 2) == "\r\n") {
            str.erase(str.size() - 2);  // 删除末尾的 \r\n
        }
        else if (!str.empty() && str.back() == '\n') {
            str.erase(str.size() - 1);  // 删除末尾的 \n
        }
    }

private:
    static void xml_to_json_recursive(Value& json, xml_node<>* node, Document::AllocatorType& allocator) {
        for (xml_node<>* cur_node = node->first_node(); cur_node; cur_node = cur_node->next_sibling()) {

            // 检查是否需要跳过节点
            xml_attribute<>* hide_attr = cur_node->first_attribute("hide");
            if (hide_attr && std::string(hide_attr->value()) == "yes") {
                continue;  // 如果 hide 属性值为 "true"，跳过该节点
            }

            // 检查是否已经有该节点名称的数组
            Value* array = nullptr;
            if (json.HasMember(cur_node->name())) {
                array = &json[cur_node->name()];
            }
            else {
                Value node_array(kArrayType); // 创建新的数组
                json.AddMember(Value(cur_node->name(), allocator).Move(), node_array, allocator);
                array = &json[cur_node->name()];
            }

            // 创建一个 JSON 对象代表当前节点
            Value child_json(kObjectType);

            // 处理节点的属性
            for (xml_attribute<>* attr = cur_node->first_attribute(); attr; attr = attr->next_attribute()) {
                Value attr_name(attr->name(), allocator);
                Value attr_value(attr->value(), allocator);
                child_json.AddMember(attr_name, attr_value, allocator);
            }

            // 递归处理子节点
            xml_to_json_recursive(child_json, cur_node, allocator);

            // 将当前节点对象添加到对应数组中
            array->PushBack(child_json, allocator);
        }
    }


};

#endif //MISC_UTIL_HPP
