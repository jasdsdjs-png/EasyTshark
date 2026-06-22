

#ifndef TSHARK_SERVER_TSHARK_ERRORCODE_HPP
#define TSHARK_SERVER_TSHARK_ERRORCODE_HPP

#include <map>

#define ERROR_SUCCESS           0
#define ERROR_PARAMETER_WRONG   1001
#define ERROR_INTERNAL_WRONG    1002
#define ERROR_DATABASE_WRONG    1003
#define ERROR_TSHARK_WRONG      1004
#define ERROR_STATUS_WRONG      1005
#define ERROR_FILE_TOOLARGE     1006
#define ERROR_FILE_NOTFOUND     1007
#define ERROR_FILE_SAVE_FAILED  1008

// 后端错误码到用户可读提示的映射工具。
class TsharkError {

public:
    // 根据错误码返回响应消息，未知错误码返回默认提示。
    static std::string getErrorMsg(int errorCode) {
        if (ERROR_MSG_MAP.find(errorCode) != ERROR_MSG_MAP.end()) {
            return ERROR_MSG_MAP[errorCode];
        } else {
            return "未知错误";
        }
    }

private:
    static std::map<int, std::string> ERROR_MSG_MAP;
};

std::map<int, std::string> TsharkError::ERROR_MSG_MAP = {
        {ERROR_SUCCESS, "操作成功"},
        {ERROR_PARAMETER_WRONG, "参数错误"},
        {ERROR_INTERNAL_WRONG, "内部错误"},
        {ERROR_DATABASE_WRONG, "数据库错误"},
        {ERROR_TSHARK_WRONG, "tshark执行错误"},
        {ERROR_STATUS_WRONG, "状态错误"},
        {ERROR_FILE_TOOLARGE, "文件太大了"},
        {ERROR_FILE_NOTFOUND, "文件不存在"}
};


#endif //TSHARK_SERVER_TSHARK_ERRORCODE_HPP
