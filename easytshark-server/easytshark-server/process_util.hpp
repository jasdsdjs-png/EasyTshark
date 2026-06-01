//
// Created by xuanyuan on 24-10-19.
//

#ifndef PROCESSUTIL_H
#define PROCESSUTIL_H

#include <stdio.h>
#include <string>

#ifdef _WIN32
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <csignal>
#include <tlhelp32.h>
typedef DWORD PID_T;
#else
#include <unistd.h>
#include <signal.h>
#include <limits.h>
typedef pid_t PID_T;
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <limits.h>
#endif


#include "misc_util.hpp"


class ProcessUtil {

public:
    // Linux/Mac版本
#if defined(__unix__) || defined(__APPLE__)
    static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr) {
        int pipefd[2] = { 0 };
        FILE* pipeFp = nullptr;

        if (pipe(pipefd) == -1) {
            perror("pipe");
            return nullptr;
        }

        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            return nullptr;
        }

        if (pid == 0) {
            // 子进程
            close(pipefd[0]);  // 关闭读端
            dup2(pipefd[1], STDOUT_FILENO); // 将 stdout 重定向到管道
            dup2(pipefd[1], STDERR_FILENO); // 将 stderr 重定向到管道
            close(pipefd[1]);

            execl("/bin/sh", "sh", "-c", command.c_str(), NULL);  // 执行命令
            _exit(1);  // execl失败
        }

        // 父进程将读取管道，关闭写端
        close(pipefd[1]);
        pipeFp = fdopen(pipefd[0], "r");

        if (pidOut) {
            *pidOut = pid;
        }

        return pipeFp;
    }

    static int Kill(PID_T pid) {

//        int ret = 0;
//        while (true) {
//            int x = kill(pid, 0);
//            if (x == 0) {
//                ret = kill(pid, SIGTERM);
//                std::this_thread::sleep_for(std::chrono::milliseconds(1));
//            } else {
//                break;
//            }
//        }
//        return ret;
        return kill(pid, SIGTERM);
    }

    // 批量根据进程名杀死进程
    static void KillAll(const char* name) {
        std::string cmd = "killall -9 ";
        cmd += name;
        std::system(cmd.c_str());
    }

    static PID_T WaitPid(PID_T pid, int* status, int options) {
        return waitpid(pid, status, options);
    }

    static void SetCurrentThreadName(std::string name) {
        pthread_setname_np(name.c_str());
    }

#endif
#ifdef _WIN32
    // Windows 版本
    static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr) {

        //  Windows平台要转换，否则执行tshark时候，命令行参数有中文（比如网卡名）会乱码
        command = MiscUtil::UTF8ToANSIString(command);

        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES saAttr;
        PROCESS_INFORMATION piProcInfo;
        STARTUPINFO siStartInfo;
        FILE* pipeFp = nullptr;

        // 设置安全属性，允许管道句柄继承
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = nullptr;

        // 创建匿名管道
        if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
            perror("CreatePipe");
            return nullptr;
        }

        // 确保写句柄不被子进程继承
        if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
            perror("SetHandleInformation");
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return nullptr;
        }

        // 初始化 STARTUPINFO 结构体
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
        siStartInfo.cb = sizeof(STARTUPINFO);
        siStartInfo.hStdError = hWritePipe;
        siStartInfo.hStdOutput = hWritePipe;
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

        // 创建子进程
        if (!CreateProcess(
            nullptr,                        // No module name (use command line)
            (LPSTR)command.data(),          // Command line
            nullptr,                        // Process handle not inheritable
            nullptr,                        // Thread handle not inheritable
            TRUE,                           // Set handle inheritance
            CREATE_NO_WINDOW,               // No window
            nullptr,                        // Use parent's environment block
            nullptr,                        // Use parent's starting directory 
            &siStartInfo,                   // Pointer to STARTUPINFO structure
            &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
        )) {
            perror("CreateProcess");
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return nullptr;
        }

        // 关闭写端句柄（父进程不使用）
        CloseHandle(hWritePipe);

        // 返回子进程 PID
        if (pidOut) {
            *pidOut = piProcInfo.dwProcessId;
        }

        // 将管道的读端转换为 FILE* 并返回
        pipeFp = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(hReadPipe), _O_RDONLY), "r");
        if (!pipeFp) {
            CloseHandle(hReadPipe);
        }

        // 关闭进程句柄（不需要等待子进程）
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);

        return pipeFp;
    }

    static int Kill(PID_T pid) {

        // 打开指定进程
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == nullptr) {
            std::cout << "Failed to open process with PID " << pid << ", error: " << GetLastError() << std::endl;
            return -1;
        }

        // 终止进程
        if (!TerminateProcess(hProcess, 0)) {
            std::cout << "Failed to terminate process with PID " << pid << ", error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        // 成功终止进程
        CloseHandle(hProcess);
        return 0;
    }

    static void KillAll(const char* name) {
        // 获取系统所有进程的快照
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            std::cerr << "创建进程快照失败." << std::endl;
            return;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        // 获取第一个进程的信息
        if (Process32First(hSnap, &pe)) {
            do {
                // 比较进程名，注意：pe.szExeFile 为 char 数组
                if (_stricmp(name, pe.szExeFile) == 0) {
                    Kill(pe.th32ProcessID);
                }
            } while (Process32Next(hSnap, &pe));
        }
        else {
            std::cerr << "无法检索进程信息." << std::endl;
            CloseHandle(hSnap);
        }

        CloseHandle(hSnap);
    }


    // 模拟 Linux 的 waitpid 函数
    static PID_T WaitPid(PID_T pid, int* status, int options) {
        if (pid <= 0 || options != 0) {
            std::cout << "Unsupported options or invalid PID." << std::endl;
            return -1;
        }

        // 打开指定进程的句柄
        HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            std::cout << "Failed to open process with PID " << pid << ", error: " << GetLastError() << std::endl;
            return -1;
        }

        // 等待进程退出
        DWORD waitResult = WaitForSingleObject(hProcess, INFINITE);
        if (waitResult != WAIT_OBJECT_0) {
            std::cout << "WaitForSingleObject failed, error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        // 获取进程退出代码
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode)) {
            if (status) {
                *status = (exitCode & 0xFF);
            }
        }
        else {
            std::cout << "Failed to get exit code, error: " << GetLastError() << std::endl;
        }

        CloseHandle(hProcess);
        return pid;
    }

    static void SetCurrentThreadName(std::string name) {
        std::wstring wname = MiscUtil::ANSIToUnicode(name);
        SetThreadDescription(GetCurrentThread(), wname.c_str());
    }

#endif

    static bool isProcessRunning(PID_T pid) {
#ifdef _WIN32
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (process == NULL) {
            return false;
        }
        DWORD exitCode;
        if (GetExitCodeProcess(process, &exitCode)) {
            CloseHandle(process);
            return (exitCode == STILL_ACTIVE);
        }
        CloseHandle(process);
        return false;
#else
        // On Unix-like systems, sending signal 0 to a process checks if it exists
        int ret = kill(pid, 0);
        return (ret == 0);
#endif
    }

    static std::string getExecutablePath() {
#if defined(_WIN32)
        char buffer[MAX_PATH];
        DWORD length = GetModuleFileNameA(NULL, buffer, MAX_PATH);
        return std::string(buffer, length);
#elif defined(__APPLE__)
        char buffer[PATH_MAX];
        uint32_t size = sizeof(buffer);
        if (_NSGetExecutablePath(buffer, &size) == 0)
            return std::string(buffer);
        else {
            // 分配足够大小的缓冲区
            char* buf = new char[size];
            _NSGetExecutablePath(buf, &size);
            std::string path(buf);
            delete[] buf;
            return path;
        }
#elif defined(__linux__)
        char buffer[PATH_MAX];
        ssize_t length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
        if (length != -1) {
            buffer[length] = '\0'; // 添加结束符
            return std::string(buffer);
        }
        return std::string();
#endif
    }

    static std::string getExecutableDir() {
        std::string fullPath = getExecutablePath();
        // 查找最后一个斜杠或反斜杠的位置
        size_t pos = fullPath.find_last_of("/\\");
        if (pos != std::string::npos)
            return fullPath.substr(0, pos + 1);
        return std::string();
    }

    // 封装一下执行命令行程序，将控制台窗口隐藏
    static bool Exec(std::string cmdline) {
#ifdef _WIN32
        PROCESS_INFORMATION piProcInfo;
        STARTUPINFO siStartInfo;

        // 初始化 STARTUPINFO 结构体
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));

        // 创建子进程
        if (CreateProcess(
            nullptr,                        // No module name (use command line)
            (LPSTR)cmdline.data(),          // Command line
            nullptr,                        // Process handle not inheritable
            nullptr,                        // Thread handle not inheritable
            TRUE,                           // Set handle inheritance
            CREATE_NO_WINDOW,               // No window
            nullptr,                        // Use parent's environment block
            nullptr,                        // Use parent's starting directory
            &siStartInfo,                   // Pointer to STARTUPINFO structure
            &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
        )) {
            WaitForSingleObject(piProcInfo.hProcess, INFINITE);
            CloseHandle(piProcInfo.hProcess);
            CloseHandle(piProcInfo.hThread);
            return true;
        }
        else {
            return false;
        }
#else
        return std::system(cmdline.c_str()) == 0;
#endif
    }

    // 判断进程是否为单例
    static bool IsSingleton() {
#ifdef _WIN32
        // 使用命名互斥体确保只有一个进程实例运行
        HANDLE hMutex = CreateMutex(NULL, TRUE, "__EASYTSHARK_MUTEX__");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            // 互斥体已经存在，说明另一个实例已经运行
            return false;
        }
#else
        // 在 Linux 下采用文件锁的方式
        // 这里将锁文件放在 /tmp 目录中，也可根据需要选择其他路径
        int fd = open("/tmp/easytshark.lock", O_CREAT | O_RDWR, 0666);
        if (fd < 0) {
            LOG_F(ERROR, "无法打开锁文件");
            return false;
        }
        // 使用 lockf 尝试加锁，如果加锁失败则说明已经有进程持有该锁
        if (lockf(fd, F_TLOCK, 0) < 0) {
            close(fd);
            return false;
        }
        // 注意：为了使锁保持有效，不要在进程生命周期中关闭 fd
#endif
        return true;
    }

};



#endif //PROCESSUTIL_H
