# EasyTshark

EasyTshark 是一个网页前端 + C++17 本地后端的网络抓包与 pcap 离线分析项目。前端只作为浏览器网页运行，后端提供本地 HTTP API，负责调用 tshark/editcap、解析数据包、聚合会话、写入 SQLite，并提供查询与诊断接口。

当前项目已经移除 Electron 桌面端，只保留：

- `easytshark-web/`：React 网页前端，运行在 `http://localhost:3000`
- `easytshark-server/`：C++17 后端，默认监听 `http://127.0.0.1:8080`

## 技术亮点

- C++17 本地 HTTP 后端：基于 cpp-httplib 注册 `/api` 接口，统一 JSON 响应格式。
- 有界分析线程池：`AnalysisThreadPool` 限制离线分析并发和排队长度，并暴露 submitted/completed/rejected 等指标。
- 异步批量落库：`StorageQueue` 将解析线程和 SQLite 写入解耦，支持批量写入、背压等待、pending 峰值统计。
- SQLite WAL 读写分离：写连接负责事务批量写入，读连接服务分页和统计查询，减少读写互相阻塞。
- 会话五元组聚合：`SessionAggregator` 将 TCP/UDP 正反向数据包归并为同一会话并统计双向流量。
- 子进程生命周期管理：后端负责调用 tshark/editcap，支持任务取消、停止抓包和 UI 进程退出联动。
- 防御式输入处理：分页排序字段白名单、JSON 类型校验、上传扩展名过滤、tshark 行解析失败不抛出到主流程。
- 可观测性接口：`/api/getBackendMetrics` 暴露工作状态、队列积压、背压次数、最近一次分析耗时和吞吐。

## 功能概览

- 实时抓包：选择网卡后由后端启动 tshark 抓包。
- 离线分析：网页上传 `.pcap`、`.pcapng`、`.cap` 文件，后端异步分析。
- 数据包查询：分页查看数据包，支持 IP、端口、协议、会话等条件过滤。
- 会话聚合：按 TCP/UDP 五元组聚合正反向流量。
- 统计分析：支持 IP、协议、国家/地区维度统计。
- 后端诊断：暴露分析线程池、任务队列、存储队列、落库数量等指标。

## 总体架构

```text
Browser React UI
        |
        | HTTP API
        v
C++17 Backend, 127.0.0.1:8080
        |
        +-- cpp-httplib HTTP Gateway
        +-- DistributedRuntime / AnalysisThreadPool
        +-- TsharkCommandService -> tshark / editcap
        +-- PacketParser
        +-- SessionAggregator
        +-- StorageQueue -> SQLite WAL
        +-- AdapterFlowMonitor
```

离线 pcap 分析流程：

```text
Web upload
    -> POST /api/analysisTasks
    -> bounded AnalysisThreadPool queue
    -> worker thread runs TsharkManager
    -> tshark/editcap subprocess reads packets
    -> PacketParser + SessionAggregator
    -> StorageQueue batches writes
    -> SQLite task database
    -> activate task as current dataset
```

## 环境要求

- Windows
- Visual Studio 2022 Community，包含 C++ 桌面开发工具链
- Node.js 和 npm
- Npcap，实时抓包需要
- 项目自带 `easytshark-web/resources/tshark_win/`，后端构建后会复制 tshark 和 `ip2region.xdb`

## 第一次构建后端

在 PowerShell 进入项目根目录：

```powershell
cd D:\Organized_Files\Projects\EasyTshark
```

构建 C++ 后端：

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  .\easytshark-server\easytshark-server.sln `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /m
```

构建成功后后端程序位置：

```text
easytshark-server\x64\Debug\easytshark-server.exe
```

## 启动后端

打开一个 PowerShell，进入项目根目录：

```powershell
cd D:\Organized_Files\Projects\EasyTshark
```

启动后端：

```powershell
.\easytshark-server\x64\Debug\easytshark-server.exe --uipid=$PID --analysis-workers=4 --analysis-queue=64
```

参数说明：

- `--uipid=$PID`：告诉后端当前 PowerShell 进程还活着；这个进程退出时后端会自动退出。手动测试时用 `$PID` 最方便。
- `--analysis-workers=4`：离线 pcap 分析线程池 worker 数。
- `--analysis-queue=64`：待分析任务队列上限。

后端启动后监听：

```text
http://127.0.0.1:8080
```

可以用浏览器或 PowerShell 测试：

```powershell
Invoke-RestMethod http://127.0.0.1:8080/api/getBackendMetrics
```

## 启动前端网页

另开一个 PowerShell，进入前端目录：

```powershell
cd D:\Organized_Files\Projects\EasyTshark\easytshark-web
```

第一次运行先安装依赖：

```powershell
npm.cmd install
```

启动网页开发服务器：

```powershell
npm.cmd start
```

浏览器打开：

```text
http://localhost:3000
```

前端会调用固定后端地址：

```text
http://127.0.0.1:8080
```

所以使用抓包、文件分析、数据查询前，必须先启动后端。

## 常用开发命令

后端自测：

```powershell
cd D:\Organized_Files\Projects\EasyTshark
powershell -ExecutionPolicy Bypass -File .\easytshark-server\tests\run_backend_selftest.ps1
```

API 冒烟测试（需要先完成后端构建，并确保 tshark 资源可用）：

```powershell
cd D:\Organized_Files\Projects\EasyTshark
powershell -ExecutionPolicy Bypass -File .\easytshark-server\tests\run_api_smoke.ps1
```

前端生产构建：

```powershell
cd D:\Organized_Files\Projects\EasyTshark\easytshark-web
npm.cmd run build
```

后端完整构建：

```powershell
cd D:\Organized_Files\Projects\EasyTshark
& 'D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  .\easytshark-server\easytshark-server.sln `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /m
```

## 主要接口

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/getWorkStatus` | 获取后端工作状态 |
| `POST` | `/api/startCapture` | 开始实时抓包 |
| `GET` | `/api/stopCapture` | 停止实时抓包 |
| `POST` | `/api/analysisTasks` | 上传或提交 pcap 离线分析任务 |
| `GET` | `/api/analysisTasks/{taskId}` | 查询单个任务状态 |
| `POST` | `/api/analysisTasks/{taskId}/activate` | 激活完成任务作为当前数据集 |
| `POST` | `/api/analysisTasks/{taskId}/cancel` | 取消任务 |
| `POST` | `/api/getPacketList` | 查询数据包列表 |
| `POST` | `/api/getPacketDetail` | 查询数据包详情 |
| `POST` | `/api/getSessionList` | 查询会话列表 |
| `POST` | `/api/getSessionDataStream` | 查询会话数据流 |
| `POST` | `/api/getIPStatsList` | 查询 IP 统计 |
| `POST` | `/api/getProtoStatsList` | 查询协议统计 |
| `POST` | `/api/getCountryStatsList` | 查询国家/地区统计 |
| `GET` | `/api/getBackendMetrics` | 查询后端指标 |
| `GET` | `/api/getWorkerList` | 查询本地分析 worker |
| `GET` | `/api/getDistributedTaskStatus` | 查询所有分析任务 |

## 目录说明

```text
EasyTshark/
├── README.md                         # 项目总说明，启动方式只维护这里
├── .gitignore                        # 忽略构建产物、运行日志、本地数据
├── docs/
│   └── API.md                        # HTTP API 细节
├── easytshark-server/
│   ├── agents.md                     # 后端 AI 快速上下文
│   ├── Directory.Build.props         # C++17 等公共构建配置
│   ├── easytshark-server.sln
│   ├── tests/                        # 后端自测和 API 冒烟测试脚本
│   └── easytshark-server/
│       ├── main.cpp                  # 后端入口，HTTP 路由注册
│       ├── analysis_thread_pool.*    # 固定线程池与有界任务队列
│       ├── distributed_runtime.*     # 本地异步分析任务运行时
│       ├── tshark_manager.*          # 抓包/分析核心协调器
│       ├── storage_queue.*           # 异步批量落库队列
│       ├── session_aggregator.*      # 会话聚合
│       ├── packet_parser.*           # tshark 输出解析
│       └── controller/               # HTTP controller
├── easytshark-web/
│   ├── agents.md                     # 前端 AI 快速上下文
│   ├── package.json
│   ├── public/
│   ├── resources/                    # 后端构建使用的 tshark/Npcap 资源
│   └── src/
│       ├── Api.ts                    # 后端 API 封装
│       ├── App.tsx                   # 路由入口
│       ├── Page/                     # 页面
│       └── components/               # 业务组件
└── local-artifacts/                  # 本地构建/测试产物，已被 .gitignore 忽略
    ├── build-objects/                # 临时 .obj 编译产物
    ├── logs/                         # 本地 app.log 等日志
    └── test-data/                    # 后端自测临时数据库等数据
```

## 注意事项

- 项目已经移除 Electron，不再使用 `npm run electron-dev`。
- 前端网页不会自动启动后端，必须手动启动 `easytshark-server.exe`。
- 浏览器不能直接让后端保存到用户指定路径，所以网页端保留上传分析能力，移除了 Electron 的本地保存对话框能力。
- 如果 PowerShell 中 `npm` 被执行策略拦截，请使用 `npm.cmd`。
- 如果在非项目目录运行相对路径命令，会出现“项目文件不存在”；先 `cd D:\Organized_Files\Projects\EasyTshark`。
- 后端 CORS 当前允许 `http://localhost:3000` 和 `http://127.0.0.1:3000`。
- 本地手动编译或自测产生的 `.obj`、`.log`、`.db` 等文件不要放在根目录；临时保留时归档到 `local-artifacts/build-objects/`、`local-artifacts/logs/`、`local-artifacts/test-data/`。


