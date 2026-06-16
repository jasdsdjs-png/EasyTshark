# EasyTshark

EasyTshark 是一个面向本机网络抓包和 pcap 离线分析的桌面应用。项目由 React/Electron 前端和 C++ 后端组成：前端负责交互和可视化，后端负责调用 tshark、解析网络数据包、聚合会话、异步落库，并通过本地 HTTP API 提供查询能力。

这个仓库的后端重点不只是 CRUD，而是一个小型数据处理系统：它包含进程管理、异步任务、队列背压、SQLite 读写优化、gRPC Worker 演示链路和诊断指标，适合作为后端/系统工程方向的作品集项目。

## 功能特性

- 实时抓包：选择网卡后启动 tshark 抓包，支持停止抓包和保存 pcap。
- 离线分析：上传或选择 `.pcap`、`.pcapng`、`.cap` 文件后提交异步分析任务。
- 数据包视图：分页查询数据包，支持协议、IP、端口、会话等条件过滤。
- 会话聚合：按 TCP/UDP 五元组聚合会话，并支持会话详情和数据流查看。
- 统计分析：提供 IP、协议、国家/地区维度的统计查询。
- 后端诊断：提供任务状态、Worker 列表、HTTP/gRPC/队列/落库指标。
- 桌面集成：Electron 负责窗口、文件选择、后端进程启动和生命周期管理。

## 架构

```text
Electron / React UI
        |
        | HTTP API: http://127.0.0.1:8080/api/*
        v
C++ HTTP Gateway
        |
        +-- Task Scheduler
        +-- TsharkCommandService -> tshark / dumpcap / editcap
        +-- PacketParser
        +-- SessionAggregator
        +-- StorageQueue -> SQLite WAL
        +-- AdapterFlowMonitor
        +-- DistributedRuntime -> gRPC Worker diagnostics
```

分布式演示链路：

```text
Gateway --heartbeat / task metadata--> WorkerRegistry
Gateway --PacketAnalyzeService-------> gRPC Worker
Gateway --local source of truth------> SQLite result store
```

当前版本保留本地分析结果作为查询页面的数据源，gRPC Worker 链路用于展示服务拆分、Worker 注册/心跳、RPC 指标、任务状态和后续水平扩展点。

## 后端亮点

- **异步任务模型**：离线分析通过任务接口提交，任务状态包括 `QUEUED`、`RUNNING`、`DONE`、`FAILED`、`CANCELED`，并记录创建、启动、结束时间。
- **异步落库队列**：解析线程和 SQLite 写入解耦，队列提供批量落库、背压等待、pending gauge 和存储指标。
- **SQLite 优化**：开启 WAL，读写连接分离，批量事务写入，并为包、会话和统计查询建立索引。
- **会话聚合**：使用五元组聚合 TCP/UDP 会话，正反向流量归并到同一 session。
- **进程与资源控制**：后端管理 tshark 子进程，UI 退出后自动停止服务并释放抓包状态。
- **可观测性**：暴露 HTTP 线程池、队列、任务、Worker、RPC 调用等诊断指标，便于演示和排障。

## 主要 API

所有响应默认形如：

```json
{
  "code": 0,
  "msg": "操作成功",
  "data": {}
}
```

常用接口：

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/getWorkStatus` | 获取后端工作状态 |
| `POST` | `/api/startCapture` | 开始实时抓包 |
| `GET` | `/api/stopCapture` | 停止实时抓包 |
| `POST` | `/api/analysisFile` | 按本地文件路径提交离线分析任务 |
| `POST` | `/api/uploadAnalysisFile` | 上传 pcap 并提交离线分析任务 |
| `POST` | `/api/analysisTasks` | 新异步任务接口，支持文件上传或 `filePath` |
| `GET` | `/api/analysisTasks/{taskId}` | 查询单个任务状态 |
| `POST` | `/api/analysisTasks/{taskId}/activate` | 将完成任务激活为当前查询数据集 |
| `POST` | `/api/analysisTasks/{taskId}/cancel` | 取消未完成任务 |
| `POST` | `/api/getPacketList` | 查询数据包列表 |
| `POST` | `/api/getSessionList` | 查询会话列表 |
| `GET` | `/api/getBackendMetrics` | 查询后端指标 |
| `GET` | `/api/getWorkerList` | 查询配置的 Worker |
| `GET` | `/api/getDistributedTaskStatus` | 查询所有分布式任务 |

提交任务示例：

```http
POST /api/analysisTasks
Content-Type: application/json

{
  "filePath": "D:\\captures\\sample.pcap"
}
```

任务响应示例：

```json
{
  "task_id": "task-1781595035128",
  "status": "RUNNING",
  "file_path": "D:\\captures\\sample.pcap",
  "worker_id": "local",
  "db_path": "",
  "message": "tshark parsing packets",
  "progress": 20,
  "created_at_ms": 1781595035128,
  "started_at_ms": 1781595035201,
  "finished_at_ms": 0
}
```

## 运行方式

### 后端构建

使用 Visual Studio 2022 打开：

```text
easytshark-server/easytshark-server.sln
```

选择 `Debug|x64` 构建。也可以使用 MSBuild：

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  easytshark-server\easytshark-server.sln `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /m
```

### 启动 Gateway

```powershell
.\easytshark-server\x64\Debug\easytshark-server.exe --uipid=<ui-pid>
```

配置 Worker：

```powershell
.\easytshark-server\x64\Debug\easytshark-server.exe --uipid=<ui-pid> --workers=127.0.0.1:50051
```

### 启动 Worker

```powershell
.\easytshark-server\x64\Debug\easytshark-server.exe --role=worker --listen=127.0.0.1:50051
```

### 前端运行

```powershell
cd easytshark-web
npm install
npm start
```

Electron 开发模式：

```powershell
cd easytshark-web
npm run electron-dev
```

## 验证

后端轻量自检：

```powershell
powershell -ExecutionPolicy Bypass -File .\easytshark-server\tests\run_backend_selftest.ps1
```

前端构建：

```powershell
cd easytshark-web
npm run build
```

后端 smoke test 建议：

1. 启动 Worker：`--role=worker --listen=127.0.0.1:50051`
2. 启动 Gateway：`--uipid=<pid> --workers=127.0.0.1:50051`
3. 访问 `/api/getBackendMetrics`、`/api/getWorkerList`、`/api/getDistributedTaskStatus`
4. 使用示例 pcap 提交 `/api/analysisTasks`
5. 查询任务直到 `DONE` 或明确失败原因
6. 验证包列表、会话列表和统计接口仍可读取数据

## 面试讲法

可以这样介绍：

> 我把一个本地抓包工具的后端拆成了 Gateway、任务调度、tshark 命令服务、数据包解析、会话聚合、异步落库队列和 gRPC Worker 诊断链路。离线分析不再阻塞 HTTP 请求，而是提交任务并通过状态接口追踪进度；解析线程和 SQLite 写入通过队列解耦，配合 WAL、批量事务、索引和慢查询日志提升吞吐。系统还暴露队列积压、落库数量、Worker 心跳、RPC 调用次数等指标，便于演示后端稳定性和可观测性。

## 目录

```text
EasyTshark
├── easytshark-web/                 # React + Electron 前端
├── easytshark-server/              # C++ 后端
│   ├── easytshark-server/
│   │   ├── controller/             # HTTP API
│   │   ├── sql/                    # SQL 构建
│   │   ├── proto/                  # gRPC proto 与生成代码
│   │   ├── packet_parser.*         # tshark 字段解析
│   │   ├── session_aggregator.*    # 会话聚合
│   │   ├── storage_queue.*         # 异步落库
│   │   ├── distributed_runtime.*   # 任务与 Worker 运行时
│   │   └── tshark_manager.*        # 后端核心协调器
│   └── tests/                      # 轻量后端自检
└── README.md
```

## 注意事项

- 后端默认监听 `127.0.0.1:8080`，主要用于本机桌面应用。
- Windows 抓包依赖 Npcap 和 Wireshark/tshark 命令行组件。
- gRPC C++ 依赖通过 `easytshark-server/Directory.Build.props` 指向本机已有 `D:\grpc.file` 环境。
- 日志、数据库、pcap 和构建产物不应作为源码提交。
