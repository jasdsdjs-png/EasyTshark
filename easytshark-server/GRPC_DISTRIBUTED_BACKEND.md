# EasyTshark gRPC 分布式后端说明

本文档说明 EasyTshark 后端的 Gateway + Worker 改造。当前实现目标是让原本的单机 C++ HTTP 服务具备可演示的服务拆分、异步任务、Worker 心跳、RPC 指标和后续水平扩展基础，同时保持原有前端查询体验稳定。

## 架构角色

```text
React/Electron
    |
    | HTTP /api/*
    v
Gateway (127.0.0.1:8080)
    |
    +-- DistributedRuntime
    |   +-- task queue
    |   +-- task status snapshots
    |   +-- worker list
    |   +-- heartbeat metrics
    |
    +-- TsharkManager
        +-- TsharkCommandService
        +-- PacketParser
        +-- SessionAggregator
        +-- StorageQueue
        +-- SQLite

Worker (--role=worker)
    |
    +-- WorkerRegistry
    +-- PacketAnalyzeService
```

## gRPC 服务

`easytshark-server/easytshark-server/proto/easytshark_worker.proto` 定义两个服务：

- `WorkerRegistry`
  - `RegisterWorker`
  - `Heartbeat`
- `PacketAnalyzeService`
  - `AnalyzePacketRange`
  - `AnalyzeChunk`
  - `CancelTask`

当前 Worker 会响应 heartbeat 和分析 RPC，Gateway 会维护 Worker 地址、在线状态、最后心跳时间、RPC 调用计数和任务状态。

## 任务状态模型

离线分析任务统一为以下状态：

| 状态 | 说明 |
| --- | --- |
| `QUEUED` | 任务已提交，等待调度 |
| `RUNNING` | 任务正在执行 |
| `DONE` | 任务成功完成，结果可激活 |
| `FAILED` | 任务失败，`message` 包含失败原因 |
| `CANCELED` | 任务已取消 |

任务快照包含：

- `task_id`
- `status`
- `file_path`
- `worker_id`
- `db_path`
- `message`
- `progress`
- `total_batches`
- `total_packets`
- `created_at_ms`
- `started_at_ms`
- `finished_at_ms`

## 为什么当前仍以本地结果为准

EasyTshark 的前端已有包列表、会话、详情树、HEX/ASCII 数据流、统计页等查询能力。这些页面依赖当前 SQLite 数据模型和本地 pcap 文件偏移。为了保证项目可运行性，当前版本采用：

1. Gateway 接收离线分析任务。
2. Gateway 记录任务状态并维护 Worker 诊断链路。
3. 本地 `TsharkManager` 完成实际解析、会话聚合和 SQLite 入库。
4. 完成任务可以激活为当前查询数据集。

这让前端兼容性、数据详情查询和保存 pcap 能力保持稳定，同时为后续真正的远程切片解析留出接口。

## 后续可扩展方向

完整远程 Worker 分析可以按以下步骤演进：

1. Gateway 根据 pcap 文件切片或 frame range 生成多个子任务。
2. Worker 通过 `AnalyzeChunk` 或 `AnalyzePacketRange` 返回 `AnalyzeBatch`。
3. Gateway 合并 `PacketRecord` 和 `SessionRecord`，统一写入任务数据库。
4. 对失败 Worker 做重试或重新分配。
5. 任务完成后将远程结果激活为当前数据集。

## 运行命令

构建：

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  easytshark-server\easytshark-server.sln `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /m
```

启动 Worker：

```powershell
.\easytshark-server\x64\Debug\easytshark-server.exe --role=worker --listen=127.0.0.1:50051
```

启动 Gateway：

```powershell
.\easytshark-server\x64\Debug\easytshark-server.exe --uipid=<ui-pid> --workers=127.0.0.1:50051
```

## 诊断接口

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/getBackendMetrics` | HTTP、tshark、队列、任务、gRPC 指标 |
| `GET` | `/api/getWorkerList` | Worker 地址、在线状态、最后心跳 |
| `GET` | `/api/getDistributedTaskStatus` | 所有任务状态 |
| `GET` | `/api/analysisTasks/{taskId}` | 单个任务状态 |

## 面试表达

可以这样讲：

> 我把单机抓包分析后端拆成 Gateway + Worker 的形态。Gateway 保持原来的 HTTP API，不影响前端；内部增加 DistributedRuntime 管理任务队列、任务状态、Worker 列表、heartbeat 和 RPC 指标。当前版本为了保证包详情、会话流和 SQLite 查询稳定，仍以本地分析结果作为查询 source of truth，但 gRPC 服务边界、proto、Worker 运行方式、诊断接口和任务模型已经建立，后续可以自然扩展为真正的多 Worker 分片解析。
