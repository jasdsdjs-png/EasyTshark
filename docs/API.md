# EasyTshark HTTP API

后端默认监听 `http://127.0.0.1:8080`。接口统一放在 `/api` 下，响应使用 `code/msg/data` 包装。

## 通用响应

成功：

```json
{
  "code": 0,
  "msg": "操作成功",
  "data": {}
}
```

列表：

```json
{
  "code": 0,
  "msg": "操作成功",
  "total": 100,
  "data": []
}
```

错误：

```json
{
  "code": 1001,
  "msg": "参数错误"
}
```

## 工作状态与抓包

### `GET /api/getWorkStatus`

返回后端工作状态：

- `0`: idle
- `1`: analyzing file
- `2`: capturing
- `3`: monitoring adapter flow

### `POST /api/startCapture`

```json
{
  "adapterName": "\\Device\\NPF_{...}"
}
```

### `GET /api/stopCapture`

停止当前抓包任务。

## 离线分析任务

### `POST /api/analysisTasks`

支持 JSON 文件路径：

```json
{
  "filePath": "D:\\captures\\sample.pcap"
}
```

也支持 multipart 表单字段 `file` 上传。上传文件限制为 1GB，并只接受 `.pcap`、`.pcapng`、`.cap`。

响应：

```json
{
  "code": 0,
  "msg": "操作成功",
  "data": {
    "taskId": "task-1781595035128",
    "status": "QUEUED",
    "async": true
  }
}
```

### `GET /api/analysisTasks/{taskId}`

查询单个任务状态。

### `POST /api/analysisTasks/{taskId}/activate`

将完成的任务激活为当前查询数据集。

### `POST /api/analysisTasks/{taskId}/cancel`

取消排队或运行中的任务。运行中的任务会通知后端停止并终止当前 tshark 分析子进程。

兼容接口：

- `POST /api/analysisFile`
- `POST /api/uploadAnalysisFile`

这两个接口现在也返回异步任务信息。

## 分页和排序参数

列表接口支持 URL 查询参数：

| 参数 | 说明 |
| --- | --- |
| `pageNum` | 页码，非法值回退为 `1` |
| `pageSize` | 每页数量，范围限制为 `1..1000` |
| `orderBy` | 仅允许后端白名单字段，例如 `frame_number`、`time`、`session_id`、`total_bytes` |
| `descOrAsc` | 仅允许 `asc` 或 `desc`，其他值回退为 `asc` |

排序字段不会直接拼接用户输入；不在白名单内的字段会被忽略。
## 查询接口

| Method | Path | 说明 |
| --- | --- | --- |
| `POST` | `/api/getPacketList` | 查询数据包列表 |
| `POST` | `/api/getPacketDetail` | 查询单个数据包详情 |
| `POST` | `/api/savePacket` | 保存当前 pcap |
| `POST` | `/api/getSessionList` | 查询会话列表 |
| `POST` | `/api/getSessionDetail` | 查询会话详情 |
| `POST` | `/api/getSessionDataStream` | 查询会话数据流 |
| `POST` | `/api/getIPStatsList` | 查询 IP 统计 |
| `POST` | `/api/getProtoStatsList` | 查询协议统计 |
| `POST` | `/api/getCountryStatsList` | 查询国家/地区统计 |

## 诊断接口

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/getBackendMetrics` | 后端指标 |
| `GET` | `/api/getWorkerList` | 本地分析 worker |
| `GET` | `/api/getDistributedTaskStatus` | 所有分析任务状态 |
`/api/getBackendMetrics` 的 `data.tshark` 包含：

| 字段 | 说明 |
| --- | --- |
| `work_status` | 当前工作状态 |
| `parsed_packets` / `stored_packets` | 当前数据集解析和成功落库数量 |
| `pending_packets` / `peak_pending_packets` | 存储队列当前积压和峰值积压 |
| `storage_backpressure_waits` | 解析线程因存储队列满而等待的次数 |
| `last_analysis_duration_ms` | 最近一次离线分析耗时 |
| `last_analysis_packet_count` | 最近一次离线分析解析包数 |
| `last_analysis_packets_per_second` | 最近一次离线分析吞吐估算 |

`data.tshark.active_dataset` 在激活离线分析任务后返回当前数据集自己的存储队列、包缓存和最近一次分析指标。

`data.distributed.analysis_thread_pool` 包含本地分析线程池的 workers、active、queued、queue_limit、submitted、completed、rejected 等指标。

## 测试脚本

```powershell
powershell -ExecutionPolicy Bypass -File .\easytshark-server\tests\run_backend_selftest.ps1
powershell -ExecutionPolicy Bypass -File .\easytshark-server\tests\run_api_smoke.ps1
```

自测覆盖解析边界、线程池饱和与异常隔离、会话聚合、分页排序白名单和存储队列 drain。API 冒烟测试会生成一个小 pcap，启动后端，提交分析任务，激活结果并查询 packet/session/metrics。

