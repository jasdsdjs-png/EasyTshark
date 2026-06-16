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

返回单个任务快照：

```json
{
  "task_id": "task-1781595035128",
  "status": "DONE",
  "file_path": "D:\\captures\\sample.pcap",
  "worker_id": "local",
  "db_path": "D:\\...\\data\\tasks\\task-1781595035128\\packets.db",
  "message": "analysis completed",
  "progress": 100,
  "total_batches": 0,
  "total_packets": 0,
  "created_at_ms": 1781595035128,
  "started_at_ms": 1781595035201,
  "finished_at_ms": 1781595039000
}
```

### `POST /api/analysisTasks/{taskId}/activate`

将已完成任务设置为当前查询数据集。

### `POST /api/analysisTasks/{taskId}/cancel`

取消未完成任务。已完成、已失败、已取消任务不能重复取消。

兼容接口：

- `POST /api/analysisFile`
- `POST /api/uploadAnalysisFile`

这两个接口内部同样提交异步分析任务。

## 查询接口

### `POST /api/getPacketList`

请求体：

```json
{
  "ip": "192.168.1.10",
  "port": 443,
  "proto": "TLS",
  "session_id": 1
}
```

分页和排序通过 query string 传入：

```text
?pageNum=1&pageSize=100&orderBy=frame_number&descOrAsc=asc
```

### `POST /api/getPacketDetail`

```json
{
  "frameNumber": 1
}
```

### `POST /api/savePacket`

```json
{
  "savePath": "D:\\captures\\export.pcap"
}
```

### `POST /api/getSessionList`

请求体同 `getPacketList`，返回会话列表。

### `POST /api/getSessionDataStream`

```json
{
  "session_id": 1
}
```

## 统计接口

| Method | Path | 说明 |
| --- | --- | --- |
| `POST` | `/api/getIPStatsList` | IP 维度统计 |
| `POST` | `/api/getProtoStatsList` | 协议维度统计 |
| `POST` | `/api/getCountryStatsList` | 国家/地区维度统计 |

## 诊断接口

### `GET /api/getBackendMetrics`

返回 HTTP 线程池、tshark manager、异步落库队列、任务、gRPC 指标。

### `GET /api/getWorkerList`

```json
{
  "workers": [
    {
      "address": "127.0.0.1:50051",
      "max_parallel_tasks": 2,
      "online": true,
      "last_heartbeat_ms": 1781595039000
    }
  ]
}
```

### `GET /api/getDistributedTaskStatus`

返回所有任务快照，用于演示异步任务和分布式后端运行状态。
