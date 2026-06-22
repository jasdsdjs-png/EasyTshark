# EasyTshark Server Agent Notes

This directory contains the C++17 backend for EasyTshark. Use this file as the quick AI context before editing server code.

## Role

The backend is a local HTTP service at `127.0.0.1:8080`. It calls tshark/editcap, parses packet rows, aggregates sessions, stores data in SQLite, and exposes query APIs to the React web frontend.

## Build

Run from repository root:

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  .\easytshark-server\easytshark-server.sln `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /m
```

The executable is written to:

```text
easytshark-server\x64\Debug\easytshark-server.exe
```

## Run

```powershell
.\easytshark-server\x64\Debug\easytshark-server.exe --uipid=$PID --analysis-workers=4 --analysis-queue=64
```

`--uipid` is required. During manual testing, `$PID` from the current PowerShell is acceptable.

## Test

```powershell
powershell -ExecutionPolicy Bypass -File .\easytshark-server\tests\run_backend_selftest.ps1
powershell -ExecutionPolicy Bypass -File .\easytshark-server\tests\run_api_smoke.ps1
```

This covers the analysis thread pool, packet parser edge cases, session aggregator, storage queue drain, and page-order whitelist.

## Architecture Pointers

- `easytshark-server/main.cpp`: process entry, CORS, HTTP server, controller registration, worker counts.
- `analysis_thread_pool.*`: fixed C++17 worker pool with bounded queue and metrics.
- `distributed_runtime.*`: local async pcap analysis runtime. The name is kept for API compatibility; it is not a gRPC runtime anymore.
- `tshark_manager.*`: orchestrates capture, offline analysis, packet processing, storage queue, active dataset switching.
- `tshark_command_service.*`: builds and runs tshark/editcap commands.
- `storage_queue.*`: producer/consumer queue for batch SQLite writes and backpressure.
- `packet_parser.*`: parses tshark tab-separated output fields.
- `session_aggregator.*`: groups packets into sessions.
- `controller/*.hpp`: HTTP route handlers.
- `tshark_database.hpp`: SQLite schema, queries, indexes, and storage methods.

## Important Behavior

- HTTP handlers should return quickly. Long pcap analysis must go through `DistributedRuntime` and `AnalysisThreadPool`.
- Offline analysis tasks have states: `QUEUED`, `RUNNING`, `DONE`, `FAILED`, `CANCELED`.
- Each offline analysis task uses its own SQLite DB under `data/tasks/<taskId>/packets.db`.
- Finished tasks must be activated before frontend queries read that dataset.
- Running task cancellation must notify `TsharkManager::requestStop()` and terminate the analysis tshark subprocess.
- `StorageQueue` must remain bounded; do not replace backpressure with unbounded buffering.
- Keep C++ standard at C++17; shared config lives in `Directory.Build.props`.
- Avoid reintroducing gRPC/protobuf worker code unless the project explicitly asks for distributed workers again.
- Keep generated `.obj`, `.log`, `.db`, and other local test/build leftovers out of the repository root; if they must be kept temporarily, place them under `local-artifacts/build-objects/`, `local-artifacts/logs/`, or `local-artifacts/test-data/`.

## API Smoke Checks

After starting the backend:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/api/getBackendMetrics
Invoke-RestMethod http://127.0.0.1:8080/api/getWorkerList
Invoke-RestMethod http://127.0.0.1:8080/api/getDistributedTaskStatus
```
