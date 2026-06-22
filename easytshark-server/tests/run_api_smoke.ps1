param(
    [string]$Configuration = "Debug",
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$exe = Join-Path $repoRoot "easytshark-server\x64\$Configuration\easytshark-server.exe"
if (-not (Test-Path $exe)) {
    throw "Backend executable not found: $exe. Build the backend first."
}

$outDir = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$samplePcap = Join-Path $outDir "api_smoke_sample.pcap"

function Write-U32LE([System.Collections.Generic.List[byte]]$bytes, [uint32]$value) {
    $bytes.Add([byte]($value -band 0xff))
    $bytes.Add([byte](($value -shr 8) -band 0xff))
    $bytes.Add([byte](($value -shr 16) -band 0xff))
    $bytes.Add([byte](($value -shr 24) -band 0xff))
}

function Write-U16LE([System.Collections.Generic.List[byte]]$bytes, [uint16]$value) {
    $bytes.Add([byte]($value -band 0xff))
    $bytes.Add([byte](($value -shr 8) -band 0xff))
}

# Minimal Ethernet + IPv4 + UDP packet inside a pcap container.
$packet = [byte[]]@(
    0x66,0x77,0x88,0x99,0xaa,0xbb, 0x00,0x11,0x22,0x33,0x44,0x55, 0x08,0x00,
    0x45,0x00,0x00,0x20, 0x00,0x01,0x00,0x00, 0x40,0x11,0x00,0x00, 0xc0,0xa8,0x01,0x0a, 0x5d,0xb8,0xd8,0x22,
    0xd4,0x31,0x00,0x35, 0x00,0x0c,0x00,0x00, 0xde,0xad,0xbe,0xef
)
$bytes = [System.Collections.Generic.List[byte]]::new()
Write-U32LE $bytes 2712847316
Write-U16LE $bytes 2
Write-U16LE $bytes 4
Write-U32LE $bytes 0
Write-U32LE $bytes 0
Write-U32LE $bytes 65535
Write-U32LE $bytes 1
Write-U32LE $bytes 1710000000
Write-U32LE $bytes 123000
Write-U32LE $bytes $packet.Length
Write-U32LE $bytes $packet.Length
$bytes.AddRange($packet)
[System.IO.File]::WriteAllBytes($samplePcap, $bytes.ToArray())

$backend = Start-Process -FilePath $exe -ArgumentList "--uipid=$PID --analysis-workers=2 --analysis-queue=8" -WorkingDirectory (Split-Path $exe) -PassThru -WindowStyle Hidden
try {
    $baseUrl = "http://127.0.0.1:8080"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $status = Invoke-RestMethod -Uri "$baseUrl/api/getWorkStatus" -Method Get -TimeoutSec 2
            break
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    } while ((Get-Date) -lt $deadline)
    if (-not $status) { throw "Backend did not become ready before timeout." }

    $task = Invoke-RestMethod -Uri "$baseUrl/api/analysisTasks" -Method Post -ContentType "application/json" -Body (@{ filePath = $samplePcap } | ConvertTo-Json -Compress)
    if ($task.code -ne 0) { throw "Failed to submit analysis task: $($task | ConvertTo-Json -Compress)" }
    $taskId = $task.data.taskId

    do {
        Start-Sleep -Milliseconds 500
        $taskStatus = Invoke-RestMethod -Uri "$baseUrl/api/analysisTasks/$taskId" -Method Get -TimeoutSec 5
        $state = $taskStatus.data.status
        if ($state -in @("FAILED", "CANCELED")) {
            throw "Analysis task ended with ${state}: $($taskStatus.data.message)"
        }
    } while ($state -ne "DONE" -and (Get-Date) -lt $deadline)
    if ($state -ne "DONE") { throw "Analysis task did not finish before timeout." }

    $activate = Invoke-RestMethod -Uri "$baseUrl/api/analysisTasks/$taskId/activate" -Method Post -TimeoutSec 5
    if ($activate.code -ne 0) { throw "Failed to activate task: $($activate | ConvertTo-Json -Compress)" }

    $packetList = Invoke-RestMethod -Uri "$baseUrl/api/getPacketList?pageNum=1&pageSize=10&orderBy=frame_number&descOrAsc=asc" -Method Post -ContentType "application/json" -Body "{}" -TimeoutSec 5
    $sessionList = Invoke-RestMethod -Uri "$baseUrl/api/getSessionList?pageNum=1&pageSize=10" -Method Post -ContentType "application/json" -Body "{}" -TimeoutSec 5
    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/getBackendMetrics" -Method Get -TimeoutSec 5
    if ($packetList.total -lt 1) { throw "Expected at least one parsed packet, got $($packetList.total)." }
    if ($sessionList.total -lt 1) { throw "Expected at least one parsed session, got $($sessionList.total)." }

    [pscustomobject]@{
        TaskId = $taskId
        Packets = $packetList.total
        Sessions = $sessionList.total
        StoredPackets = $metrics.data.tshark.active_dataset.stored_packets
        AnalysisWorkers = $metrics.data.distributed.analysis_thread_pool.workers
    } | ConvertTo-Json -Compress
}
finally {
    if ($backend -and -not $backend.HasExited) {
        Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue
    }
}




