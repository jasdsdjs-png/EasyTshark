param(
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$serverRoot = Join-Path $repoRoot "easytshark-server\easytshark-server"
$outDir = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$candidateVcvars = @(
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($installPath) {
        $candidateVcvars += (Join-Path $installPath "VC\Auxiliary\Build\vcvars64.bat")
    }
}

$vcvars = $candidateVcvars | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vcvars) {
    throw "Visual Studio vcvars64.bat was not found. Tried: $($candidateVcvars -join '; ')"
}

$source = Join-Path $PSScriptRoot "backend_selftest.cpp"
$threadPool = Join-Path $serverRoot "analysis_thread_pool.cpp"
$parser = Join-Path $serverRoot "packet_parser.cpp"
$aggregator = Join-Path $serverRoot "session_aggregator.cpp"
$storageQueue = Join-Path $serverRoot "storage_queue.cpp"
$pageHelper = Join-Path $serverRoot "pagehelper.cpp"
$sqlite = Join-Path $serverRoot "third_library\sqlite3\sqlite3.c"
$loguru = Join-Path $serverRoot "third_library\loguru\loguru.cpp"
$exe = Join-Path $outDir "backend_selftest.exe"

$compile = @(
    "`"$vcvars`"",
    "&&",
    "cl",
    "/nologo",
    "/std:c++17",
    "/EHsc",
    "/utf-8",
    "/DNOMINMAX",
    "/I`"$serverRoot`"",
    "/I`"$serverRoot\third_library`"",
    "`"$source`"",
    "`"$threadPool`"",
    "`"$parser`"",
    "`"$aggregator`"",
    "`"$storageQueue`"",
    "`"$pageHelper`"",
    "`"$sqlite`"",
    "`"$loguru`"",
    "shlwapi.lib",
    "/Fe:`"$exe`""
) -join " "

cmd.exe /c $compile
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $exe

