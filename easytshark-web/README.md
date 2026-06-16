# EasyTshark Web

`easytshark-web` 是 EasyTshark 的前端与桌面壳工程，基于 React、Arco Design 和 Electron 构建。它负责展示抓包入口、数据包列表、协议详情、会话分析、数据流查看等界面，并通过本地 HTTP 接口调用 `easytshark-server`。

## 技术栈

- React 18
- TypeScript
- React Router v5
- Arco Design
- Axios
- ECharts
- Tailwind CSS
- Electron / electron-builder

## 主要功能

- 实时抓包入口：展示网卡流量趋势，选择网卡后开始抓包。
- 离线文件分析：支持选择、拖拽上传 `.pcap`、`.cap`、`.pcapng` 文件。
- 数据包分析：分页查看数据包，支持 ARP、ICMP、ICMPv6 等分类视图。
- 数据包详情：展示协议解析树、十六进制数据和 ASCII 视图。
- 会话分析：按 TCP、UDP、DNS、HTTP、TLS、SSH 查看会话列表。
- 会话详情：展示会话时序图、会话数据流、ASCII/HEX/原始数据视图。
- 文件保存：在 Electron 客户端中将当前抓包结果保存为 pcap 文件。

## 项目结构

```text
easytshark-web/
├── electron.js          # Electron 主进程，负责窗口、文件对话框、后端进程启动
├── preload.js           # Electron preload，向渲染进程暴露安全 IPC API
├── package.json         # 前端依赖、脚本和 electron-builder 配置
├── public/              # 静态资源
├── resources/           # 打包时随应用携带的 tshark/Npcap 资源
└── src/
    ├── Api.ts           # 本地后端 API 封装，默认访问 http://127.0.0.1:8080
    ├── App.tsx          # 路由入口
    ├── Page/            # 首页和主布局
    ├── components/      # 抓包、数据包、会话、图表等业务组件
    └── style/           # 全局样式
```

## 环境要求

- Node.js 与 npm
- Windows 环境建议安装 Npcap
- 本地后端服务 `easytshark-server`，默认监听 `127.0.0.1:8080`
- Electron 打包模式下需要可执行文件 `easytshark-server.exe` 以及 tshark 相关资源

## 开发运行

安装依赖：

```bash
npm install
```

启动 React 开发服务器：

```bash
npm start
```

浏览器访问：

```text
http://localhost:3000
```

如果只启动浏览器前端，需要另外启动后端服务，否则抓包、文件分析和数据查询接口不可用。

启动 Electron 开发模式：

```bash
npm run electron-dev
```

Electron 开发模式会加载 `http://localhost:3000`，因此需要先运行 `npm start`。

## 可用脚本

```bash
npm start
```

启动 React 开发服务器。

```bash
npm test
```

以交互监听模式运行测试。

```bash
npm run build
```

构建生产环境静态文件到 `build/`。

```bash
npm run electron
```

使用当前构建产物启动 Electron。

```bash
npm run electron-dev
```

以开发模式启动 Electron。

```bash
npm run electron-build
```

先执行前端构建，再使用 electron-builder 打包桌面应用。

## 后端接口约定

前端默认调用：

```text
http://127.0.0.1:8080
```

主要接口包括：

- `/api/getWorkStatus`
- `/api/startCapture`
- `/api/stopCapture`
- `/api/startMonitorAdaptersFlowTrend`
- `/api/getAdaptersFlowTrendData`
- `/api/analysisFile`
- `/api/uploadAnalysisFile`
- `/api/getPacketList`
- `/api/getPacketDetail`
- `/api/savePacket`
- `/api/getSessionList`
- `/api/getSessionDataStream`
- `/api/getIPStatsList`
- `/api/getProtoStatsList`
- `/api/getCountryStatsList`

## 打包说明

`package.json` 中的 `build.extraResources` 会把 `resources/tshark_${os}/` 复制到应用资源目录。Electron 主进程会从资源目录启动 `easytshark-server.exe`，并传入当前 UI 进程 PID：

```text
--uipid=<electron-process-pid>
```

后端会监控 UI 进程，UI 退出后自动停止 HTTP 服务并清理抓包任务。

## 注意事项

- `Api.ts` 中的后端地址是固定的 `http://127.0.0.1:8080`。
- CORS 允许来源为 `http://localhost:3000`，开发端口变更时需要同步调整后端配置。
- Electron 模式支持系统文件选择和保存对话框；浏览器模式使用文件上传兜底，保存到指定路径不可用。
- Windows 抓包依赖 Npcap；打包资源中包含 Npcap 安装程序时，Electron 会在启动时检查并引导安装。
