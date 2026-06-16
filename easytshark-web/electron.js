const { app, BrowserWindow, ipcMain, dialog, electron, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const dayjs = require('dayjs')
const { execFile, execSync, spawn, spawnSync } = require('child_process');

//所有窗体
const windows = {
  windowIndex: 0,
  mainWindow: null, //主窗口
  subWindow: null, //主窗口
}

// 获取日志文件路径
const logFilePath = path.join(app.getPath('userData'), 'app.log');

// 重定向 console.log 到日志文件
const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });
console.log = (...args) => {
    const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : arg).join(' ') + '\n';
    logStream.write(message);
    process.stdout.write(message); // 同时输出到终端（如果存在）
};


function createWindow() {
  windows.mainWindow = new BrowserWindow({
    width: 1200,
    height: 900,
    title: 'MyTshark',
    webPreferences: {
        preload: path.join(__dirname, 'preload.js'), // 预加载脚本
    },
  });

  /*隐藏electron的菜单栏*/
  Menu.setApplicationMenu(null);

  const mode = process.argv[2];
  if (mode === 'dev') {
    windows.mainWindow.loadURL('http://localhost:3000/#/data/dataPacket/all');
    windows.mainWindow.webContents.openDevTools();
  } else {
    windows.mainWindow.loadURL(`file://${path.join(__dirname, 'build/index.html')}#/home`);
    windows.mainWindow.webContents.openDevTools();
  }
}

// 先启动后台进程，然后再创建前端窗口
app.whenReady().then(() => {

  // 第一步：对于Windows平台，需要检查NPCAP
  if (process.platform === 'win32') {
    checkNpcap();
  }  

  // 第二步：启动easytshark-server进程
  startTsharkServer();

  // 第三步：创建主窗口
  createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});


// 检查注册表，判断是否安装了 Npcap
function isNpcapInstalled() {
  try {
      // 执行 reg 命令查询 Npcap 注册表项
      const result = execSync('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Npcap"').toString();
      return result.includes('Npcap');
  } catch (error) {
      console.log("Npcap 未安装:", error.message);
      return false;
  }
}

// 安装 Npcap 并等待安装完成
function installNpcap() {
  const installerPath = path.join(process.resourcesPath, '\\tshark\\bin\\npcap-1.79.exe');

  console.log("正在安装 Npcap, installer path: ", installerPath);

  // **同步执行安装程序，并阻塞直到它退出**
  const result = spawnSync(installerPath, [], {
     shell: true, 
     stdio: 'inherit',
     windowsHide: true,
     detached: true
    });

  // **检查安装程序的退出码**
  if (result.error) {
      console.error("启动 Npcap 安装程序时出错:", result.error);
      process.exit(1); // 直接退出程序
  }

  if (result.status === 0 && isNpcapInstalled()) {
      console.log("Npcap 安装完成");
  } else {
      console.error(`Npcap 安装失败，退出码: ${result.status}`);
      process.exit(1); // 直接退出程序，防止继续执行
  }
}

async function checkNpcap() {
  if (!isNpcapInstalled()) {
    try {
      dialog.showMessageBoxSync({
        type: 'info',
        title: '安装Npcap',
        message: '检测到没有安装Npcap，需要先安装才能使用哦:)',
        buttons: ['确定']
      });
      await installNpcap(); // 等待安装完成
    } catch (err) {
      dialog.showMessageBoxSync({
        type: 'info',
        title: '安装Npcap失败',
        message: 'Npcap 安装失败，无法继续运行应用程序:(',
        buttons: ['确定']
      });
      console.error("Npcap 安装失败，无法继续运行应用程序:", err);
      app.quit();
      return;
    }
  }
}


// 启动easytshark-server进程
function startTsharkServer() {
  const mode = process.argv[2];
  const tsharkServerPath = mode === 'dev'
    ? path.resolve(__dirname, '../easytshark-server/x64/Debug/easytshark-server.exe')
    : path.join(process.resourcesPath, 'easytshark-server.exe')
  const args = ['--uipid=' + process.pid]; // 指定其前端进程的PID
  
  console.log('tsharkServerPath: ', tsharkServerPath)
  
  const options = {
    detached: true,
    stdio: 'ignore',
    shell: false
  };

  if (process.platform === 'win32') {
    options.windowsVerbatimArguments = true;
    options.windowsHide = true;
    options.windowsBreakawayFromJob = true;
  }

  console.log('options:', options)
  const tsharkServerProcess = spawn(tsharkServerPath, args, options)
  tsharkServerProcess.unref();

  tsharkServerProcess.on('exit', (code) => {
    console.log('tsharkServerProcess exited with code:', code);
    app.quit();
  });
}


//当一个新的 webContents 被创建时触发。
app.on('web-contents-created', function (event, webContents) {

  // 监听 window.open 事件
  webContents.setWindowOpenHandler((details) => {

    // 获取要打开的 URL
    const { url } = details;


    // 不是超链接，就是打开会话详情弹窗，单独处理
    const params = url.split('?')[1];
    const browserWindow = new BrowserWindow({
      width: 1000,
      height: 800,
      title: 'MyTshark'
    });

    if (windows.windowIndex === 0) {
      windows.subWindow = browserWindow;
    } else {
      windows[`subWindow${windows.windowIndex}`] = browserWindow;
    }

    /*隐藏electron的菜单栏*/
    Menu.setApplicationMenu(null);

    // 加载 URL
    const mode = process.argv[2];
    if (mode === 'dev') {
      browserWindow.loadURL(`http://localhost:3000/#/detail?${params}`);
      browserWindow.webContents.openDevTools();
    } else {
      browserWindow.loadURL(`file://${path.join(__dirname, 'build/index.html')}#/detail?${params}`, );
      browserWindow.webContents.openDevTools();
    }

    windows.windowIndex = windows.windowIndex + 1;

    // 阻止 Electron 默认的窗口打开行为
    return { action: 'deny' };
  });
});


// 监听来自渲染进程的文件读取请求
ipcMain.handle('open-file-dialog', async (event) => {
  const result = await dialog.showOpenDialog(windows.mainWindow, {
    properties: ['openFile'], // 只允许选择单个文件
    filters: [
      { name: 'pcap', extensions: ['pcap', 'cap', 'pcapng'] },
    ],
  });

  if (!result.canceled && result.filePaths.length > 0) {
    console.log("result: ", result.filePaths[0])
    return result.filePaths[0]; // 返回第一个文件的路径
  }

  console.log("return null")
  return null; // 用户取消选择
});


ipcMain.handle('show-save-dialog', async (event) => {
  const result = await dialog.showSaveDialog(windows.mainWindow, {
    title: "保存文件",
    defaultPath: `easytshark_${dayjs().format('YYYY-MM-DD')}_${dayjs().format('HH-mm-ss')}.pcap`, // 默认文件名
    buttonLabel: "保存",
    filters: [
      { name: '所有文件', extensions: ['*'] }
    ]
  });
  if (!result.canceled) {
    return result.filePath; // 发送所选路径回渲染进程
  } else {
    return null
  }
});
