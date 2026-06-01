const { contextBridge, ipcRenderer, app } = require('electron');
// window.ipcRenderer = require('electron').ipcRenderer;
// // 安全地暴露 ipcRenderer
// contextBridge.exposeInMainWorld('electronAPI', {
//   send: (channel, data) => {
//     ipcRenderer.send(channel, data);
//   },
//   receive: (channel, func) => {
//     ipcRenderer.on(channel, (event, ...args) => func(...args));
//   },
//   invoke: async (channel, data) => {
//     return await ipcRenderer.invoke(channel, data);
//   },
// });

contextBridge.exposeInMainWorld('electronAPI', {
	operationWindow: (windowName, actionType) => ipcRenderer.send('operation-window', windowName, actionType),
	openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
	showSavePath: () => ipcRenderer.invoke('show-save-dialog'),

})