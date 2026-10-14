import { contextBridge, ipcRenderer } from 'electron';
import type { DesktopApi } from '../shared/types';

// 只暴露固定 RPC 通道，不允许页面直接使用 Node 或任意 IPC。
const api: DesktopApi = {
  call: (action, payload) => ipcRenderer.invoke('rpc', action, payload),
  onChange: (callback) => {
    const handler = () => callback();
    ipcRenderer.on('state:changed', handler);
    return () => ipcRenderer.removeListener('state:changed', handler);
  },
};
contextBridge.exposeInMainWorld('desktop', api);
