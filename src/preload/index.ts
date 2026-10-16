import { contextBridge, ipcRenderer } from 'electron';
import type { CertificateIssueProgress, DesktopApi } from '../shared/types';

// 只暴露固定 RPC 通道，不允许页面直接使用 Node 或任意 IPC。
const api: DesktopApi = {
  call: (action, payload) => ipcRenderer.invoke('rpc', action, payload),
  onChange: (callback) => {
    const handler = () => callback();
    ipcRenderer.on('state:changed', handler);
    return () => ipcRenderer.removeListener('state:changed', handler);
  },
  onCertificateProgress: (callback) => {
    const handler = (_event: Electron.IpcRendererEvent, progress: CertificateIssueProgress) =>
      callback(progress);
    ipcRenderer.on('certificate:progress', handler);
    return () => ipcRenderer.removeListener('certificate:progress', handler);
  },
};
contextBridge.exposeInMainWorld('desktop', api);
