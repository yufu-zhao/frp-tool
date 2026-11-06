import { contextBridge, ipcRenderer } from 'electron';
import type { CertificateIssueProgress, DesktopApi, ServerSiteProgress } from '../shared/types';

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
  onServerSiteProgress: (callback) => {
    const handler = (_event: Electron.IpcRendererEvent, progress: ServerSiteProgress) =>
      callback(progress);
    ipcRenderer.on('server-site:progress', handler);
    return () => ipcRenderer.removeListener('server-site:progress', handler);
  },
  onTerminalEvent: (callback) => {
    const handler = (
      _event: Electron.IpcRendererEvent,
      terminalEvent: Parameters<typeof callback>[0],
    ) => callback(terminalEvent);
    ipcRenderer.on('terminal:event', handler);
    return () => ipcRenderer.removeListener('terminal:event', handler);
  },
  terminalInput: (terminalId, data) => ipcRenderer.send('terminal:input', { terminalId, data }),
  terminalResize: (terminalId, cols, rows) =>
    ipcRenderer.send('terminal:resize', { terminalId, cols, rows }),
  terminalClose: (terminalId) => ipcRenderer.send('terminal:close', terminalId),
};
contextBridge.exposeInMainWorld('desktop', api);
