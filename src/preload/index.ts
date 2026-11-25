import { contextBridge, ipcRenderer } from 'electron';
import type {
  CertificateIssueProgress,
  DesktopApi,
  DownloadProgress,
  TlsProxyProgress,
  ServerDeployProgress,
} from '../shared/types';

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
  onDownloadProgress: (callback) => {
    const handler = (_event: Electron.IpcRendererEvent, progress: DownloadProgress) =>
      callback(progress);
    ipcRenderer.on('download:progress', handler);
    return () => ipcRenderer.removeListener('download:progress', handler);
  },
  onTlsProxyProgress: (callback) => {
    const handler = (_event: Electron.IpcRendererEvent, progress: TlsProxyProgress) =>
      callback(progress);
    ipcRenderer.on('tls-proxy:progress', handler);
    return () => ipcRenderer.removeListener('tls-proxy:progress', handler);
  },
  onServerDeployProgress: (callback) => {
    const handler = (_event: Electron.IpcRendererEvent, progress: ServerDeployProgress) =>
      callback(progress);
    ipcRenderer.on('server:deploy-progress', handler);
    return () => ipcRenderer.removeListener('server:deploy-progress', handler);
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
