/** 退出及窗口销毁后，SSH/子进程的异步事件仍可能到达，此时不能发送 IPC。 */
export function notifyRenderer(
  window:
    | {
        isDestroyed(): boolean;
        webContents: { isDestroyed(): boolean; send(channel: string): void };
      }
    | undefined,
  quitting: boolean,
) {
  if (quitting || !window || window.isDestroyed() || window.webContents.isDestroyed()) return;
  window.webContents.send('state:changed');
}
