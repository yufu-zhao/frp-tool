import { spawn, execFileSync } from 'node:child_process';
import { build } from 'tsup';
import { createServer } from 'vite';
import electron from 'electron';
import chokidar from 'chokidar';

execFileSync(process.execPath, ['scripts/icons.mjs'], { stdio: 'inherit' });

const MAIN_ENTRY = {
  entry: { index: 'src/main/index.ts', 'index.preload': 'src/preload/index.ts' },
  format: ['cjs'],
  outDir: 'dist/main',
  external: ['electron'],
  clean: true,
};

const server = await createServer();
await server.listen();

let child;
let restarting = false;
let pendingRestart = false;
let debounce;

function startElectron() {
  // 某些终端/工具会注入 ELECTRON_RUN_AS_NODE，导致 Electron 以纯 Node 模式
  // 运行主进程并在访问 app API 时崩溃；这里显式清除，保证以 GUI 模式启动。
  const childEnv = { ...process.env, VITE_DEV_SERVER_URL: 'http://127.0.0.1:1854' };
  delete childEnv.ELECTRON_RUN_AS_NODE;
  const proc = spawn(electron, ['.', '--no-sandbox', '--disable-gpu-sandbox'], {
    stdio: 'inherit',
    env: childEnv,
  });
  child = proc;
  const startedAt = Date.now();
  proc.on('exit', (code) => {
    // 只有当前实例退出才结束开发命令；重建重启时忽略旧实例的退出事件。
    if (child !== proc || restarting) return;
    // 单实例锁会让第二个 Electron 秒退，进而连带关掉 Vite，表现为「启动不了且无报错」。
    // 启动时给出明确提示，避免误以为构建或代码出了问题。
    if (Date.now() - startedAt < 5000)
      console.warn(
        '[dev] Electron 启动后立即退出。若旧调试窗口仍在（单实例锁），请先关闭它再重新启动。',
      );
    void shutdown(code ?? 0);
  });
}

async function shutdown(code) {
  await server.close().catch(() => {});
  process.exit(code);
}

async function rebuildAndRestart() {
  if (restarting) {
    pendingRestart = true;
    return;
  }
  restarting = true;
  console.log('[dev] 主进程源码已变化，正在重建并重启应用…');
  try {
    await build(MAIN_ENTRY);
    const previous = child;
    child = undefined;
    previous?.kill();
    startElectron();
  } catch (error) {
    console.error('[dev] 主进程重建失败：', error);
  } finally {
    restarting = false;
    if (pendingRestart) {
      pendingRestart = false;
      void rebuildAndRestart();
    }
  }
}

await build(MAIN_ENTRY);
startElectron();

// 界面由 Vite 热更新；主进程 / preload / 共享类型必须重建并重启，否则会出现
// 「新界面 + 旧主进程」的校验错位（例如界面不再传 domain，旧进程仍要求必填）。
chokidar
  .watch(['src/main', 'src/preload', 'src/shared'], { ignoreInitial: true })
  .on('all', (_event, file) => {
    if (!/\.(ts|tsx|json)$/.test(file)) return;
    clearTimeout(debounce);
    debounce = setTimeout(() => void rebuildAndRestart(), 300);
  });

process.on('SIGINT', () => void shutdown(0));
