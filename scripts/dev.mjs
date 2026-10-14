import { spawn } from 'node:child_process';
import { build } from 'tsup';
import { createServer } from 'vite';
import electron from 'electron';
import { execFileSync } from 'node:child_process';
execFileSync(process.execPath, ['scripts/icons.mjs'], { stdio: 'inherit' });

// 主进程变更需要重启开发命令；界面由 Vite 热更新。
await build({
  entry: { index: 'src/main/index.ts', 'index.preload': 'src/preload/index.ts' },
  format: ['cjs'],
  outDir: 'dist/main',
  external: ['electron'],
  clean: true,
});
const server = await createServer();
await server.listen();
const child = spawn(electron, ['.'], {
  stdio: 'inherit',
  env: { ...process.env, VITE_DEV_SERVER_URL: 'http://127.0.0.1:5173' },
});
child.on('exit', async (code) => {
  await server.close();
  process.exit(code ?? 0);
});
process.on('SIGINT', () => child.kill());
