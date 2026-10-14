import { defineConfig } from 'tsup';
// 独立入口名称避免主进程与 preload 同名覆盖。
export default defineConfig({
  entry: { index: 'src/main/index.ts', 'index.preload': 'src/preload/index.ts' },
  format: ['cjs'],
  outDir: 'dist/main',
  external: ['electron'],
  clean: true,
});
