import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// 相对资源路径使安装包可以直接通过 file:// 加载。
export default defineConfig({
  plugins: [vue()],
  base: './',
  root: 'src/renderer',
  build: { outDir: '../../dist/renderer', emptyOutDir: true },
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
} as Parameters<typeof defineConfig>[0]);
