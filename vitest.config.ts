import { defineConfig } from 'vitest/config';
// 核心回归独立于界面开发服务器运行。
export default defineConfig({
  test: { include: ['tests/**/*.test.ts'], environment: 'node', testTimeout: 15000 },
});
