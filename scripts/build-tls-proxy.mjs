// 可重复构建：把 tools/tls-proxy 交叉编译成两个 Linux 静态二进制，
// 供 TlsProxyManager 在全新服务器上按架构上传。仅依赖 Go 标准库。
//
//   node scripts/build-tls-proxy.mjs
//
// 产物：assets/bin/tls-proxy-linux-amd64 与 assets/bin/tls-proxy-linux-arm64
import { spawnSync } from 'node:child_process';
import { mkdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceDir = path.join(root, 'tools', 'tls-proxy');
const outDir = path.join(root, 'assets', 'bin');

mkdirSync(outDir, { recursive: true });

for (const arch of ['amd64', 'arm64']) {
  const output = path.join(outDir, `tls-proxy-linux-${arch}`);
  const result = spawnSync('go', ['build', '-trimpath', '-ldflags=-s -w', '-o', output, '.'], {
    cwd: sourceDir,
    env: { ...process.env, GOOS: 'linux', GOARCH: arch, CGO_ENABLED: '0' },
    encoding: 'utf8',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || 'go build 失败\n');
    process.exit(result.status || 1);
  }
  const bytes = statSync(output).size;
  console.log(
    `built ${path.relative(root, output)} (${bytes} bytes / ${(bytes / 1024 / 1024).toFixed(2)} MiB)`,
  );
}
console.log('done');
