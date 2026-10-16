import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageInfo = JSON.parse(await readFile(path.join(projectRoot, 'package.json'), 'utf8'));
const args = process.argv.slice(2);

// 将 electron-builder 的目标平台别名统一映射为目录名。
const platformOptions = new Map([
  ['--mac', 'mac'],
  ['--macos', 'mac'],
  ['-m', 'mac'],
  ['--win', 'win'],
  ['--windows', 'win'],
  ['-w', 'win'],
  ['--linux', 'linux'],
  ['-l', 'linux'],
]);
const requestedPlatforms = new Set();
for (const arg of args) {
  if (platformOptions.has(arg)) requestedPlatforms.add(platformOptions.get(arg));
  // electron-builder 也支持 -mwl 这样的组合短参数。
  if (/^-[mwl]+$/.test(arg)) {
    for (const alias of arg.slice(1))
      requestedPlatforms.add({ m: 'mac', w: 'win', l: 'linux' }[alias]);
  }
}

if (requestedPlatforms.size > 1) {
  throw new Error('一次只能打包一个目标平台；请分别执行 mac、win 或 linux 打包命令。');
}

const hostPlatform = { darwin: 'mac', win32: 'win', linux: 'linux' }[process.platform];
const platform = [...requestedPlatforms][0] ?? hostPlatform;
if (!platform) throw new Error(`不支持在 ${process.platform} 上自动选择打包平台。`);
if (!/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(packageInfo.version))
  throw new Error(`package.json 版本号格式无效：${packageInfo.version}`);

const outputDirectory = `release/${packageInfo.version}/${platform}`;
const builder = path.join(
  projectRoot,
  'node_modules',
  '.bin',
  process.platform === 'win32' ? 'electron-builder.cmd' : 'electron-builder',
);
const child = spawn(builder, [...args, `--config.directories.output=${outputDirectory}`], {
  cwd: projectRoot,
  stdio: 'inherit',
  shell: process.platform === 'win32',
});
child.on('error', (error) => {
  console.error(`无法启动 electron-builder：${error.message}`);
  process.exitCode = 1;
});
child.on('exit', (code, signal) => {
  if (signal) process.exitCode = 1;
  else process.exitCode = code ?? 1;
});
