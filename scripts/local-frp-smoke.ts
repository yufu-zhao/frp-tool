import { mkdtemp, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from 'node:http';
import net from 'node:net';
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { Store } from '../src/main/store';
import { Versions } from '../src/main/versions';
import { Processes, execute } from '../src/main/processes';
import {
  serverSchema,
  instanceSchema,
  type InstalledVersion,
  type ProxyRule,
} from '../src/shared/types';
import { clientConfig } from '../src/main/frp';

const wait = (delay: number) => new Promise((resolve) => setTimeout(resolve, delay));
async function until(check: () => boolean, label: string, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (check()) return;
    await wait(100);
  }
  throw new Error(`等待超时：${label}`);
}
async function freePort() {
  const socket = net.createServer();
  await new Promise<void>((resolve) => socket.listen(0, '127.0.0.1', resolve));
  const port = (socket.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => socket.close(() => resolve()));
  return port;
}
async function kill(child: ChildProcess) {
  if (child.exitCode !== null) return;
  await new Promise<void>((resolve) => {
    child.once('close', () => resolve());
    child.kill();
  });
}
async function main() {
  const fixtureRoot = process.env.INTRANET_SMOKE_DATA;
  if (!fixtureRoot) throw new Error('请提供包含本机 FRP 包的 INTRANET_SMOKE_DATA。');
  const fixture = JSON.parse(await readFile(path.join(fixtureRoot, 'state.json'), 'utf8'));
  const local = fixture.versions.find(
    (v: InstalledVersion) => v.platform === 'darwin' && v.arch === 'amd64',
  );
  if (!local) throw new Error('缺少本机测试包。');
  const root = await mkdtemp(path.join(tmpdir(), 'intranet-local-'));
  const store = new Store(root, {
    available: () => false,
    encrypt: () => Buffer.alloc(0),
    decrypt: () => '',
  });
  await store.load();
  store.data.versions.push(local);
  const versions = new Versions(store, fetch, (file) => execute(file, ['-v']));
  const oldKey = '0.70.1_darwin_amd64';
  const existing = fixture.versions.find((v: InstalledVersion) => v.key === oldKey);
  if (existing) store.data.versions.push(existing);
  else {
    const old = await versions.install({
      version: '0.70.1',
      platform: 'darwin',
      arch: 'amd64',
      url: 'https://github.com/fatedier/frp/releases/download/v0.70.1/frp_0.70.1_darwin_amd64.tar.gz',
    });
    fixture.versions.push(old);
    await writeFile(path.join(fixtureRoot, 'state.json'), JSON.stringify(fixture, null, 2), {
      mode: 0o600,
    });
  }
  const processes = new Processes(store, () => {});
  const checks: Record<string, unknown> = { startedAt: new Date().toISOString() };
  const website = createServer((_request, response) => response.end('multi-instance-ok'));
  await new Promise<void>((resolve) => website.listen(0, '127.0.0.1', resolve));
  const bind = await freePort();
  const firstPort = await freePort();
  const secondPort = await freePort();
  const token = randomBytes(24).toString('hex');
  const server = serverSchema.parse({
    id: 'local-server',
    name: '本机测试服务',
    host: '127.0.0.1',
    sshPort: 22,
    username: 'test',
    auth: 'password',
    publicHost: '127.0.0.1',
    frpPort: bind,
    token,
  });
  await store.saveServer(server);
  store.server(server.id).deployment = {
    binary: '',
    config: '',
    log: '',
    pidFile: '',
    mode: 'process',
    service: 'unused',
    managed: true,
    version: '0.71.0',
    versionKey: local.key,
  };
  const configPath = path.join(root, 'frps.toml');
  await writeFile(
    configPath,
    `bindAddr = "127.0.0.1"\nbindPort = ${bind}\n[auth]\nmethod = "token"\ntoken = "${token}"\n`,
    { mode: 0o600 },
  );
  let serverLog = '';
  const startServer = () => {
    const child = spawn(path.join(local.directory, 'frps'), ['-c', configPath]);
    child.stdout.on('data', (data) => {
      serverLog += data.toString();
    });
    child.stderr.on('data', (data) => {
      serverLog += data.toString();
    });
    return child;
  };
  let daemon = startServer();
  const base: ProxyRule = {
    id: 'tcp',
    name: 'tcp',
    type: 'tcp',
    localIP: '127.0.0.1',
    localPort: (website.address() as net.AddressInfo).port,
    remotePort: firstPort,
    domain: '',
    tlsMode: 'passthrough',
    certPath: '',
    keyPath: '',
  };
  const first = instanceSchema.parse({
    id: 'first-client',
    name: '第一实例',
    serverId: server.id,
    versionKey: local.key,
    mode: 'form',
    proxies: [base],
  });
  const second = instanceSchema.parse({
    ...first,
    id: 'second-client',
    name: '版本不同的第二实例',
    versionKey: oldKey,
    proxies: [{ ...base, remotePort: secondPort }],
  });
  try {
    await until(() => serverLog.includes('frps started successfully'), '本机服务启动');
    await store.saveInstance(first);
    await store.saveInstance(second);
    await processes.start(first.id);
    await processes.start(second.id);
    await until(
      () =>
        processes.status(first.id).proxies.tcp === '已注册' &&
        processes.status(second.id).proxies.tcp === '已注册',
      '多实例注册',
    );
    checks.multiInstance =
      (await (await fetch(`http://127.0.0.1:${firstPort}`)).text()) === 'multi-instance-ok' &&
      (await (await fetch(`http://127.0.0.1:${secondPort}`)).text()) === 'multi-instance-ok';
    checks.versionMismatch = processes.log(second.id).includes('客户端 0.70.1 / 服务端 0.71.0');
    const collision = instanceSchema.parse({ ...first, id: 'collision-client' });
    await store.saveInstance(collision);
    await processes.start(collision.id);
    await until(
      () => (processes.status(collision.id).proxies.tcp ?? '').includes('注册失败'),
      '端口冲突提示',
    );
    checks.portConflict = true;
    await processes.stop(collision.id);
    const bad = instanceSchema.parse({
      ...first,
      id: 'bad-auth-client',
      mode: 'raw',
      rawConfig: clientConfig({ ...first, id: 'bad-auth-client' }, server, 'wrong-token'),
    });
    await store.saveInstance(bad);
    await processes.start(bad.id);
    await until(() => processes.status(bad.id).message.includes('连接失败'), '认证失败状态');
    checks.badAuth = processes.status(bad.id).status !== 'connected';
    await processes.stop(bad.id);
    await kill(daemon);
    await until(() => processes.status(first.id).status !== 'connected', '断线状态');
    checks.disconnect = true;
    serverLog = '';
    daemon = startServer();
    await until(
      () =>
        processes.status(first.id).proxies.tcp === '已注册' &&
        processes.status(first.id).status === 'connected',
      '恢复后重新注册',
    );
    checks.reconnect =
      (await (await fetch(`http://127.0.0.1:${firstPort}`)).text()) === 'multi-instance-ok';
    await processes.shutdown();
    checks.shutdown =
      processes.status(first.id).status === 'stopped' &&
      processes.status(second.id).status === 'stopped';
    if (Object.entries(checks).some(([key, value]) => key !== 'startedAt' && value !== true))
      throw new Error('本机测试有未通过项');
    checks.result = 'passed';
  } catch (error) {
    checks.result = 'failed';
    checks.error = (error as Error).message;
    throw error;
  } finally {
    await processes.shutdown();
    await kill(daemon);
    website.close();
    checks.finishedAt = new Date().toISOString();
    await writeFile(path.join(fixtureRoot, 'local-result.json'), JSON.stringify(checks, null, 2));
    console.log(JSON.stringify(checks, null, 2));
  }
}
void main().catch((error) => {
  console.error((error as Error).message);
  process.exitCode = 1;
});
