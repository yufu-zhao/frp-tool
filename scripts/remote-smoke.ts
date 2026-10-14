import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { createSocket } from 'node:dgram';
import { execFileSync } from 'node:child_process';
import { Store } from '../src/main/store';
import { Versions, chooseAsset } from '../src/main/versions';
import { Remote } from '../src/main/remote';
import { Processes, execute } from '../src/main/processes';
import { serverSchema, instanceSchema, type ProxyRule } from '../src/shared/types';

// 只在显式提供测试服务器时执行，避免普通 npm test 接触远程资源。
async function main() {
  const host = process.env.INTRANET_TEST_HOST;
  const keyPath = process.env.INTRANET_TEST_KEY;
  if (!host || !keyPath) throw new Error('请提供 INTRANET_TEST_HOST 和 INTRANET_TEST_KEY。');
  const root =
    process.env.INTRANET_SMOKE_DATA || (await mkdtemp(path.join(tmpdir(), 'intranet-remote-')));
  await mkdir(root, { recursive: true });
  const store = new Store(root, {
    available: () => false,
    encrypt: () => {
      throw new Error('测试不保存凭据');
    },
    decrypt: () => '',
  });
  await store.load();
  const trusted = execFileSync('ssh-keygen', ['-F', host], { encoding: 'utf8' })
    .split('\n')
    .filter((line) => line && !line.startsWith('#'))
    .map((line) =>
      createHash('sha256')
        .update(Buffer.from(line.split(/\s+/)[2], 'base64'))
        .digest('hex'),
    );
  if (!trusted.length) throw new Error('请先独立确认测试服务器的 SSH known_hosts 指纹。');
  const remote = new Remote(
    store,
    async (_server, fingerprint) => trusted.includes(fingerprint),
    () => {},
  );
  const processes = new Processes(store, () => {});
  const versions = new Versions(store, fetch, (binary) => execute(binary, ['-v']));
  const serverId = process.env.INTRANET_SMOKE_SERVER_ID || `smoke-${Date.now()}`;
  const version = '0.71.0';
  const token = randomBytes(24).toString('hex');
  const server = serverSchema.parse({
    id: serverId,
    name: '开发验证服务器',
    host,
    sshPort: 22,
    username: 'root',
    auth: 'key',
    keyPath,
    publicHost: host,
    frpPort: 7000,
    httpPort: 8080,
    httpsPort: 8443,
    token,
  });
  await store.saveServer(server);
  const checks: Record<string, unknown> = { root, serverId, startedAt: new Date().toISOString() };
  const website = httpServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('intranet-smoke-ok');
  });
  const udp = createSocket('udp4');
  udp.on('message', (message, address) => udp.send(message, address.port, address.address));
  let tls: ReturnType<typeof httpsServer> | undefined;
  let deployed = false;
  try {
    let release;
    try {
      const catalog = await versions.catalog();
      checks.catalog = catalog.cached ? 'cache' : 'online';
      release = catalog.releases.find((r) => r.version === version);
    } catch {
      checks.catalog = 'GitHub 限流，验证手动官方地址兜底';
    }
    for (const [platform, arch] of [
      ['darwin', 'amd64'],
      ['linux', 'amd64'],
    ] as const) {
      const key = `${version}_${platform}_${arch}`;
      if (!store.data.versions.some((v) => v.key === key)) {
        const asset = release
          ? chooseAsset(release, platform, arch)
          : {
              url: `https://github.com/fatedier/frp/releases/download/v${version}/frp_${version}_${platform}_${arch}.tar.gz`,
              digest: undefined,
            };
        await versions.install({ version, platform, arch, url: asset.url, digest: asset.digest });
      }
    }
    checks.installed = store.data.versions.map((v) => v.key);
    await remote.connect(serverId);
    checks.ssh = 'connected';
    checks.environment = await remote.detect(serverId);
    checks.deployment = await remote.deploy(serverId, `${version}_linux_amd64`);
    deployed = true;
    checks.start = await remote.control(serverId, 'start');
    if (checks.start !== 'active' && checks.start !== 'running')
      throw new Error(`服务端未启动：${checks.start}`);
    await new Promise<void>((resolve) => website.listen(0, '127.0.0.1', resolve));
    await new Promise<void>((resolve) => udp.bind(0, '127.0.0.1', resolve));
    const localPort = (website.address() as { port: number }).port;
    const udpPort = udp.address().port;
    const cert = path.join(root, 'smoke-cert.pem');
    const certKey = path.join(root, 'smoke-key.pem');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        certKey,
        '-out',
        cert,
        '-days',
        '1',
        '-subj',
        '/CN=smoke.invalid',
      ],
      { stdio: 'ignore' },
    );
    tls = httpsServer(
      { cert: await readFile(cert), key: await readFile(certKey) },
      (_request, response) => response.end('intranet-tls-ok'),
    );
    await new Promise<void>((resolve) => tls!.listen(0, '127.0.0.1', resolve));
    const tlsPort = (tls.address() as { port: number }).port;
    const base: ProxyRule = {
      id: 'tcp',
      name: 'tcp',
      type: 'tcp',
      localIP: '127.0.0.1',
      localPort,
      remotePort: 18080,
      domain: '',
      tlsMode: 'passthrough',
      certPath: '',
      keyPath: '',
    };
    const proxies: ProxyRule[] = [
      base,
      { ...base, id: 'http', name: 'http', type: 'http', domain: 'http.smoke.invalid' },
      {
        ...base,
        id: 'https',
        name: 'https',
        type: 'https',
        localPort: tlsPort,
        domain: 'smoke.invalid',
      },
      {
        ...base,
        id: 'terminate',
        name: 'terminate',
        type: 'https',
        domain: 'terminate.smoke.invalid',
        tlsMode: 'terminate',
        certPath: cert,
        keyPath: certKey,
      },
      { ...base, id: 'udp', name: 'udp', type: 'udp', localPort: udpPort, remotePort: 18081 },
    ];
    const instance = instanceSchema.parse({
      id: 'smoke-client',
      name: '真实链路验证',
      serverId,
      versionKey: `${version}_darwin_amd64`,
      mode: 'form',
      proxies,
    });
    await store.saveInstance(instance);
    await processes.start(instance.id);
    const deadline = Date.now() + 20000;
    while (
      Date.now() < deadline &&
      !Object.values(processes.status(instance.id).proxies).every((s) => s === '已注册')
    )
      await new Promise((resolve) => setTimeout(resolve, 250));
    checks.client = JSON.parse(JSON.stringify(processes.status(instance.id)));
    if (
      checks.client &&
      Object.values(processes.status(instance.id).proxies).some((s) => s !== '已注册')
    )
      throw new Error(`代理未全部注册：${processes.log(instance.id)}`);
    checks.tcp = await remote.exec(serverId, 'curl --max-time 10 -fsS http://127.0.0.1:18080');
    checks.http = await remote.exec(
      serverId,
      "curl --max-time 10 -fsS -H 'Host: http.smoke.invalid' http://127.0.0.1:8080",
    );
    checks.https = await remote.exec(
      serverId,
      'curl --max-time 10 -fkSs --resolve smoke.invalid:8443:127.0.0.1 https://smoke.invalid:8443',
    );
    checks.httpsTerminate = await remote.exec(
      serverId,
      'curl --max-time 10 -fkSs --resolve terminate.smoke.invalid:8443:127.0.0.1 https://terminate.smoke.invalid:8443',
    );
    checks.udp = await remote.exec(
      serverId,
      `python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(10); s.sendto(b"udp-smoke-ok",("127.0.0.1",18081)); print(s.recv(1024).decode())'`,
    );
    try {
      const response = await fetch(`http://${host}:18080`, { signal: AbortSignal.timeout(8000) });
      checks.publicTCP = await response.text();
    } catch {
      checks.publicTCP = '公网入口未直连通过，请检查安全组；服务器侧真实隧道流量已验证';
    }
    if (
      checks.tcp !== 'intranet-smoke-ok' ||
      checks.http !== 'intranet-smoke-ok' ||
      checks.https !== 'intranet-tls-ok' ||
      checks.httpsTerminate !== 'intranet-smoke-ok' ||
      checks.udp !== 'udp-smoke-ok'
    )
      throw new Error('隧道流量内容不匹配');
    await processes.stop(instance.id);
    checks.clientStopped = processes.status(instance.id).status;
    await remote.control(serverId, 'stop');
    checks.serverStopped = await remote.status(serverId);
    await remote.apply(serverId);
    checks.apply = '配置备份与替换通过';
    await remote.changeVersion(serverId, `${version}_linux_amd64`);
    checks.versionReplace = '程序备份与替换通过';
    const backups = await remote.backups(serverId);
    for (const kind of ['config', 'binary'] as const) {
      const backup = backups.find((item) => item.kind === kind);
      if (!backup) throw new Error('缺少恢复测试所需备份');
      await remote.restore(serverId, backup.path);
    }
    checks.restore = '程序和配置备份恢复通过';
    await remote.control(serverId, 'start');
    checks.restart = await remote.status(serverId);
    await remote.control(serverId, 'stop');
    const d = { ...store.server(serverId).deployment! };
    await remote.detach(serverId);
    await remote.adopt(serverId, d);
    checks.adopt = store.server(serverId).deployment?.managed === false;
    await remote.uninstall(serverId, false);
    checks.detachKeptBinary = await remote.exec(
      serverId,
      `test -x '${d.binary}' && echo preserved`,
    );
    await remote.adopt(serverId, d);
    await remote.uninstall(serverId, true);
    deployed = false;
    checks.uninstalled = '测试服务已停止并移除，备份保留';
    checks.result = 'passed';
  } catch (error) {
    checks.result = 'failed';
    checks.error = error instanceof Error ? error.message : String(error);
    throw error;
  } finally {
    await processes.shutdown();
    if (deployed && remote.connected(serverId))
      await remote.control(serverId, 'stop').catch(() => {});
    remote.closeAll();
    website.close();
    udp.close();
    tls?.close();
    checks.finishedAt = new Date().toISOString();
    await writeFile(path.join(root, 'result.json'), JSON.stringify(checks, null, 2));
    console.log(JSON.stringify(checks, null, 2));
  }
}
void main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
