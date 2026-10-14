import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, readFile, writeFile, mkdir, readdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import * as tar from 'tar';
import TOML from '@iarna/toml';
import { serverSchema, instanceSchema, type ProxyRule } from '../src/shared/types';
import { clientConfig, serverConfig, frpAdapter, validateRules } from '../src/main/frp';
import { accessAddress } from '../src/shared/address';
import { normalizeReleases, chooseAsset, Versions, extractBinaries } from '../src/main/versions';
import { Store, type CryptoProvider } from '../src/main/store';
import { redact } from '../src/shared/errors';
import { execute } from '../src/main/processes';
import { Remote, quote, remotePath } from '../src/main/remote';

const server = serverSchema.parse({
  id: 'server1',
  name: '测试',
  host: 'localhost',
  sshPort: 22,
  username: 'user',
  auth: 'key',
  publicHost: 'demo.example.com',
  frpPort: 7000,
});
const rule: ProxyRule = {
  id: 'rule1',
  name: '网站',
  type: 'tcp',
  localIP: '127.0.0.1',
  localPort: 3000,
  remotePort: 18080,
  domain: '',
  tlsMode: 'passthrough',
  certPath: '',
  keyPath: '',
};
const instance = instanceSchema.parse({
  id: 'client1',
  name: '本机',
  serverId: server.id,
  versionKey: '0.71.0_darwin_amd64',
  mode: 'form',
  proxies: [rule],
});
let root: string;
const noCrypto: CryptoProvider = {
  available: () => false,
  encrypt: () => {
    throw new Error('不应加密');
  },
  decrypt: () => {
    throw new Error('不应解密');
  },
};
beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'intranet-test-'));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('FRP 配置与输入边界', () => {
  it('生成可解析 TOML，包含认证令牌和代理隔离名称', () => {
    const config = TOML.parse(clientConfig(instance, server, 'secret-token')) as any;
    expect(config.auth.token).toBe('secret-token');
    expect(config.proxies[0].name).toBe('client1_网站');
    expect(config.proxies[0].remotePort).toBe(18080);
    expect((TOML.parse(serverConfig(server, 'secret-token')) as any).bindPort).toBe(7000);
  });
  it('支持 HTTPS 证书终止和 IPv6 本地地址', () => {
    const https = {
      ...rule,
      type: 'https' as const,
      domain: 'demo.example.com',
      localIP: '::1',
      tlsMode: 'terminate' as const,
      certPath: '/cert.pem',
      keyPath: '/key.pem',
    };
    const config = TOML.parse(clientConfig({ ...instance, proxies: [https] }, server, 't')) as any;
    expect(config.proxies[0].plugin.localAddr).toBe('[::1]:3000');
    expect(config.proxies[0].plugin.type).toBe('https2http');
  });
  it('拒绝重复代理、公网端口、无域名或不完整证书', () => {
    expect(() => validateRules([rule, rule])).toThrow('名称重复');
    expect(() => validateRules([rule, { ...rule, name: '第二个' }])).toThrow('端口重复');
    expect(() => validateRules([{ ...rule, type: 'http', domain: 'https://x' }])).toThrow('域名');
    expect(() =>
      validateRules([{ ...rule, type: 'https', domain: 'x', tlsMode: 'terminate' }]),
    ).toThrow('证书');
    expect(() => serverConfig({ ...server, httpPort: 7000 }, 't')).toThrow('端口不能重复');
  });
  it('正确显示 IPv6、默认 HTTP 端口和非默认 HTTPS 端口', () => {
    expect(accessAddress(rule, { ...server, publicHost: '::1' })).toBe('[::1]:18080');
    expect(
      accessAddress({ ...rule, type: 'http', domain: 'x.com' }, { ...server, httpPort: 80 }),
    ).toBe('http://x.com');
    expect(accessAddress({ ...rule, type: 'https', domain: 'x.com' }, server)).toBe(
      'https://x.com:8443',
    );
  });
  it('识别旧版本，拒绝非法标识与端口', () => {
    expect(frpAdapter.supportsForm('0.51.3')).toBe(false);
    expect(frpAdapter.supportsForm('v0.52.0')).toBe(true);
    expect(serverSchema.safeParse({ ...server, id: '../x' }).success).toBe(false);
    expect(serverSchema.safeParse({ ...server, sshPort: 65536 }).success).toBe(false);
  });
});

describe('版本查询回归与兜底', () => {
  it('缺失字段、空 asset、无版本号不会触发 undefined.replace', () => {
    expect(normalizeReleases([undefined, {}, { tag_name: null }, { tag_name: 'v0.71.0' }])).toEqual(
      [{ version: '0.71.0', publishedAt: '', assets: [] }],
    );
    expect(() => normalizeReleases({ message: 'rate limited' })).toThrow('非列表');
  });
  it('跳过草稿和预发布，仅接受有效安装包 URL', () => {
    const releases = normalizeReleases([
      {
        tag_name: 'v0.71.0',
        assets: [
          null,
          {},
          { name: 'frp_0.71.0_linux_amd64.tar.gz', browser_download_url: 'https://github.com/a' },
        ],
      },
      { tag_name: 'v0.70.0', prerelease: true },
    ]);
    expect(releases).toHaveLength(1);
    expect(chooseAsset(releases[0], 'linux', 'amd64').url).toBe('https://github.com/a');
    expect(() => chooseAsset(releases[0], 'windows', 'amd64')).toThrow('没有');
  });
  it('先获取数据，再在限流时回退带时间戳缓存', async () => {
    const store = new Store(root, noCrypto);
    await store.load();
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify([{ tag_name: 'v0.71.0', assets: [] }])))
      .mockResolvedValueOnce(new Response('', { status: 429 }));
    const versions = new Versions(store, fetcher, async () => '');
    const online = await versions.catalog();
    const cached = await versions.catalog();
    expect(online.cached).toBe(false);
    expect(cached.cached).toBe(true);
    expect(cached.updatedAt).toBe(online.updatedAt);
    expect(cached.warning).toContain('限流');
  });
  it.each(['网络超时', '返回 HTML', '缺少字段'])('冷启动失败有离线入口提示：%s', async (kind) => {
    const store = new Store(root, noCrypto);
    await store.load();
    const fetcher =
      kind === '网络超时'
        ? async () => {
            throw new Error('ETIMEDOUT');
          }
        : async () => new Response(kind === '返回 HTML' ? '<html>error</html>' : '[{}]');
    await expect(new Versions(store, fetcher, async () => '').catalog()).rejects.toThrow(
      '导入本地安装包',
    );
  });
  it('下载失败与版本查询失败区分', async () => {
    const store = new Store(root, noCrypto);
    await store.load();
    const versions = new Versions(
      store,
      async () => new Response('', { status: 404 }),
      async () => '',
    );
    await expect(
      versions.install({
        version: '0.71.0',
        platform: 'linux',
        arch: 'amd64',
        url: 'https://github.com/missing',
      }),
    ).rejects.toThrow('安装包下载失败');
    expect(store.data.versions).toHaveLength(0);
  });
  it('坏校验值不安装并清理临时目录', async () => {
    const store = new Store(root, noCrypto);
    await store.load();
    const file = path.join(root, 'bad.tar.gz');
    await writeFile(file, 'bad package');
    await expect(
      new Versions(store, fetch, async () => '').install({
        version: '0.71.0',
        platform: 'linux',
        arch: 'amd64',
        localPath: file,
        digest: '0'.repeat(64),
      }),
    ).rejects.toThrow('校验失败');
    expect(await readdir(path.join(root, 'packages'))).toEqual([]);
  });
  it('离线包只提取程序，缺少二进制会拒绝', async () => {
    const source = path.join(root, 'source');
    await mkdir(source);
    await writeFile(path.join(source, 'frpc'), 'client');
    await writeFile(path.join(source, 'frps'), 'server');
    await writeFile(path.join(source, 'run.sh'), 'dangerous');
    const file = path.join(root, 'package.tar.gz');
    await tar.c({ cwd: root, file, gzip: true }, ['source']);
    const dest = path.join(root, 'bin');
    await extractBinaries(file, dest, 'linux');
    expect(await readFile(path.join(dest, 'frpc'), 'utf8')).toBe('client');
    expect(await readdir(path.join(dest, 'source'))).not.toContain('run.sh');
    const empty = path.join(root, 'empty.tar.gz');
    await tar.c({ cwd: source, file: empty, gzip: true }, ['run.sh']);
    await expect(extractBinaries(empty, path.join(root, 'missing'), 'linux')).rejects.toThrow(
      '缺少',
    );
  });
  it.skipIf(process.platform === 'win32')('拒绝二进制软链接', async () => {
    await symlink('/etc/passwd', path.join(root, 'frpc'));
    const file = path.join(root, 'link.tar.gz');
    await tar.c({ cwd: root, file, gzip: true }, ['frpc']);
    await expect(extractBinaries(file, path.join(root, 'bin'), 'linux')).rejects.toThrow('不安全');
  });
  it('Windows ZIP 只提取程序，并拒绝软链接', async () => {
    const dest = path.join(root, 'windows');
    await extractBinaries(path.resolve('tests/fixtures/windows-valid.zip'), dest, 'windows');
    expect((await readdir(dest)).sort()).toEqual(['frpc.exe', 'frps.exe']);
    await expect(
      extractBinaries(
        path.resolve('tests/fixtures/windows-symlink.zip'),
        path.join(root, 'unsafe-windows'),
        'windows',
      ),
    ).rejects.toThrow('不安全');
  });
  it('被客户端或服务器引用的版本不能删除', async () => {
    const store = new Store(root, noCrypto);
    await store.load();
    store.data.instances.push(instance);
    await expect(
      new Versions(store, fetch, async () => '').remove(instance.versionKey),
    ).rejects.toThrow('引用');
  });
});

describe('存储、命令与日志保护', () => {
  it('安全存储不可用时敏感字段不落盘，重新加载后不保留', async () => {
    const store = new Store(root, noCrypto);
    await store.load();
    await store.saveServer({
      ...server,
      password: 'password123',
      token: 'token123',
      rawConfig: 'auth.token = "raw-secret"',
    });
    const disk = await readFile(path.join(root, 'state.json'), 'utf8');
    expect(disk).not.toContain('password123');
    expect(disk).not.toContain('raw-secret');
    expect(disk).not.toContain('token123');
    expect(store.secret('server:server1:token')).toBe('token123');
    const reloaded = new Store(root, noCrypto);
    await reloaded.load();
    expect(reloaded.secret('server:server1:token')).toBe('');
  });
  it('加密字段重启可恢复，普通编辑保留凭据', async () => {
    const key = randomBytes(32);
    const crypto: CryptoProvider = {
      available: () => true,
      encrypt: (value) => {
        const iv = randomBytes(16);
        const cipher = createCipheriv('aes-256-cbc', key, iv);
        return Buffer.concat([iv, cipher.update(value), cipher.final()]);
      },
      decrypt: (value) => {
        const decipher = createDecipheriv('aes-256-cbc', key, value.subarray(0, 16));
        return Buffer.concat([decipher.update(value.subarray(16)), decipher.final()]).toString();
      },
    };
    const store = new Store(root, crypto);
    await store.load();
    await store.saveServer({ ...server, token: 'private-token' });
    await store.saveServer({ ...server, name: '修改名称' });
    const reloaded = new Store(root, crypto);
    await reloaded.load();
    expect(reloaded.secret('server:server1:token')).toBe('private-token');
    expect(await readFile(path.join(root, 'state.json'), 'utf8')).not.toContain('private-token');
  });
  it('并发持久化不会写坏 JSON', async () => {
    const store = new Store(root, noCrypto);
    await store.load();
    await Promise.all(
      Array.from({ length: 10 }, (_, index) => {
        store.data.settings.proxyUrl = String(index);
        return store.persist();
      }),
    );
    expect(
      JSON.parse(await readFile(path.join(root, 'state.json'), 'utf8')).settings.proxyUrl,
    ).toBe('9');
  });
  it('损坏存储不被静默覆盖', async () => {
    await writeFile(path.join(root, 'state.json'), '{bad');
    await expect(new Store(root, noCrypto).load()).rejects.toThrow('不会覆盖');
    expect(await readFile(path.join(root, 'state.json'), 'utf8')).toBe('{bad');
  });
  it('日志隐藏已知凭据、密码字段和私钥', () => {
    const output = redact(
      'token = abc password=def known123 -----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----',
      ['known123'],
    );
    expect(output).not.toContain('known123');
    expect(output).not.toContain('abc');
    expect(output).not.toContain('def');
    expect(output).not.toContain('data');
  });
  it('远程参数转义及路径拒绝', () => {
    expect(quote("a'b")).toBe("'a'\"'\"'b'");
    expect(() => remotePath('/')).toThrow();
    expect(() => remotePath('/a/../b')).toThrow();
    expect(() => remotePath('/a\nb')).toThrow();
    expect(remotePath('/home/a b/frps')).toBe('/home/a b/frps');
  });
  it('接管系统服务必须匹配程序与配置，不能误管其他单元', async () => {
    const store = new Store(root, noCrypto);
    await store.load();
    await store.saveServer(server);
    const remote = new Remote(
      store,
      async () => false,
      () => {},
    );
    const exec = vi
      .spyOn(remote, 'exec')
      .mockResolvedValueOnce('0.71.0')
      .mockResolvedValueOnce('')
      .mockResolvedValueOnce('{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx ; }');
    await expect(
      remote.adopt(server.id, {
        binary: '/opt/frps',
        config: '/opt/frps.toml',
        log: '/opt/frps.log',
        pidFile: '/opt/frps.pid',
        mode: 'system',
        service: 'nginx.service',
        managed: false,
        version: '',
        versionKey: '',
      }),
    ).rejects.toThrow('不一致');
    expect(store.server(server.id).deployment).toBeUndefined();
    expect(exec.mock.calls.some((call) => call[1].includes('systemctl stop'))).toBe(false);
  });
  it('本机执行分别处理成功、失败和超时', async () => {
    expect(await execute(process.execPath, ['-e', 'console.log("0.71.0")'])).toBe('0.71.0');
    await expect(
      execute(process.execPath, ['-e', 'console.error("配置错误");process.exit(1)']),
    ).rejects.toThrow('配置错误');
    await expect(execute(process.execPath, ['-e', 'setTimeout(()=>{},10000)'], 50)).rejects.toThrow(
      '超时',
    );
  });
});
