import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  dnsAccountSchema,
  proxySchema,
  serverCertificateSchema,
  serverSchema,
  type HostInfo,
  type Instance,
} from '../src/shared/types';
import { deployFailureHint } from '../src/shared/deploy-hint';
import {
  WEB_INCLUDE_MARKER_BEGIN,
  WEB_INCLUDE_MARKER_END,
  hasManagedInclude,
  includeBlockFor,
  includeDirectiveFor,
  managedDirFor,
  probeConfigFor,
  probeDumpCommand,
  probePathFor,
  removeManagedInclude,
  siteConfigFileName,
  nginxTlsServerConfig,
  nginxHttp01ServerConfig,
  resolveTlsSiteConfig,
  mergeTlsSiteConfig,
} from '../src/shared/web-include';
import { decideTlsPlan } from '../src/shared/tls-plan';
import { accessAddress } from '../src/shared/address';
import { validateRules } from '../src/main/frp';
import { ensureHiddenHttpsRules, restoreHiddenRules } from '../src/main/server-certificates';
import {
  detectSiteFlavor,
  generateSiteConfig,
  type SiteConfigFlavor,
} from '../src/shared/site-config';
import { Downloader, emitProgress, progressEvent, type Fetcher } from '../src/main/downloader';
import { insertHttpSnippet, withNginxTransaction } from '../src/main/server-sites';
import { extractServerBlocks } from '../src/main/site-inspector';
import { Processes } from '../src/main/processes';
import {
  createDnsHook,
  manageAdapterForAccount,
  readDnsAccountCredentials,
  readDnsCredentials,
  removeDnsHook,
  resolveAutomation,
  testDnsAccount,
} from '../src/main/dns-automation';
import type { Store } from '../src/main/store';
import type { DnsChallengeRecord } from '../src/main/certificates';

// 伪造主进程注入的 fetcher：不联网，且能断言 Range / 状态码分支。
function mockResponse(
  status: number,
  headers: Record<string, string>,
  chunks: Uint8Array[],
): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
    body: (async function* () {
      for (const chunk of chunks) yield chunk;
    })(),
  } as unknown as Response;
}

function mockStore(root: string, secrets: Record<string, string> = {}): Store {
  return {
    root,
    data: { downloads: [], settings: { downloadRetries: 0 } },
    saveDownload: async () => {},
    dropDownload: async () => {},
    secret: (key: string) => secrets[key] ?? '',
    putSecret: () => {},
    allSecrets: () => Object.values(secrets),
  } as unknown as Store;
}

describe('下载进度事件', () => {
  it('按已收/总字节计算百分比，并夹在 0-100', () => {
    const base = { taskId: 'task-1', key: 'v1_darwin_arm64', version: 'v1' };
    expect(
      progressEvent(base, { status: 'downloading', message: '下载中', received: 25, total: 100 }),
    ).toMatchObject({
      status: 'downloading',
      received: 25,
      total: 100,
      percent: 25,
      resumable: false,
      attempt: 1,
    });
    expect(
      progressEvent(base, { status: 'downloading', message: 'x', received: 120, total: 100 })
        .percent,
    ).toBe(100);
    expect(progressEvent(base, { status: 'starting', message: '开始' }).percent).toBe(0);
    expect(
      progressEvent(base, {
        status: 'downloading',
        message: 'x',
        received: 30,
        total: 100,
        percent: 42,
      }).percent,
    ).toBe(42);
  });

  it('回调抛错不影响下载流程，且事件正常转发', () => {
    expect(() =>
      emitProgress(
        () => {
          throw new Error('IPC 已断开');
        },
        progressEvent(
          { taskId: 't', key: 'k', version: 'v' },
          { status: 'starting', message: '开始' },
        ),
      ),
    ).not.toThrow();
    let seen = 0;
    emitProgress(
      () => {
        seen += 1;
      },
      progressEvent(
        { taskId: 't', key: 'k', version: 'v' },
        { status: 'starting', message: '开始' },
      ),
    );
    expect(seen).toBe(1);
  });
});

describe('下载器断点续传', () => {
  it('.part 路径固定且过滤非法字符', () => {
    const downloader = new Downloader(mockStore('/tmp/intranet-test-root'), async () =>
      mockResponse(200, {}, []),
    );
    expect(downloader.partPath('v1_linux/../arm64')).toBe(
      '/tmp/intranet-test-root/downloads/v1_linux_.._arm64.part',
    );
  });

  it('206 响应带 Range 请求并把剩余分片追加到已有 .part', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'intranet-resume-'));
    try {
      const downloader = new Downloader(mockStore(root), async () => mockResponse(200, {}, []));
      const part = downloader.partPath('v1_linux_amd64');
      await mkdir(path.dirname(part), { recursive: true });
      await writeFile(part, Buffer.from('ABCD'));

      let range = '';
      const fetcher: Fetcher = async (_url, init) => {
        range = (init?.headers as Record<string, string>).Range ?? '';
        return mockResponse(206, { 'content-range': 'bytes 4-7/8', 'content-length': '4' }, [
          Buffer.from('EFGH'),
        ]);
      };
      const resumable = new Downloader(mockStore(root), fetcher);
      const result = await resumable.download({
        key: 'v1_linux_amd64',
        url: 'https://example.test/pkg',
        taskId: 't1',
        version: 'v1',
      });
      expect(range).toBe('bytes=4-');
      expect(result).toMatchObject({ received: 8, total: 8 });
      expect((await readFile(part)).toString()).toBe('ABCDEFGH');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('服务端返回 200（不支持 Range）时丢弃旧分片从头覆盖', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'intranet-full-'));
    try {
      const downloader = new Downloader(mockStore(root), async () => mockResponse(200, {}, []));
      const part = downloader.partPath('v2_linux_amd64');
      await mkdir(path.dirname(part), { recursive: true });
      await writeFile(part, Buffer.from('OLD-DATA'));

      const fetcher: Fetcher = async () =>
        mockResponse(200, { 'content-length': '3' }, [Buffer.from('XYZ')]);
      const result = await new Downloader(mockStore(root), fetcher).download({
        key: 'v2_linux_amd64',
        url: 'https://example.test/pkg',
        taskId: 't2',
        version: 'v2',
      });
      expect(result).toMatchObject({ received: 3, total: 3 });
      expect((await readFile(part)).toString()).toBe('XYZ');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('只读站点检查解析', () => {
  it('解析 nginx -T 的多个 server 块、泛域名/正则名与证书路径', () => {
    const dump = `# configuration file /etc/nginx/nginx.conf:
http {
  include /etc/nginx/conf.d/*.conf;
}
# configuration file /etc/nginx/conf.d/app.conf:
server {
    listen 80 default_server; # 默认站点
    server_name example.com *.example.com ~^www\\d+\\.example\\.com$;
}
server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate "/etc/ssl/app/fullchain.pem";
    ssl_certificate_key /etc/ssl/app/privkey.pem;
}
# configuration file /etc/nginx/conf.d/empty.conf:
server { listen 8080; server_name _; }
`;
    const blocks = extractServerBlocks(dump);
    expect(blocks).toHaveLength(3);
    expect(blocks[0]).toMatchObject({
      file: '/etc/nginx/conf.d/app.conf',
      names: ['example.com', '*.example.com', '~^www\\d+\\.example\\.com$'],
      ssl: false,
      defaultServer: true,
    });
    expect(blocks[1]).toMatchObject({
      file: '/etc/nginx/conf.d/app.conf',
      names: ['app.example.com'],
      certPath: '/etc/ssl/app/fullchain.pem',
      keyPath: '/etc/ssl/app/privkey.pem',
      ssl: true,
      defaultServer: false,
    });
    expect(blocks[2].file).toBe('/etc/nginx/conf.d/empty.conf');
  });

  it('无 nginx -T 文件标记时仍能从纯配置文本解析', () => {
    const blocks = extractServerBlocks('server { listen 443 ssl; server_name a.test; }');
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toMatchObject({ file: '(unknown)', names: ['a.test'], ssl: true });
  });
});

describe('服务端端口硬约束', () => {
  const base = {
    id: 'srv-1',
    name: '服务器',
    host: '203.0.113.10',
    sshPort: 22,
    username: 'root',
    auth: 'key' as const,
    publicHost: '203.0.113.10',
    frpPort: 7000,
  };
  it('允许按服务器现状填写 80 / 443 或高端口', () => {
    expect(serverSchema.safeParse({ ...base, httpPort: 80, httpsPort: 8443 }).success).toBe(true);
    expect(serverSchema.safeParse({ ...base, httpPort: 8080, httpsPort: 443 }).success).toBe(true);
  });
  it('缺省与显式高端口均通过', () => {
    const parsed = serverSchema.parse(base);
    expect(parsed).toMatchObject({ httpPort: 8080, httpsPort: 8443 });
    expect(serverSchema.parse({ ...base, httpPort: 18080, httpsPort: 18443 })).toMatchObject({
      httpPort: 18080,
      httpsPort: 18443,
    });
  });
});

describe('DNS-01 逐级降级', () => {
  it('凭据从安全存储按命名空间读取', () => {
    const store = mockStore('/tmp/intranet-dns-test', {
      'dns:dnspod:secretId': 'id-1',
      'dns:dnspod:secretKey': 'key-1',
    });
    expect(readDnsCredentials(store, 'dnspod')).toMatchObject({
      secretId: 'id-1',
      secretKey: 'key-1',
    });
    expect(readDnsCredentials(store, 'cloudflare').secretId).toBeUndefined();
  });

  it('多个 DNS 账户按各自命名空间读取凭据', () => {
    const store = mockStore('/tmp/intranet-dns-test', {
      'dns:account:acc-1:secretId': 'id-main',
      'dns:account:acc-1:secretKey': 'key-main',
      'dns:account:acc-2:secretId': 'id-backup',
      'dns:account:acc-2:secretKey': 'key-backup',
    });
    expect(readDnsAccountCredentials(store, 'acc-1')).toMatchObject({
      secretId: 'id-main',
      secretKey: 'key-main',
    });
    expect(readDnsAccountCredentials(store, 'acc-2')).toMatchObject({
      secretId: 'id-backup',
      secretKey: 'key-backup',
    });
    expect(readDnsAccountCredentials(store, 'missing').secretId).toBeUndefined();
  });

  it('不再支持 acme-dns / reuse / manual 服务商', () => {
    for (const provider of ['acme-dns', 'reuse', 'manual'])
      expect(
        dnsAccountSchema.safeParse({ id: 'acc-x', name: 'x', provider, createdAt: 1 }).success,
      ).toBe(false);
    expect(
      dnsAccountSchema.safeParse({ id: 'acc-y', name: 'y', provider: 'cloudflare', createdAt: 1 })
        .success,
    ).toBe(true);
  });

  it('无可用服务商 API 凭据时直接失败，不降级到手动 TXT', async () => {
    const messages: string[] = [];
    await expect(
      resolveAutomation('manual', mockStore('/tmp/intranet-dns-test'), [], (value) => {
        messages.push(value.message);
      }),
    ).rejects.toThrow('不支持的 DNS 服务商');
    await expect(
      resolveAutomation('dnspod', mockStore('/tmp/intranet-dns-test'), []),
    ).rejects.toThrow('请在设置中重新测试并保存 DNS 账户凭据后重试');
    expect(messages.join('|')).not.toContain('手动');
  });

  it('服务商 API 探测通过后返回 api 级别并使用适配器', async () => {
    const record: DnsChallengeRecord = {
      domain: 'a.test',
      record: '_acme-challenge.a.test',
      value: 'token',
    };
    const set = vi.fn(async () => {});
    const unset = vi.fn(async () => {});
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify({ status: { code: '1' }, records: [] }), { status: 200 }),
      ),
    );
    const store = mockStore('/tmp/intranet-dns-test', {
      'dns:account:acc-1:secretId': 'id-1',
      'dns:account:acc-1:secretKey': 'key-1',
    });
    const resolution = await resolveAutomation('dnspod', store, ['a.test'], undefined, 'acc-1');
    expect(resolution.level).toBe('api');
    resolution.adapter.set = set;
    resolution.adapter.unset = unset;
    await createDnsHook(resolution)(record);
    await removeDnsHook(resolution)(record);
    expect(set).toHaveBeenCalledWith(record);
    expect(unset).toHaveBeenCalledWith(record);
    vi.unstubAllGlobals();
  });
});

describe('本机证书与 frpc https2http 链路', () => {
  it('证书记录默认落在服务端，也可显式标记为本机证书', () => {
    const base = {
      id: 'cert-1',
      serverId: 'srv-1',
      name: 'demo',
      provider: 'letsencrypt' as const,
      domains: ['demo.example.com'],
      certPath: '/tmp/demo/fullchain.pem',
      keyPath: '/tmp/demo/private-key.pem',
      createdAt: Date.now(),
    };
    expect(serverCertificateSchema.parse(base).location).toBe('server');
    expect(
      serverCertificateSchema.parse({
        ...base,
        location: 'local',
        localCertificateId: 'local-1',
        deployState: 'deployed',
      }),
    ).toMatchObject({ location: 'local', localCertificateId: 'local-1' });
  });

  it('本机证书路径被 frpc 预览配置自动引用', async () => {
    const server = {
      id: 'srv-1',
      name: '演示服务器',
      host: '203.0.113.10',
      sshPort: 22,
      username: 'root',
      auth: 'key' as const,
      keyPath: '',
      publicHost: '203.0.113.10',
      frpPort: 7000,
      httpPort: 80,
      httpsPort: 443,
      accessMode: 'managed' as const,
      configMode: 'form' as const,
      rawConfig: '',
      rawFormat: 'toml' as const,
    };
    const store = {
      data: {
        certificates: [],
        serverCertificates: [
          {
            id: 'cert-1',
            serverId: 'srv-1',
            name: 'demo',
            provider: 'letsencrypt',
            domains: ['demo.example.com'],
            certPath: '/tmp/local-certs/demo/fullchain.pem',
            keyPath: '/tmp/local-certs/demo/private-key.pem',
            location: 'local',
            localCertificateId: 'local-1',
            deployState: 'deployed',
            createdAt: Date.now(),
          },
        ],
      },
      server: () => server,
      secret: () => 'token',
    } as unknown as Store;
    const processes = new Processes(store, () => {});
    const instance = {
      id: 'ins-1',
      name: 'demo',
      serverId: 'srv-1',
      versionKey: 'v0.71.0_linux_amd64',
      mode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      proxies: [
        {
          id: 'rule-1',
          name: 'web',
          type: 'https',
          localIP: '127.0.0.1',
          localPort: 3000,
          domains: ['demo.example.com'],
          tlsMode: 'terminate',
          certificateId: 'local-1',
        },
      ],
    } as any;
    const config = await processes.preview(instance);
    expect(config).toContain('type = "https2http"');
    expect(config).toContain('/tmp/local-certs/demo/fullchain.pem');
    expect(config).toContain('/tmp/local-certs/demo/private-key.pem');
  });
  it('安装失败时给出分类的下一步建议，避免只显示一句错误', () => {
    expect(deployFailureHint('Permission denied: /etc/systemd/system')).toContain('免密 sudo');
    expect(deployFailureHint('服务器端口 7000 已占用')).toContain('更换');
    expect(deployFailureHint('已有部署，请使用切换版本')).toContain('覆盖上传');
    expect(deployFailureHint('请选择 Linux/amd64 安装包')).toContain('版本库');
    expect(deployFailureHint('SSH 连接失败')).toContain('连接 SSH');
    expect(deployFailureHint('未知错误')).toContain('重试');
  });
});

describe('DNS 账户凭据测试', () => {
  afterEach(() => vi.unstubAllGlobals());

  function jsonResponse(body: unknown): Response {
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify(body),
    } as unknown as Response;
  }

  function credentialStore(initial: Record<string, string> = {}) {
    const secrets = { ...initial };
    const store = {
      root: '/tmp',
      data: { downloads: [], settings: {} },
      secret: (key: string) => secrets[key] ?? '',
      putSecret: (key: string, value?: string) => {
        secrets[key] = value ?? '';
      },
      allSecrets: () => Object.values(secrets),
      persist: async () => {},
    } as unknown as Store;
    return { store, secrets };
  }

  it('没有填写 ID/Key 时明确失败，不调用网络也不保存凭据', async () => {
    const requests: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      requests.push(url);
      return jsonResponse({ status: { code: '1' } });
    });
    const { store, secrets } = credentialStore();
    const result = await testDnsAccount(
      { id: 'acc-1', name: '测试账户', provider: 'dnspod' },
      store,
    );
    expect(result.ok).toBe(false);
    expect(result.message).toContain('缺少 DNSPod ID/Token');
    expect(requests).toHaveLength(0);
    expect(secrets['dns:account:acc-1:secretId']).toBeUndefined();
  });

  it('填写凭据后真实调用服务商接口，成功才落到安全存储', async () => {
    const calls: { url: string; body?: string }[] = [];
    vi.stubGlobal('fetch', async (url: string, init?: { body?: string }) => {
      calls.push({ url, body: init?.body });
      return jsonResponse({ status: { code: '1' } });
    });
    const { store, secrets } = credentialStore();
    const result = await testDnsAccount(
      {
        id: 'acc-2',
        name: 'DNSPod 主账户',
        provider: 'dnspod',
        secretId: 'sid',
        secretKey: 'skey',
      },
      store,
    );
    expect(result.ok).toBe(true);
    expect(calls[0].url).toContain('dnsapi.cn/Domain.List');
    expect(calls[0].body).toContain('login_token=sid%2Cskey');
    expect(secrets['dns:account:acc-2:secretId']).toBe('sid');
    expect(secrets['dns:account:acc-2:secretKey']).toBe('skey');
  });

  it('Cloudflare 用 token verify 校验，不再依赖测试域名', async () => {
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(url);
      return jsonResponse({ success: true, result: { status: 'active' } });
    });
    const { store } = credentialStore();
    const result = await testDnsAccount(
      { id: 'acc-3', name: 'CF', provider: 'cloudflare', token: 'tk' },
      store,
    );
    expect(result.ok).toBe(true);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toContain('api.cloudflare.com/client/v4/user/tokens/verify');
  });

  it('接口返回校验失败时不得提示通过，也不保存凭据', async () => {
    vi.stubGlobal('fetch', async () => jsonResponse({ status: { code: '0' } }));
    const { store, secrets } = credentialStore();
    const result = await testDnsAccount(
      { id: 'acc-4', name: 'bad', provider: 'dnspod', secretId: 'x', secretKey: 'y' },
      store,
    );
    expect(result.ok).toBe(false);
    expect(result.message).not.toContain('通过');
    expect(secrets['dns:account:acc-4:secretId']).toBeUndefined();
  });

  it('DNS 账户数据模型不再保存域名提示字段', () => {
    const account = dnsAccountSchema.parse({
      id: 'acc-5',
      name: '账户',
      provider: 'dnspod',
      createdAt: 1,
    });
    expect(account).not.toHaveProperty('domainHint');
  });
});

describe('Web 规则站点配置模板', () => {
  const webRule = proxySchema.parse({
    id: 'rule-web',
    name: '官网',
    type: 'http',
    localIP: '127.0.0.1',
    localPort: 3000,
    domains: ['www.a.com', 'a.com', 'www.a.com'],
    tlsMode: 'passthrough',
  });
  const hostInfo = (name: string, running = true) =>
    ({ webServices: [{ name, installed: true, running }] }) as HostInfo;

  it('按探测到的 nginx 生成反向代理 server 块', () => {
    const generated = generateSiteConfig({ rule: webRule, hostInfo: hostInfo('nginx') });
    expect(generated.flavor).toBe('nginx');
    expect(generated.content).toContain('server {');
    expect(generated.content).toContain('server_name www.a.com a.com;');
    expect(generated.content).toContain('proxy_pass http://127.0.0.1:8080;');
    expect(generated.content).toContain('proxy_set_header Host $host;');
  });

  it('HTTPS 规则生成 nginx stream 透传模板', () => {
    const rule = { ...webRule, type: 'https' as const };
    const generated = generateSiteConfig({ rule, hostInfo: hostInfo('openresty') });
    expect(generated.flavor).toBe('nginx');
    expect(generated.content).toContain('stream 上下文');
    expect(generated.content).toContain('proxy_pass 127.0.0.1:8443;');
  });

  it('探测到 Apache 时切换为 VirtualHost 语法', () => {
    const generated = generateSiteConfig({ rule: webRule, hostInfo: hostInfo('apache2') });
    expect(generated.flavor).toBe('apache');
    expect(generated.content).toContain('<VirtualHost *:80>');
    expect(generated.content).toContain('ProxyPass / http://127.0.0.1:8080/');
  });

  it('未探测到 Web 服务时回退 Nginx 并给出警告', () => {
    expect(detectSiteFlavor(undefined).detected).toBe(false);
    const generated = generateSiteConfig({ rule: webRule });
    expect(generated.warnings.join(' ')).toContain('未探测到');
    expect(generated.content).toContain('# 由穿透工作台生成 · Nginx 站点反代模板');
  });

  it('规则契约保留站点配置文本与语法来源', () => {
    const parsed = proxySchema.parse({
      ...webRule,
      siteConfig: '# custom',
      siteConfigFlavor: 'caddy' as SiteConfigFlavor,
      siteConfigUpdatedAt: 123,
    });
    expect(parsed.siteConfig).toBe('# custom');
    expect(parsed.siteConfigFlavor).toBe('caddy');
    expect(parsed.siteConfigUpdatedAt).toBe(123);
    const withoutConfig = proxySchema.parse(webRule);
    expect(withoutConfig.siteConfig).toBeUndefined();
  });

  it('Web 服务 include 路径与语法按服务类型区分', () => {
    expect(managedDirFor('nginx')).toBe('/etc/intranet-frp/sites/nginx');
    expect(managedDirFor('apache')).toBe('/etc/intranet-frp/sites/apache');
    expect(includeDirectiveFor('nginx')).toContain(';');
    expect(includeDirectiveFor('apache')).toMatch(/^IncludeOptional .*\.conf$/);
    expect(siteConfigFileName('rule_1')).toBe('rule_1.conf');
    expect(siteConfigFileName('../bad')).toBe('bad.conf');
  });

  it('注入块可识别且只清除本工具标记内容', () => {
    const config = `user nginx;\nevent {}\nhttp {\n  include /etc/nginx/conf.d/*.conf;\n}\n`;
    const next = config.replace('http {', `http {\n${includeBlockFor('nginx')}`);
    expect(next).toContain(WEB_INCLUDE_MARKER_BEGIN);
    expect(hasManagedInclude(next, 'nginx')).toBe(true);
    expect(hasManagedInclude(config, 'nginx')).toBe(false);
    expect(removeManagedInclude(next)).toBe(config);
    expect(removeManagedInclude(config)).toBe(config);
    expect(includeBlockFor('apache')).toContain(WEB_INCLUDE_MARKER_END);
  });

  it('Nginx 注入块作为完整片段插入 http 块，不产生 include # 无效指令', () => {
    const config = `user www;\nevents {}\nhttp {\n  include mime.types;\n  #include luawaf.conf;\n}\n`;
    const next = insertHttpSnippet(config, includeBlockFor('nginx'));
    expect(next).toContain(`http {\n  ${WEB_INCLUDE_MARKER_BEGIN}`);
    expect(next).toContain(`  ${includeDirectiveFor('nginx')}`);
    expect(next).not.toMatch(/include\s+#/);
    expect(hasManagedInclude(next, 'nginx')).toBe(true);
    expect(removeManagedInclude(next)).toBe(config);
  });

  it('探针文件位于托管目录且用配置 dump 检测标记', () => {
    expect(probePathFor(managedDirFor('nginx'))).toBe('/etc/intranet-frp/sites/nginx/default.conf');
    const content = probeConfigFor('nginx', 'intranet-frp-test');
    expect(content).toContain('intranet-frp-test');
    expect(content).not.toMatch(/^\s*(server|VirtualHost)\b/m);
    expect(probeDumpCommand('nginx')).toBe('nginx -T 2>&1');
    expect(probeDumpCommand('apache')).toContain('DUMP_CONFIG');
    expect(() => siteConfigFileName('default')).toThrow('保留文件');
  });

  it('注入后校验回调失败时按快照回滚', async () => {
    const files = new Map<string, string>([['/etc/nginx/nginx.conf', 'original']]);
    const commands: string[] = [];
    const admin = {
      run: async (command: string) => {
        commands.push(command);
        return '';
      },
      read: async (file: string): Promise<string> => files.get(file) ?? '',
      mode: async () => '644',
      write: async (file: string, content: string) => {
        files.set(file, content);
      },
    };
    await expect(
      withNginxTransaction(
        admin,
        '/backup',
        [{ path: '/etc/nginx/nginx.conf', content: 'injected' }],
        {
          validate: 'nginx -t',
          reload: 'nginx -s reload',
          verify: async () => {
            throw new Error('探针未生效');
          },
        },
      ),
    ).rejects.toThrow('探针未生效');
    expect(files.get('/etc/nginx/nginx.conf')).toBe('original');
    expect(commands).toContain('nginx -t && nginx -s reload');
  });
});

describe('TLS 双方案', () => {
  const hostWithNginx: HostInfo = {
    home: '/root',
    supported: true,
    distribution: 'ubuntu',
    version: '22.04',
    kernel: '5.15',
    arch: 'amd64',
    cpuModel: 'x86',
    cpuCores: 2,
    memoryTotalKB: 1024,
    memoryAvailableKB: 512,
    diskTotalKB: 1024,
    diskAvailableKB: 512,
    serviceManager: 'systemd',
    systemd: true,
    userSystemd: false,
    root: false,
    sudo: true,
    ports: '',
    port80: { state: 'free', owner: '' },
    port443: { state: 'occupied', owner: 'nginx' },
    webServices: [{ name: 'nginx', installed: true, running: true }],
  };
  const injected = {
    serverId: 's1',
    flavor: 'nginx' as const,
    serviceName: 'nginx',
    mainConfig: '/etc/nginx/nginx.conf',
    managedDir: '/etc/intranet-frp/sites/nginx',
    includeDirective: 'include /etc/intranet-frp/sites/nginx/*.conf;',
    backupPath: '',
    injectedAt: 1,
    probe: {
      path: '/etc/intranet-frp/sites/nginx/default.conf',
      token: 'probe-token',
      ok: true,
      checkedAt: 1,
    },
  };

  it('非标 vhostHTTPPort + nginx + 注入探针生效判定为方案 A 且允许申请', () => {
    const plan = decideTlsPlan({
      httpPort: 8080,
      hostInfo: hostWithNginx,
      webInclude: injected,
    });
    expect(plan.mode).toBe('server');
    expect(plan.canIssue).toBe(true);
    expect(plan.checks.every((item) => item.ok)).toBe(true);
    expect(plan.reason).toContain('服务器');
  });

  it('标准 80 端口只用方案 B，环境探测不阻止申请', () => {
    const plan = decideTlsPlan({ httpPort: 80, hostInfo: undefined });
    expect(plan.mode).toBe('local');
    expect(plan.canIssue).toBe(true);
    expect(plan.checks.filter((item) => item.required && !item.ok)).toHaveLength(0);
  });

  it('探测结果缺失时不误断言为“非 root 且无免密 sudo”', () => {
    const plan = decideTlsPlan({ httpPort: 8080, hostInfo: undefined, webInclude: injected });
    expect(plan.mode).toBe('server');
    expect(plan.warnings.some((w) => w.includes('尚未读取到服务器 SSH 探测结果'))).toBe(true);
    expect(plan.warnings.some((w) => w.includes('非 root 且无免密 sudo'))).toBe(false);
  });

  it('探测到 root + 免密 sudo + nginx 时不出现权限告警', () => {
    const plan = decideTlsPlan({
      httpPort: 8080,
      hostInfo: { ...hostWithNginx, root: true, sudo: true },
      webInclude: injected,
    });
    expect(plan.canIssue).toBe(true);
    expect(plan.warnings.some((w) => w.includes('sudo'))).toBe(false);
  });

  it('非标端口下 web 服务、注入记录、探针任一失败仍为方案 A 但阻止申请', () => {
    const base = { httpPort: 8080, hostInfo: hostWithNginx, webInclude: injected };
    const noWeb = decideTlsPlan({ ...base, hostInfo: { ...hostWithNginx, webServices: [] } });
    const probeFailed = decideTlsPlan({
      ...base,
      probe: { ...injected.probe!, ok: false },
    });
    const noInclude = decideTlsPlan({ httpPort: 8080, hostInfo: hostWithNginx });
    const unknownPort = decideTlsPlan({ hostInfo: hostWithNginx, webInclude: injected });
    for (const plan of [noWeb, probeFailed, noInclude, unknownPort]) {
      expect(plan.mode).toBe('server');
      expect(plan.canIssue).toBe(false);
      expect(plan.blockers.length).toBeGreaterThan(0);
    }
    // 443 占用只在 warnings 中提示，不参与决策。
    expect(plan443Warning(probeFailed)).toBe(true);
  });

  it('方案 A 模板同时生成 listen 80 与 listen 443 ssl 两个 server 块并回源 httpPort', () => {
    const config = nginxTlsServerConfig({
      domains: ['a.example.com', 'b.example.com'],
      certPath: '/etc/intranet-frp/sites/nginx/certs/id.crt',
      keyPath: '/etc/intranet-frp/sites/nginx/certs/id.key',
      httpPort: 8080,
      certificateId: 'cert-1',
    });
    expect(config).toContain('listen 443 ssl;');
    expect(config).toContain('listen 80;');
    expect(config.match(/server \{/g)).toHaveLength(2);
    expect(config).toContain('server_name a.example.com b.example.com;');
    expect(config).toContain('proxy_pass http://127.0.0.1:8080;');
    expect(config).toContain('ssl_certificate /etc/intranet-frp/sites/nginx/certs/id.crt;');
  });

  it('HTTP-01 challenge server 只绑定目标域名并限制 challenge 路径', () => {
    const config = nginxHttp01ServerConfig({
      domains: ['a.example.com'],
      root: '/etc/intranet-frp/acme',
    });
    expect(config).toContain('listen 80;');
    expect(config).toContain('server_name a.example.com;');
    expect(config).toContain('location /.well-known/acme-challenge/');
    expect(config).not.toContain('default_server');
  });

  it('方案 A 的站点模板按 tlsMode=server 生成 ssl server 块', () => {
    const config = generateSiteConfig({
      rule: {
        id: 'r1',
        name: 'web',
        type: 'http',
        localIP: '127.0.0.1',
        localPort: 3000,
        domains: ['a.example.com'],
        tlsMode: 'passthrough',
        certPath: '',
        keyPath: '',
        publicHttps: true,
      },
      server: { httpPort: 8080 } as never,
      hostInfo: hostWithNginx,
      tlsMode: 'server',
    });
    expect(config.content).toContain('listen 443 ssl;');
    expect(config.content).toContain('listen 80;');
    expect(config.content).toContain('proxy_pass http://127.0.0.1:8080;');
    expect(config.content).not.toContain('stream {');
  });

  it('签发时普通 http 规则显式标记 publicHttps 后生成 443 ssl 块', () => {
    // 复现真实签发路径：规则此刻仍未标记 publicHttps（部署成功后才由 convertRulesToServerTls 置位）。
    const original = {
      id: 'r2',
      name: 'web',
      type: 'http' as const,
      localIP: '127.0.0.1',
      localPort: 3000,
      domains: ['a.example.com'],
      tlsMode: 'passthrough' as const,
      certPath: '',
      keyPath: '',
      publicHttps: false,
    };
    const generated = generateSiteConfig({
      rule: { ...original, publicHttps: true },
      server: { httpPort: 8080 } as never,
      hostInfo: hostWithNginx,
      tlsMode: 'server',
      certificateId: 'cert-1',
    }).content;
    expect(generated).toContain('listen 443 ssl;');
    expect(generated).toContain('listen 80;');
    expect(generated).toContain('cert-1.crt');
    expect(generated).not.toContain('<证书ID>');
    expect(
      resolveTlsSiteConfig({
        siteConfig: generated,
        domains: ['a.example.com'],
        certPath: '/x/cert-1.crt',
        keyPath: '/x/cert-1.key',
        httpPort: 8080,
        certificateId: 'cert-1',
      }).trim(),
    ).toBe(generated.trim());
  });

  it('写入端拒绝非 TLS 模板并退回内置 80 + 443 ssl 配置', () => {
    const fallback = resolveTlsSiteConfig({
      siteConfig: 'server { listen 80; server_name a.example.com; }',
      domains: ['a.example.com'],
      certPath: '/x/cert-1.crt',
      keyPath: '/x/cert-1.key',
      httpPort: 8080,
      certificateId: 'cert-1',
    });
    expect(fallback).toContain('listen 443 ssl;');
    expect(fallback).toContain('listen 80;');
    expect(fallback).toContain('ssl_certificate /x/cert-1.crt;');
    expect(fallback).toContain('proxy_pass http://127.0.0.1:8080;');
  });

  it('已有旧 TLS 配置只有 443 时合并补齐 HTTP server 块并保留用户改动', () => {
    const old = `# 用户自定义
server {
    listen 443 ssl;
    server_name a.example.com;
    ssl_certificate /old/cert.crt;
    ssl_certificate_key /old/cert.key;
    add_header X-Custom yes;
}`;
    const merged = mergeTlsSiteConfig({
      existing: old,
      generated: nginxTlsServerConfig({
        domains: ['a.example.com'],
        certPath: '/x/cert-1.crt',
        keyPath: '/x/cert-1.key',
        httpPort: 8080,
        certificateId: 'cert-1',
      }),
      domains: ['a.example.com'],
      certPath: '/x/cert-1.crt',
      keyPath: '/x/cert-1.key',
      httpPort: 8080,
    });
    expect(merged).toContain('# 用户自定义');
    expect(merged).toContain('add_header X-Custom yes;');
    expect(merged).toContain('ssl_certificate /x/cert-1.crt;');
    expect(merged).toContain('listen 443 ssl;');
    expect(merged).toContain('listen 80;');
    expect(merged.match(/server \{/g)).toHaveLength(2);
  });
});

describe('隐藏 HTTPS 伴随规则与证书回退', () => {
  const baseRule = {
    id: 'rule-1',
    name: 'web',
    type: 'http' as const,
    localIP: '127.0.0.1',
    localPort: 3000,
    domains: ['a.example.com'],
    tlsMode: 'passthrough' as const,
    certPath: '',
    keyPath: '',
  };

  it('HTTP 与隐藏 HTTPS 规则可共用域名，用户 HTTP 规则保持不变', () => {
    const instance: Instance = {
      id: 'instance-1',
      name: 'local',
      serverId: 'server-1',
      versionKey: 'v1',
      mode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      proxies: [baseRule],
    };
    const refs = ensureHiddenHttpsRules(instance, [baseRule], 'cert-1');
    expect(refs).toHaveLength(1);
    expect(instance.proxies[0]).toEqual(baseRule);
    const hidden = instance.proxies[1];
    expect(hidden).toMatchObject({
      type: 'https',
      hidden: true,
      sourceRuleId: 'rule-1',
      certificateId: 'cert-1',
      tlsMode: 'terminate',
    });
    expect(() => validateRules(instance.proxies)).not.toThrow();
    restoreHiddenRules([instance], refs);
    expect(instance.proxies).toEqual([baseRule]);
  });

  it('方案 A 模板使用真实证书路径，访问地址按公网 HTTPS 显示', () => {
    const config = generateSiteConfig({
      rule: { ...baseRule, publicHttps: true },
      server: { httpPort: 8080 } as never,
      tlsMode: 'server',
      certificateId: 'cert-abc',
    });
    expect(config.content).toContain('/etc/intranet-frp/sites/nginx/certs/cert-abc.crt');
    expect(accessAddress({ ...baseRule, publicHttps: true }, { httpPort: 8080 } as never)).toBe(
      'https://a.example.com',
    );
  });
});

function plan443Warning(plan: ReturnType<typeof decideTlsPlan>): boolean {
  return plan.warnings.some((warning) => warning.includes('443'));
}

describe('DNS 管理：域名与解析记录 CRUD', () => {
  function accountStore(): Store {
    return {
      secret: (key: string) =>
        ({
          'dns:account:acc-1:secretId': 'sid',
          'dns:account:acc-1:secretKey': 'skey',
          'dns:account:acc-1:token': 'tk',
        })[key] ?? '',
    } as unknown as Store;
  }
  function jsonResponse(body: unknown): Response {
    return new Response(JSON.stringify(body), { status: 200 });
  }

  it('DNSPod 读取域名与记录，并把子域名还原成完整记录名', async () => {
    const calls: { url: string; body?: string }[] = [];
    vi.stubGlobal('fetch', async (url: string, init?: { body?: string }) => {
      calls.push({ url, body: init?.body });
      if (url.includes('Domain.List'))
        return jsonResponse({ status: { code: '1' }, domains: [{ name: 'example.com' }] });
      return jsonResponse({
        status: { code: '1' },
        records: [
          { id: 'r1', name: 'www', type: 'A', value: '1.2.3.4', ttl: 600, line: '默认' },
          { id: 'r2', name: '@', type: 'MX', value: 'mail.example.com', ttl: 600, mx: 10 },
        ],
      });
    });
    const adapter = manageAdapterForAccount('dnspod', accountStore(), 'acc-1');
    const domains = await adapter.listDomains();
    expect(domains).toEqual([{ name: 'example.com' }]);
    const records = await adapter.listRecords('example.com');
    expect(records[0]).toMatchObject({ name: 'www.example.com', type: 'A', value: '1.2.3.4' });
    expect(records[1]).toMatchObject({ name: '@', type: 'MX', priority: 10 });
    vi.unstubAllGlobals();
  });

  it('DNSPod 新增/更新/删除记录都带上正确的子域名与记录 ID', async () => {
    const calls: { url: string; body?: string }[] = [];
    vi.stubGlobal('fetch', async (url: string, init?: { body?: string }) => {
      calls.push({ url, body: init?.body });
      return jsonResponse({ status: { code: '1' }, record: { id: 'new-1' } });
    });
    const adapter = manageAdapterForAccount('dnspod', accountStore(), 'acc-1');
    const input = { name: 'www.example.com', type: 'A', value: '5.6.7.8', ttl: 600 };
    await adapter.createRecord('example.com', input);
    expect(calls[0].url).toContain('Record.Create');
    expect(calls[0].body).toContain('sub_domain=www');
    await adapter.updateRecord('example.com', 'r1', input);
    expect(calls[1].url).toContain('Record.Modify');
    expect(calls[1].body).toContain('record_id=r1');
    await adapter.deleteRecord('example.com', 'r1');
    expect(calls[2].url).toContain('Record.Remove');
    expect(calls[2].body).toContain('record_id=r1');
    vi.unstubAllGlobals();
  });

  it('阿里云新增记录把 TTL 抬到最小 600，避免 QuotaExceeded.TTL', async () => {
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(url);
      return jsonResponse({ RecordId: '123' });
    });
    const adapter = manageAdapterForAccount('aliyun', accountStore(), 'acc-1');
    await adapter.createRecord('example.com', {
      name: 'www.example.com',
      type: 'A',
      value: '1.1.1.1',
      ttl: 60,
    });
    expect(urls[0]).toContain('Action=AddDomainRecord');
    expect(decodeURIComponent(urls[0])).toContain('TTL=600');
    vi.unstubAllGlobals();
  });

  it('Cloudflare 读取域名列表并新增记录到对应 zone', async () => {
    const calls: { url: string; init?: { method?: string; body?: string } }[] = [];
    vi.stubGlobal('fetch', async (url: string, init?: { method?: string; body?: string }) => {
      calls.push({ url, init });
      if (url.includes('/zones?'))
        return jsonResponse({ success: true, result: [{ id: 'zone-1', name: 'example.com' }] });
      if (url.includes('/dns_records') && init?.method === 'POST')
        return jsonResponse({ success: true, result: { id: 'rec-1' } });
      return jsonResponse({ success: true, result: [] });
    });
    const adapter = manageAdapterForAccount('cloudflare', accountStore(), 'acc-1');
    const domains = await adapter.listDomains();
    expect(domains).toEqual([{ name: 'example.com' }]);
    await adapter.createRecord('example.com', {
      name: 'www.example.com',
      type: 'A',
      value: '2.2.2.2',
      ttl: 1,
    });
    expect(calls.some((c) => c.init?.method === 'POST')).toBe(true);
    vi.unstubAllGlobals();
  });
});
