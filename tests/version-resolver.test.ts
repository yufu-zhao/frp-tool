import { describe, expect, it, vi } from 'vitest';
import { VersionResolver } from '../src/main/version-resolver';
import { CHECKSUM_UNAVAILABLE } from '../src/shared/contracts';
import type { Catalog, DownloadProgress, InstalledVersion } from '../src/shared/types';

function makeCatalog(version = '0.71.0', platform = 'darwin', arch = 'arm64'): Catalog {
  const name = `frp_${version}_${platform}_${arch}.${platform === 'windows' ? 'zip' : 'tar.gz'}`;
  return {
    source: 'api',
    releases: [
      {
        version,
        publishedAt: '2026-01-01T00:00:00.000Z',
        assets: [
          {
            name,
            url: `https://github.com/fatedier/frp/releases/download/v${version}/${name}`,
            digest: `sha256:${'a'.repeat(64)}`,
          },
        ],
      },
    ],
    updatedAt: '2026-01-01T00:00:00.000Z',
    cached: true,
    page: 1,
    hasMore: false,
  };
}

function installed(key: string): InstalledVersion {
  return {
    key,
    version: key.split('_')[0],
    platform: 'darwin',
    arch: 'arm64',
    directory: '/tmp/frp/bin',
    source: 'test',
    installedAt: '',
    verified: true,
    digest: 'a'.repeat(64),
  };
}

function makeStore(
  overrides: { servers?: unknown[]; versions?: InstalledVersion[]; catalog?: Catalog | null } = {},
) {
  return {
    data: {
      servers: overrides.servers ?? [],
      versions: overrides.versions ?? [],
      catalog: overrides.catalog === undefined ? makeCatalog() : overrides.catalog,
    },
  };
}

function makeVersions(
  options: {
    digest?: string;
    catalog?: Catalog;
    installError?: Error;
  } = {},
) {
  const calls: Array<{ request: Record<string, unknown>; options: Record<string, unknown> }> = [];
  return {
    calls,
    async resolveReleaseDigest(request: Record<string, unknown>) {
      return options.digest ? { ...request, digest: options.digest } : request;
    },
    async catalog() {
      return options.catalog ?? makeCatalog();
    },
    async install(request: Record<string, unknown>, installOptions: Record<string, unknown>) {
      calls.push({ request, options: installOptions });
      if (options.installError) throw options.installError;
      const key = `${request.version}_${request.platform}_${request.arch}`;
      const onProgress = installOptions.onProgress as (p: DownloadProgress) => void;
      onProgress?.({
        taskId: String(request.taskId),
        key,
        version: String(request.version),
        status: 'succeeded',
        percent: 100,
        received: 1,
        total: 1,
        speed: 0,
        attempt: 1,
        resumable: true,
        message: '安装完成。',
        updatedAt: Date.now(),
      });
      return installed(key);
    },
  };
}

function resolverFor(
  store: unknown,
  versions: unknown,
  events: DownloadProgress[] = [],
  changed = vi.fn(),
) {
  return new VersionResolver(
    store as never,
    versions as never,
    (progress) => events.push(progress),
    changed,
  );
}

describe('VersionResolver.resolve - 使用点版本决策', () => {
  it('客户端版本号跟随所选服务器已部署版本，架构按本机', () => {
    const store = makeStore({
      servers: [{ id: 's1', name: '主服务器', deployment: { version: '0.70.0' } }],
    });
    const result = resolverFor(store, makeVersions()).resolve({
      purpose: 'client',
      serverId: 's1',
      platform: 'darwin',
      arch: 'arm64',
    });
    expect(result.version).toBe('0.70.0');
    expect(result.source).toBe('server-deployment');
    expect(result.key).toBe('0.70.0_darwin_arm64');
    expect(result.note).toContain('跟随服务器');
  });

  it('服务端用途强制 Linux 平台并使用探测到的架构', () => {
    const result = resolverFor(makeStore(), makeVersions()).resolve({
      purpose: 'server',
      platform: 'darwin',
      arch: 'amd64',
    });
    expect(result.platform).toBe('linux');
    expect(result.arch).toBe('amd64');
    expect(result.version).toBe('0.71.0');
  });

  it('服务器尚未部署时取本地列表最新稳定版并提示改为一致', () => {
    const result = resolverFor(
      makeStore({ servers: [{ id: 's1', name: '新服务器' }] }),
      makeVersions(),
    ).resolve({ purpose: 'client', serverId: 's1', platform: 'darwin', arch: 'arm64' });
    expect(result.version).toBe('0.71.0');
    expect(result.source).toBe('latest-cached');
    expect(result.note).toContain('尚未部署');
  });

  it('探测到不支持的架构时不静默猜测', () => {
    const result = resolverFor(makeStore(), makeVersions()).resolve({
      purpose: 'server',
      arch: 'armv7l',
    });
    expect(result.archSupported).toBe(false);
    expect(result.available).toBe(false);
    expect(result.note).toContain('只支持 amd64 / arm64');
  });

  it('没有本地版本列表时给出明确提示而不是编造版本', () => {
    const result = resolverFor(makeStore({ servers: [], catalog: null }), makeVersions()).resolve({
      purpose: 'server',
      arch: 'amd64',
    });
    expect(result.version).toBe('');
    expect(result.source).toBe('unavailable');
    expect(result.note).toContain('尚未获取官方版本列表');
  });
});

describe('VersionResolver.ensure - 自动准备安装包', () => {
  it('命中已安装版本时直接复用，不触发下载也不产生进度占位', async () => {
    const existing = installed('0.71.0_darwin_arm64');
    const versions = makeVersions();
    const events: DownloadProgress[] = [];
    const result = await resolverFor(makeStore({ versions: [existing] }), versions, events).ensure({
      taskId: 't1',
      purpose: 'client',
      platform: 'darwin',
      arch: 'arm64',
    });
    expect(result.prepared).toBe(false);
    expect(result.version).toBe(existing);
    expect(versions.calls).toHaveLength(0);
    expect(events).toHaveLength(0);
  });

  it('未安装时自动下载，并在调用瞬间就上报 starting 事件', async () => {
    const versions = makeVersions({ digest: 'a'.repeat(64) });
    const events: DownloadProgress[] = [];
    const changed = vi.fn();
    const result = await resolverFor(makeStore(), versions, events, changed).ensure({
      taskId: 't2',
      purpose: 'client',
      platform: 'darwin',
      arch: 'arm64',
    });
    expect(result.prepared).toBe(true);
    expect(versions.calls).toHaveLength(1);
    expect(String(versions.calls[0].request.url)).toContain('frp_0.71.0_darwin_arm64.tar.gz');
    expect(events[0].status).toBe('starting');
    expect(events[0].purpose).toBe('client');
    expect(events.at(-1)?.status).toBe('succeeded');
    expect(changed).toHaveBeenCalledOnce();
  });

  it('取不到官方 SHA256 且未确认时抛特定错误，便于渲染层弹确认', async () => {
    const catalog = makeCatalog();
    catalog.releases[0].assets[0].digest = undefined;
    const events: DownloadProgress[] = [];
    const versions = makeVersions();
    await expect(
      resolverFor(makeStore({ catalog }), versions, events).ensure({
        taskId: 't3',
        purpose: 'client',
        platform: 'darwin',
        arch: 'arm64',
      }),
    ).rejects.toMatchObject({ code: CHECKSUM_UNAVAILABLE });
    expect(versions.calls).toHaveLength(0);
    expect(events.some((item) => item.status === 'failed')).toBe(true);
  });

  it('本地列表缺少目标版本时强制刷新一次官方列表', async () => {
    const versions = makeVersions({ digest: 'a'.repeat(64), catalog: makeCatalog('0.72.0') });
    const catalogSpy = vi.spyOn(versions, 'catalog');
    // 强制刷新回来的列表是 darwin/arm64，与 linux/amd64 不匹配，应明确失败而不是静默装错包。
    await expect(
      resolverFor(makeStore(), versions).ensure({
        taskId: 't4',
        purpose: 'server',
        version: '0.72.0',
        arch: 'amd64',
      }),
    ).rejects.toMatchObject({ code: 'NO_ASSET' });
    expect(catalogSpy).toHaveBeenCalledWith(1, { force: true });
  });
});
