import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { notifyRenderer } from '../src/main/lifecycle';
import { releaseAssets, releaseTags, Versions } from '../src/main/versions';
import { Store } from '../src/main/store';

const assets =
  '<a href="/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_darwin_amd64.tar.gz">包</a>';
const page = `<a href="/fatedier/frp/releases/tag/v0.71.0">v0.71.0</a>${assets}<a href="/fatedier/frp/releases?page=2">下一页</a>`;

describe('退出时的异步状态通知', () => {
  it('正常运行时发送，开始退出后不再访问窗口对象', () => {
    const send = vi.fn();
    const window = {
      isDestroyed: vi.fn(() => false),
      webContents: { isDestroyed: () => false, send },
    };
    notifyRenderer(window, false);
    expect(send).toHaveBeenCalledOnce();
    window.isDestroyed.mockImplementation(() => {
      throw new Error('不应访问退出窗口');
    });
    expect(() => notifyRenderer(window, true)).not.toThrow();
    expect(send).toHaveBeenCalledOnce();
  });
  it('窗口或 webContents 销毁、窗口引用清除后，不发送通知', () => {
    const send = vi.fn();
    notifyRenderer(undefined, false);
    notifyRenderer(
      { isDestroyed: () => true, webContents: { isDestroyed: () => false, send } },
      false,
    );
    notifyRenderer(
      { isDestroyed: () => false, webContents: { isDestroyed: () => true, send } },
      false,
    );
    expect(send).not.toHaveBeenCalled();
  });
});

describe('官方发布页面自动兜底', () => {
  it('只接受正式版本与指定版本的官方安装包，不生成猜测链接', () => {
    expect(
      releaseTags(`${page}<a href='/fatedier/frp/releases/tag/v0.72.0-beta'>预览</a>`),
    ).toEqual(['v0.71.0']);
    const links = releaseAssets(
      `${assets}<a href="https://evil.example/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_windows_amd64.zip">伪装</a><a href="/fatedier/frp/releases/download/v0.70.0/frp_0.70.0_windows_amd64.zip">其他版本</a>`,
      'v0.71.0',
    );
    expect(links).toEqual([
      {
        name: 'frp_0.71.0_darwin_amd64.tar.gz',
        url: 'https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_darwin_amd64.tar.gz',
      },
    ]);
  });
  it('冷启动 API 限流仍取得可下载列表，冷却期翻页不重复请求 API', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'intranet-catalog-'));
    try {
      const store = new Store(root, {
        available: () => false,
        encrypt: () => Buffer.alloc(0),
        decrypt: () => '',
      });
      await store.load();
      const fetcher = vi.fn(async (url: string) =>
        url.includes('api.github.com')
          ? new Response('', { status: 403, headers: { 'x-ratelimit-remaining': '0' } })
          : new Response(page),
      );
      const versions = new Versions(store, fetcher, async () => '');
      const result = await versions.catalog();
      expect(result.source).toBe('github-web');
      expect(result.cached).toBe(false);
      expect(result.hasMore).toBe(true);
      expect(result.releases[0].assets).toHaveLength(1);
      await versions.catalog(2);
      expect(fetcher.mock.calls.filter(([url]) => url.includes('api.github.com'))).toHaveLength(1);
      versions.resetNetworkState();
      await versions.catalog();
      expect(fetcher.mock.calls.filter(([url]) => url.includes('api.github.com'))).toHaveLength(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it('懒加载安装包走官方资源端点；两条网络路径都失败后使用缓存', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'intranet-catalog-'));
    try {
      const store = new Store(root, {
        available: () => false,
        encrypt: () => Buffer.alloc(0),
        decrypt: () => '',
      });
      await store.load();
      let offline = false;
      const fetcher = vi.fn(async (url: string) => {
        if (offline) throw new Error('ETIMEDOUT');
        if (url.includes('api.github.com')) return new Response('', { status: 429 });
        return new Response(
          url.includes('expanded_assets')
            ? assets
            : '<a href="/fatedier/frp/releases/tag/v0.71.0">版本</a>',
        );
      });
      const versions = new Versions(store, fetcher, async () => '');
      expect((await versions.catalog()).releases[0].assets).toHaveLength(1);
      expect(fetcher.mock.calls.some(([url]) => url.endsWith('/expanded_assets/v0.71.0'))).toBe(
        true,
      );
      offline = true;
      const cached = await versions.catalog();
      expect(cached.cached).toBe(true);
      expect(cached.source).toBe('github-web');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
