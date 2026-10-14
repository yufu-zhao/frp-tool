import {
  mkdir,
  readFile,
  writeFile,
  rename,
  rm,
  readdir,
  stat,
  chmod,
  copyFile,
} from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import * as tar from 'tar';
import yauzl from 'yauzl';
import type { Asset, Catalog, Release, InstallRequest, InstalledVersion } from '../shared/types';
import { AppError, friendlyError } from '../shared/errors';
import { Store } from './store';
import { frpAdapter } from './frp';

export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;
const MAX_PACKAGE = 200 * 1024 * 1024;
export function normalizeReleases(input: unknown): Release[] {
  if (!Array.isArray(input))
    throw new AppError('版本接口返回了非列表内容，请检查代理或稍后重试。', 'BAD_RESPONSE');
  return input.flatMap((value) => {
    if (!value || typeof value !== 'object') return [];
    const raw = value as Record<string, unknown>;
    if (
      raw.draft ||
      raw.prerelease ||
      typeof raw.tag_name !== 'string' ||
      !/^v?\d+\.\d+\.\d+$/.test(raw.tag_name)
    )
      return [];
    const assets: Asset[] = Array.isArray(raw.assets)
      ? raw.assets.flatMap((item) => {
          if (
            !item ||
            typeof item.name !== 'string' ||
            typeof item.browser_download_url !== 'string' ||
            !item.browser_download_url.startsWith('https://')
          )
            return [];
          return [
            {
              name: item.name,
              url: item.browser_download_url,
              digest: typeof item.digest === 'string' ? item.digest : undefined,
              size: typeof item.size === 'number' ? item.size : undefined,
            },
          ];
        })
      : [];
    return [
      {
        version: raw.tag_name.replace(/^v/, ''),
        publishedAt: typeof raw.published_at === 'string' ? raw.published_at : '',
        assets,
      },
    ];
  });
}
// 仅读取 GitHub 官方语义链接，不依赖页面样式、脚本或第三方镜像。
export function releaseTags(html: string): string[] {
  return [
    ...new Set(
      [
        ...html.matchAll(
          /href=["'](?:https:\/\/github\.com)?\/fatedier\/frp\/releases\/tag\/(v?\d+\.\d+\.\d+)["']/g,
        ),
      ].map((match) => match[1]),
    ),
  ];
}
export function releaseAssets(html: string, tag: string): Asset[] {
  const version = tag.replace(/^v/, '');
  const found = new Map<string, Asset>();
  for (const match of html.matchAll(/href=["']([^"']+)["']/g)) {
    try {
      const url = new URL(match[1].replace(/&amp;/g, '&'), 'https://github.com');
      if (
        url.origin !== 'https://github.com' ||
        !url.pathname.startsWith(`/fatedier/frp/releases/download/${tag}/`)
      )
        continue;
      const name = decodeURIComponent(url.pathname.split('/').pop()!);
      if (!name.startsWith(`frp_${version}_`) || !/\.(tar\.gz|zip)$/.test(name)) continue;
      found.set(name, { name, url: url.toString() });
    } catch {
      /* 忽略不合法链接，避免异常字段影响整页版本。 */
    }
  }
  return [...found.values()];
}
// 只从对应版本区块的语义时间标签读取发布日期，避免误读提交时间。
export function releasePublishedAt(html: string, tag: string): string {
  const marker = `data-release-anchor="release-${tag}"`;
  const start = html.indexOf(marker);
  if (start < 0) return '';
  const next = html.indexOf('data-release-anchor="release-v', start + marker.length);
  const section = html.slice(start, next < 0 ? undefined : next);
  const value = section.match(/<relative-time\b[^>]*\bdatetime=["']([^"']+)["']/i)?.[1];
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}
// 校验清单中的文件名必须与目标安装包完全一致，避免错配摘要。
export function checksumForAsset(contents: string, assetName: string): string | undefined {
  for (const line of contents.split(/\r?\n/)) {
    const match = line.trim().match(/^([a-f\d]{64})\s+\*?(.+?)\s*$/i);
    if (match?.[2] === assetName) return match[1].toLowerCase();
  }
  return undefined;
}
export function versionKey(request: Pick<InstallRequest, 'version' | 'platform' | 'arch'>) {
  return `${request.version.replace(/^v/, '')}_${request.platform}_${request.arch}`;
}
export function chooseAsset(release: Release, platform: string, arch: string): Asset {
  const name = `frp_${release.version}_${platform}_${arch}.${platform === 'windows' ? 'zip' : 'tar.gz'}`;
  const asset = release.assets.find((a) => a.name === name);
  if (!asset)
    throw new AppError(
      `版本 ${release.version} 没有 ${platform}/${arch} 安装包，请换版本或导入本地包。`,
      'NO_ASSET',
    );
  return asset;
}
// 压缩包只提取两个可执行文件，不执行包内脚本、不保留软链接。
export async function extractBinaries(archive: string, destination: string, platform: string) {
  await mkdir(destination, { recursive: true, mode: 0o700 });
  const wanted = new Set(
    ['client', 'server'].map((role) => frpAdapter.binary(role as 'client' | 'server', platform)),
  );
  const seen = new Set<string>();
  if (platform === 'windows') {
    await new Promise<void>((resolve, reject) => {
      yauzl.open(archive, { lazyEntries: true }, (error, zip) => {
        if (error || !zip) return reject(error ?? new Error('无法打开 ZIP'));
        let total = 0;
        const fail = (e: unknown) => {
          zip.close();
          reject(e);
        };
        zip.on('error', fail);
        zip.on('end', resolve);
        zip.on('entry', (entry: yauzl.Entry) => {
          const name = path.posix.basename(entry.fileName);
          if (!wanted.has(name)) return zip.readEntry();
          if (
            entry.fileName.includes('..') ||
            ((entry.externalFileAttributes >>> 16) & 0o170000) === 0o120000 ||
            seen.has(name)
          )
            return fail(new AppError('安装包包含不安全或重复文件。'));
          total += entry.uncompressedSize;
          if (total > MAX_PACKAGE) return fail(new AppError('解压后的安装包超过大小限制。'));
          seen.add(name);
          zip.openReadStream(entry, (err, stream) => {
            if (err || !stream) return fail(err);
            pipeline(stream, createWriteStream(path.join(destination, name), { mode: 0o700 })).then(
              () => zip.readEntry(),
              fail,
            );
          });
        });
        zip.readEntry();
      });
    });
  } else {
    let total = 0;
    let invalid: string | undefined;
    await tar.x({
      file: archive,
      cwd: destination,
      strict: true,
      preservePaths: false,
      filter: (name, entry) => {
        const basename = path.posix.basename(name);
        if (!wanted.has(basename)) return false;
        if (
          !('type' in entry) ||
          entry.type !== 'File' ||
          name.split('/').includes('..') ||
          name.startsWith('/') ||
          seen.has(basename)
        ) {
          invalid = '安装包包含不安全或重复文件。';
          return false;
        }
        total += entry.size;
        if (total > MAX_PACKAGE) {
          invalid = '解压后的安装包超过大小限制。';
          return false;
        }
        seen.add(basename);
        return true;
      },
    });
    if (invalid) throw new AppError(invalid);
    // 官方包多一层目录，提取后统一放到版本根目录。
    async function collect(dir: string): Promise<void> {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        const source = path.join(dir, entry.name);
        if (entry.isDirectory()) await collect(source);
        else if (wanted.has(entry.name) && dir !== destination)
          await copyFile(source, path.join(destination, entry.name));
      }
    }
    await collect(destination);
  }
  for (const name of wanted) {
    if (!seen.has(name)) throw new AppError(`安装包缺少 ${name}，请提供完整 FRP 安装包。`);
    await chmod(path.join(destination, name), 0o700);
  }
}
export async function sha256(file: string) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
export class Versions {
  private apiRetryAt = 0;
  private apiWarning = '';
  resetNetworkState() {
    this.apiRetryAt = 0;
    this.apiWarning = '';
  }
  private installing = new Set<string>();
  constructor(
    private store: Store,
    private fetcher: Fetcher,
    private checkBinary: (file: string) => Promise<string>,
  ) {}
  private async apiCatalog(page: number): Promise<Catalog> {
    if (Date.now() < this.apiRetryAt) throw new AppError(this.apiWarning);
    const response = await this.fetcher(
      `https://api.github.com/repos/fatedier/frp/releases?per_page=10&page=${page}`,
      {
        signal: AbortSignal.timeout(15000),
        headers: {
          Accept: 'application/vnd.github+json',
          'User-Agent': 'Intranet-FRP-Desktop',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      },
    );
    if (!response.ok) {
      const limited =
        response.status === 429 || response.headers.get('x-ratelimit-remaining') === '0';
      const message = limited
        ? 'GitHub API 已限流'
        : `GitHub API 查询失败（HTTP ${response.status}）`;
      if (response.status === 403 || response.status === 429) {
        const reset = Number(response.headers.get('x-ratelimit-reset')) * 1000;
        this.apiRetryAt =
          reset > Date.now() ? Math.min(reset, Date.now() + 3600000) : Date.now() + 60000;
        this.apiWarning = message;
      }
      throw new AppError(message);
    }
    const raw: unknown = await response.json();
    const releases = normalizeReleases(raw);
    if (Array.isArray(raw) && raw.length && !releases.length)
      throw new AppError('接口内容缺少有效发布版本。');
    return {
      releases,
      updatedAt: new Date().toISOString(),
      cached: false,
      source: 'api',
      page,
      hasMore: Array.isArray(raw) && raw.length === 10,
    };
  }
  private async webCatalog(page: number): Promise<Catalog> {
    const response = await this.fetcher(`https://github.com/fatedier/frp/releases?page=${page}`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) throw new AppError(`官方发布页面请求失败（HTTP ${response.status}）。`);
    const html = await response.text();
    const tags = releaseTags(html).slice(0, 10);
    if (!tags.length) throw new AppError('官方发布页面未包含可识别版本，未生成猜测版本。');
    const releases: Release[] = tags.map((tag) => ({
      version: tag.replace(/^v/, ''),
      publishedAt: releasePublishedAt(html, tag),
      assets: releaseAssets(html, tag),
    }));
    const missing = releases
      .map((release, index) => ({ release, tag: tags[index] }))
      .filter((item) => !item.release.assets.length);
    // 部分页面懒加载资源，最多四个并发请求；只接受实际列出的官方下载链接。
    for (let index = 0; index < missing.length; index += 4) {
      await Promise.all(
        missing.slice(index, index + 4).map(async ({ release, tag }) => {
          try {
            const assets = await this.fetcher(
              `https://github.com/fatedier/frp/releases/expanded_assets/${tag}`,
              { signal: AbortSignal.timeout(10000) },
            );
            if (!assets.ok) throw new AppError(`HTTP ${assets.status}`);
            release.assets = releaseAssets(await assets.text(), tag);
            if (!release.assets.length) throw new AppError('页面未包含可下载安装包');
          } catch (error) {
            release.assetError = `安装包列表获取失败：${friendlyError(error)}`;
          }
        }),
      );
    }
    if (releases.every((release) => !release.assets.length))
      throw new AppError('官方页面安装包列表获取失败。');
    return {
      releases,
      updatedAt: new Date().toISOString(),
      cached: false,
      source: 'github-web',
      page,
      hasMore: new RegExp(`[?&]page=${page + 1}(?:["'&]|&amp;)`).test(html),
    };
  }
  async catalog(page = 1): Promise<Catalog> {
    const cache = path.join(this.store.root, `releases-${page}.json`);
    let result: Catalog;
    try {
      result = await this.apiCatalog(page);
    } catch (apiError) {
      try {
        result = await this.webCatalog(page);
        result.warning = `${friendlyError(apiError)}，已自动切换到 GitHub 官方发布页面。${result.releases.some((release) => release.assetError) ? '部分版本安装包列表未取得，可刷新重试。' : ''}`;
      } catch (webError) {
        try {
          const saved = JSON.parse(await readFile(cache, 'utf8')) as Catalog;
          if (!Array.isArray(saved.releases) || !saved.releases.length)
            throw new Error('缓存不可用');
          return {
            ...saved,
            cached: true,
            warning: `${friendlyError(apiError)}；${friendlyError(webError)}`,
          };
        } catch {
          throw new AppError(
            `${friendlyError(apiError)}；${friendlyError(webError)} 当前没有可用缓存，请检查下载网络或导入本地安装包。`,
            'CATALOG_FAILED',
          );
        }
      }
    }
    // 缓存写入失败不能让已成功取得的版本列表变成失败。
    try {
      await writeFile(`${cache}.tmp`, JSON.stringify(result), { mode: 0o600 });
      await rename(`${cache}.tmp`, cache);
    } catch {
      result.warning = `${result.warning ?? ''} 版本列表已获取，但本地缓存未能保存。`;
    }
    return result;
  }
  async resolveReleaseDigest(request: InstallRequest): Promise<InstallRequest> {
    if (request.digest || !request.url) return request;
    try {
      const source = new URL(request.url);
      const expectedName = `frp_${request.version.replace(/^v/, '')}_${request.platform}_${request.arch}.${request.platform === 'windows' ? 'zip' : 'tar.gz'}`;
      const match = source.pathname.match(
        /^\/fatedier\/frp\/releases\/download\/(v?\d+\.\d+\.\d+)\/([^/]+)$/,
      );
      if (
        source.origin !== 'https://github.com' ||
        !match ||
        match[1].replace(/^v/, '') !== request.version.replace(/^v/, '') ||
        match[2] !== expectedName
      )
        return request;
      const checksumUrl = new URL(
        `/fatedier/frp/releases/download/${match[1]}/frp_sha256_checksums.txt`,
        source.origin,
      );
      const response = await this.fetcher(checksumUrl.toString(), {
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok || Number(response.headers.get('content-length') ?? 0) > 262144)
        return request;
      const contents = await response.text();
      if (contents.length > 262144) return request;
      const digest = checksumForAsset(contents, expectedName);
      return digest ? { ...request, digest } : request;
    } catch {
      // 官方校验清单不可用时，安装流程会提示用户并要求确认来源。
      return request;
    }
  }
  async verifyInstalledRelease(key: string): Promise<InstalledVersion> {
    const installed = this.store.data.versions.find((item) => item.key === key);
    if (!installed) throw new AppError('找不到该本机版本。');
    if (installed.verified) return installed;
    const request = await this.resolveReleaseDigest({
      version: installed.version,
      platform: installed.platform,
      arch: installed.arch,
      url: installed.source,
    });
    if (!request.digest)
      throw new AppError('该安装来源没有可读取的 FRP 官方 SHA256 清单，请重新从官方发布页安装。');
    if (request.digest !== installed.digest)
      throw new AppError('本机安装包摘要与 FRP 官方清单不一致，请删除并重新下载安装。');
    installed.verified = true;
    await this.store.persist();
    return installed;
  }
  async install(request: InstallRequest): Promise<InstalledVersion> {
    const key = versionKey(request);
    if (this.installing.has(key)) throw new AppError('此版本正在安装，请等待完成。');
    if (this.store.data.versions.some((v) => v.key === key)) throw new AppError('此版本已经安装。');
    this.installing.add(key);
    const work = path.join(this.store.root, 'packages', `.install-${randomUUID()}`);
    const target = path.join(this.store.root, 'packages', key);
    try {
      await mkdir(work, { recursive: true, mode: 0o700 });
      const archive = path.join(work, 'archive');
      if (request.localPath) {
        if ((await stat(request.localPath)).size > MAX_PACKAGE) throw new AppError('安装包过大。');
        await copyFile(request.localPath, archive);
      } else {
        if (!request.url || !/^https?:\/\//.test(request.url))
          throw new AppError('请输入 HTTP/HTTPS 下载地址，或选择本地安装包。');
        const response = await this.fetcher(request.url, { signal: AbortSignal.timeout(120000) });
        if (!response.ok)
          throw new AppError(
            `安装包下载失败（HTTP ${response.status}），可重试或改用离线导入。`,
            'DOWNLOAD_FAILED',
          );
        if (!response.body || Number(response.headers.get('content-length') ?? 0) > MAX_PACKAGE)
          throw new AppError('安装包为空或超过大小限制。');
        let size = 0;
        const stream = Readable.from(
          (async function* () {
            for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
              size += chunk.length;
              if (size > MAX_PACKAGE) throw new AppError('安装包超过大小限制。');
              yield chunk;
            }
          })(),
        );
        await pipeline(stream, createWriteStream(archive, { mode: 0o600 }));
      }
      const digest = await sha256(archive);
      if (request.digest && !/^(sha256:)?[a-fA-F0-9]{64}$/.test(request.digest))
        throw new AppError('SHA256 校验值格式不正确。');
      if (request.digest && digest !== request.digest.replace(/^sha256:/, '').toLowerCase())
        throw new AppError('安装包 SHA256 校验失败，未安装。', 'CHECKSUM_FAILED');
      const unpacked = path.join(work, 'bin');
      await extractBinaries(archive, unpacked, request.platform);
      const localPlatform = process.platform === 'win32' ? 'windows' : process.platform;
      const localArch = process.arch === 'x64' ? 'amd64' : process.arch;
      // 外平台包不能在本机执行，其真实版本将在远程部署时检查。
      if (request.platform === localPlatform && request.arch === localArch) {
        for (const role of ['client', 'server'] as const) {
          const actual = (
            await this.checkBinary(path.join(unpacked, frpAdapter.binary(role, request.platform)))
          )
            .trim()
            .replace(/^v/, '');
          if (actual !== request.version.replace(/^v/, ''))
            throw new AppError(`实际版本 ${actual} 与所选版本不一致。`);
        }
      }
      await rm(target, { recursive: true, force: true });
      await rename(work, target);
      const item: InstalledVersion = {
        key,
        version: request.version.replace(/^v/, ''),
        platform: request.platform,
        arch: request.arch,
        directory: path.join(target, 'bin'),
        source: request.localPath ? '本地导入' : request.url!,
        installedAt: new Date().toISOString(),
        verified: !!request.digest,
        digest,
      };
      this.store.data.versions.push(item);
      await this.store.persist();
      return item;
    } finally {
      this.installing.delete(key);
      await rm(work, { recursive: true, force: true });
    }
  }
  async remove(key: string) {
    if (
      this.store.data.instances.some((i) => i.versionKey === key) ||
      this.store.data.servers.some((s) => s.deployment?.versionKey === key)
    )
      throw new AppError('此版本被客户端或服务器部署引用，请先更换版本或移除引用。');
    const item = this.store.version(key);
    if (
      path.resolve(item.directory) !==
      path.resolve(this.store.root, 'packages', versionKey(item), 'bin')
    )
      throw new AppError('版本目录与管理目录不一致，已阻止删除。');
    await rm(path.dirname(item.directory), { recursive: true, force: true });
    this.store.data.versions = this.store.data.versions.filter((v) => v.key !== key);
    await this.store.persist();
  }
}
