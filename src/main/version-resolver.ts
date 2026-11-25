import type { Asset, DownloadProgress, InstallRequest, VersionResolution } from '../shared/types';
import {
  CHECKSUM_UNAVAILABLE,
  type EnsureVersionInput,
  type EnsureVersionResult,
  type ResolveVersionInput,
  type VersionArch,
  type VersionPlatform,
  type VersionPurpose,
} from '../shared/contracts';
import { AppError, friendlyError } from '../shared/errors';
import type { Store } from './store';
import type { Versions } from './versions';
import { chooseAsset, versionKey } from './versions';
import { progressEvent } from './downloader';

type ProgressFn = (progress: DownloadProgress) => void;
const SEMVER = /^\d+\.\d+\.\d+$/;

/**
 * 使用点版本解析：服务端安装与创建客户端共用同一套规则。
 * - 定版本：客户端跟随所选服务器已部署的 FRP 版本；服务端 / 未部署时取本地列表最新稳定版。
 * - 定架构：服务端用 SSH 探测到的 Linux 架构；客户端用本机架构。
 * - 只解析不联网、不下载；ensure() 才真正准备安装包，并全程上报进度。
 */
export class VersionResolver {
  constructor(
    private store: Store,
    private versions: Versions,
    private report: ProgressFn,
    private changed: () => void,
  ) {}

  private normalizeArch(raw?: string): VersionArch | undefined {
    const value = raw?.trim().toLowerCase();
    if (!value) return undefined;
    if (value === 'amd64' || value === 'x86_64' || value === 'x64') return 'amd64';
    if (value === 'arm64' || value === 'aarch64') return 'arm64';
    return undefined;
  }

  private localPlatform(): VersionPlatform {
    return process.platform === 'win32' ? 'windows' : (process.platform as VersionPlatform);
  }

  private platformOf(input: ResolveVersionInput): VersionPlatform {
    // frps 只部署在 Linux 服务器上（remote.deploy 里已有同样校验）。
    if (input.purpose === 'server') return 'linux';
    const raw = input.platform?.trim().toLowerCase();
    if (raw === 'darwin' || raw === 'linux' || raw === 'windows') return raw;
    if (raw === 'win32') return 'windows';
    return this.localPlatform();
  }

  private latestVersion(): string | undefined {
    return this.store.data.catalog?.releases
      .find((release) => SEMVER.test(release.version.replace(/^v/, '')))
      ?.version.replace(/^v/, '');
  }

  private findRelease(version: string) {
    return this.store.data.catalog?.releases.find(
      (release) => release.version.replace(/^v/, '') === version,
    );
  }

  private label(purpose: VersionPurpose, version: string, platform: string, arch: string): string {
    const role =
      purpose === 'server' ? '服务端安装包' : purpose === 'client' ? '客户端安装包' : '安装包';
    return `${role} FRP ${version} · ${platform}/${arch}`;
  }

  /** 只做决策，绝不联网、绝不下载，供界面实时显示「为什么是这个版本」。 */
  resolve(input: ResolveVersionInput): VersionResolution {
    const platform = this.platformOf(input);
    const rawArch = input.arch?.trim();
    const fallbackArch = input.purpose === 'client' ? this.normalizeArch(process.arch) : undefined;
    const arch = this.normalizeArch(rawArch) ?? fallbackArch;
    const archSupported = !!arch;
    const effectiveArch: VersionArch = arch ?? 'amd64';

    const server = input.serverId
      ? this.store.data.servers.find((item) => item.id === input.serverId)
      : undefined;
    const serverVersion = server?.deployment?.version?.replace(/^v/, '') || undefined;

    let version = input.version?.replace(/^v/, '') || '';
    let source: VersionResolution['source'] = 'explicit';
    if (!version) {
      if (input.purpose === 'client' && serverVersion) {
        version = serverVersion;
        source = 'server-deployment';
      } else {
        const latest = this.latestVersion();
        version = latest ?? '';
        source = latest ? 'latest-cached' : 'unavailable';
      }
    }

    const notes: string[] = [];
    switch (source) {
      case 'server-deployment':
        notes.push(
          `已跟随服务器「${server?.name ?? '所选服务器'}」的部署版本 FRP ${version}，架构按本机 ${platform}/${effectiveArch}。`,
        );
        break;
      case 'latest-cached':
        notes.push(
          input.purpose === 'client'
            ? `所选服务器尚未部署版本，暂用本地列表最新稳定版 FRP ${version}；服务端部署后建议改为一致。`
            : `使用本地版本列表中的最新稳定版 FRP ${version}，目标架构 ${platform}/${effectiveArch}。`,
        );
        break;
      case 'explicit':
        notes.push(`使用指定的 FRP ${version}（${platform}/${effectiveArch}）。`);
        break;
      case 'unavailable':
        notes.push('尚未获取官方版本列表，请先在版本库点击「获取版本列表」。');
        break;
    }
    if (input.purpose === 'client' && serverVersion && version && version !== serverVersion)
      notes.push(`注意：与服务器 FRP ${serverVersion} 版本不一致，可能影响连接兼容性。`);
    if (!archSupported)
      notes.push(
        input.purpose === 'server' && !rawArch
          ? '请先连接服务器以探测系统架构；点击「安装服务端」时会自动连接并重新探测。'
          : `检测到架构 ${rawArch || '未知'}，当前只支持 amd64 / arm64，请手动选择或使用离线导入。`,
      );

    const release = version ? this.findRelease(version) : undefined;
    let asset: Asset | undefined;
    if (release && archSupported) {
      try {
        asset = chooseAsset(release, platform, effectiveArch);
      } catch {
        // 该版本没有目标平台安装包；自动准备时会重新检查官方列表或提示离线导入。
      }
    }
    const key = version ? versionKey({ version, platform, arch: effectiveArch }) : '';
    const installed = !!key && this.store.data.versions.some((item) => item.key === key);
    if (version && !release && !installed && archSupported)
      notes.push('本地列表没有此版本，自动准备时会检查官方发布列表。');

    return {
      version,
      platform,
      arch: effectiveArch,
      key,
      installed,
      source,
      serverVersion,
      mismatch: !!serverVersion && !!version && version !== serverVersion,
      available: !!asset,
      archSupported,
      asset,
      note: notes.join(' '),
    };
  }

  /**
   * 确保目标版本在本机可用：命中已安装直接复用，否则自动下载 + 校验 + 解包。
   * 从调用的那一刻就发 starting 事件，界面不再有「点了没反应」的静默期。
   */
  async ensure(input: EnsureVersionInput): Promise<EnsureVersionResult> {
    const resolution = this.resolve(input);
    const { version, platform, arch, key } = resolution;
    if (!version)
      throw new AppError(resolution.note || '尚未获取官方版本列表。', 'VERSION_UNAVAILABLE');
    if (!resolution.archSupported)
      throw new AppError(
        `目标架构 ${input.arch || '未知'} 暂不支持，当前只支持 amd64 / arm64，请手动选择或使用离线导入。`,
        'ARCH_UNSUPPORTED',
      );

    const existing = this.store.data.versions.find((item) => item.key === key);
    // 已安装时不产生下载任务，避免任务中心出现无意义的「已完成」占位。
    if (existing) return { resolution, version: existing, prepared: false };

    const meta = {
      purpose: input.purpose,
      label: this.label(input.purpose, version, platform, arch),
      serverId: input.serverId,
    };
    const base = { taskId: input.taskId, key, version };
    const send = (
      status: DownloadProgress['status'],
      message: string,
      patch: Partial<DownloadProgress> = {},
    ) => this.report(progressEvent(base, { status, message, ...meta, ...patch }));

    send('starting', `正在准备 ${meta.label}。`);
    let enteredInstall = false;
    try {
      let asset = resolution.asset;
      if (!asset && input.refreshCatalog !== false) {
        send('starting', '本地列表缺少该版本安装包，正在检查官方发布列表。');
        const catalog = await this.versions.catalog(1, { force: true });
        const release = catalog.releases.find((item) => item.version.replace(/^v/, '') === version);
        if (release) {
          try {
            asset = chooseAsset(release, platform, arch);
          } catch {
            // 交给下面统一报错。
          }
        }
      }
      if (!asset)
        throw new AppError(
          `官方发布列表中找不到 FRP ${version} 的 ${platform}/${arch} 安装包，请在版本库确认版本，或使用「手动 / 离线导入」。`,
          'NO_ASSET',
        );

      const request: InstallRequest = {
        taskId: input.taskId,
        version,
        platform,
        arch,
        url: asset.url,
        digest: asset.digest,
      };
      const resolved = await this.versions.resolveReleaseDigest(request);
      // 官方 SHA256 取不到时交给渲染层确认，绝不再弹 Electron 原生框阻塞界面。
      if (!resolved.digest && !input.confirmed)
        throw new AppError(
          '未能取得 FRP 官方 SHA256 校验值，本次无法与官方摘要核对。请确认下载来源可信后继续。',
          CHECKSUM_UNAVAILABLE,
        );
      if (!resolved.digest) send('starting', '来源未经官方 SHA256 核对，已按你的确认继续。');

      enteredInstall = true;
      const installed = await this.versions.install(resolved, {
        taskId: input.taskId,
        onProgress: (progress) => this.report({ ...progress, ...meta }),
      });
      this.changed();
      return { resolution, version: installed, prepared: true };
    } catch (error) {
      // install() 内部已上报 failed；这里只补报「进入下载之前」的错误，
      // 否则任务中心会永远停在 starting。
      if (!enteredInstall) send('failed', friendlyError(error));
      throw error;
    }
  }
}
