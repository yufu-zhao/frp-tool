import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import type { Store } from './store';
import { quote, type Remote } from './remote';
import { AppError, redact } from '../shared/errors';
import type {
  ManagedTlsStatus,
  ManagedResource,
  TlsProxyProgress,
  PortOwner,
} from '../shared/types';
import type { TlsProxyInput } from '../shared/contracts';

// 与 tools/tls-proxy/main.go 中的 version 常量保持一致；安装后通过 `-version` 校验。
export const TLS_PROXY_VERSION = '1.0.0';
export const TLS_PROXY_UNIT = 'intranet-frp-tls';

// 应用标记：写入文本资源，用于卸载时判断「是否本工具创建、是否被用户改动」。
const APP_MARKER = '# 由穿透工作台托管 TLS 实例管理；请勿修改';
const CONFIG_MARKER = 'intranet-frp-tls-proxy';
const STATE_MARKER = 'intranet-frp-tls-proxy';
const STATE_SCHEMA = 1;

type ServiceMode = 'systemd-user' | 'process';
type ProgressFn = (progress: TlsProxyProgress) => void;
type StepReporter = (status: TlsProxyProgress['status'], step: string, message: string) => void;

// 清单里的资源：在 ManagedResource 基础上附带内容摘要/标记，用于安全卸载。
interface ManifestResource extends ManagedResource {
  sha256?: string;
  marker?: string;
  mode?: string;
  runtime?: boolean; // 运行时产物（日志/pid），无需摘要比对即可清理
}

interface RemoteState {
  schema: number;
  managedBy: string;
  version: string;
  serverId: string;
  home: string;
  root: string;
  arch: string;
  upstreamPort: number;
  unitName: string;
  serviceMode: ServiceMode;
  binaryPath: string;
  configPath: string;
  statePath: string;
  unitFile: string;
  unitLink: string;
  logPath: string;
  pidPath: string;
  challengeDir: string;
  certFile: string;
  keyFile: string;
  setcap: boolean;
  resources: ManifestResource[];
  createdAt: number;
  lastChangedAt: number;
}

export interface TlsProxyUninstallResult {
  note: string;
  removed: number;
  kept: Array<{ path: string; reason: string }>;
  residueReport: string;
}

interface EnvSnapshot {
  ports: string;
  userUnits: string;
  cron: string;
  systemPaths: string[];
}

// 关键系统路径：仅做存在性对比，卸载前后必须一致，证明从未触碰 nginx/letsencrypt。
const KEY_SYSTEM_PATHS = [
  '/etc/nginx',
  '/usr/sbin/nginx',
  '/etc/letsencrypt',
  '/var/log/nginx',
  '/etc/systemd/system/nginx.service',
];

function layout(home: string) {
  const share = `${home}/.local/share/intranet-frp`;
  const root = `${share}/tls-proxy`;
  return {
    share,
    certs: `${share}/certs`,
    root,
    bin: `${root}/bin`,
    conf: `${root}/conf`,
    vhost: `${root}/vhost`,
    logs: `${root}/logs`,
    run: `${root}/run`,
    binaryPath: `${root}/bin/tls-proxy`,
    configPath: `${root}/conf/config.json`,
    statePath: `${root}/state.json`,
    unitFile: `${root}/conf/${TLS_PROXY_UNIT}.service`,
    logPath: `${root}/logs/tls-proxy.log`,
    pidPath: `${root}/run/tls-proxy.pid`,
    challengeDir: `${root}/vhost/challenge`,
  };
}
type Layout = ReturnType<typeof layout>;

const noProgress: ProgressFn = () => {};

export class TlsProxyManager {
  constructor(
    private store: Store,
    private remote: Remote,
    private changed: () => void = () => {},
  ) {}

  // ---------------------------------------------------------------------------
  // 公开方法
  // ---------------------------------------------------------------------------

  /** 只读探测：安装/运行状态、80/443 归属、unit、资源清单。 */
  async status(serverId: string): Promise<ManagedTlsStatus> {
    const status = await this.current(serverId);
    await this.persist(status);
    return status;
  }

  /** 上传二进制、写配置与 unit、setcap、注册独立 unit；服务保持停止，需显式 start。 */
  async install(
    input: TlsProxyInput,
    onProgress: ProgressFn = noProgress,
  ): Promise<ManagedTlsStatus> {
    const { serverId, taskId } = input;
    const p = this.reporter(taskId, onProgress);
    const info = await this.remote.connect(serverId);
    return this.remote.locked(serverId, async () => {
      let created = false;
      let unitLink = '';
      try {
        p('running', '检测环境', '校验系统、架构、用户 systemd 与权限');
        if (!info.supported)
          throw new AppError(
            `暂不支持此服务器系统：${info.distribution}，托管 TLS 实例仅支持 Linux。`,
          );
        if (info.arch !== 'amd64' && info.arch !== 'arm64')
          throw new AppError(`不支持的 CPU 架构 ${info.arch}，仅提供 amd64/arm64 二进制。`);
        const L = layout(info.home);

        if (await this.statePresent(serverId, L.statePath))
          throw new AppError('该服务器已安装托管 TLS 实例，请先卸载再重新安装。');

        // 绝不抢端口：80/443 已被其他进程或 nginx 持有时直接拒绝。
        p('running', '检查端口', '确认 80/443 空闲且未被 nginx/其他进程占用');
        const owners = await this.portOwners(serverId);
        const blocked = owners.filter((o) => o.state === 'other' || o.state === 'system-nginx');
        if (blocked.length)
          throw new AppError(
            `80/443 已被占用（${blocked
              .map((o) => `${o.port}: ${o.process ?? '其他进程'}`)
              .join('、')}），本工具绝不自动抢占端口，请释放后再安装，或改用 nginx 方案。`,
          );
        const nginxPresent = await this.nginxPresent(serverId);
        if (nginxPresent)
          p(
            'running',
            '环境提示',
            '检测到系统已有 nginx 二进制/包：安装后如需让位，请执行「让位」释放 80/443；本工具绝不修改 nginx',
          );

        // 读取本地二进制并先算好 SHA256。
        p('running', '准备程序', `读取 ${info.arch} 二进制并计算 SHA256`);
        let binary: Buffer;
        try {
          binary = await readFile(this.localBinary(info.arch));
        } catch {
          throw new AppError(
            '找不到本地 tls-proxy 二进制，请先运行 node scripts/build-tls-proxy.mjs 生成产物。',
          );
        }
        const digest = createHash('sha256').update(binary).digest('hex');

        const server = this.store.server(serverId);
        const upstreamPort = server.httpPort; // frps vhost HTTP 高端口（如 8080）
        if (upstreamPort === 80 || upstreamPort === 443)
          throw new AppError(
            '托管 TLS 实例本身要监听 80，FRP 的 HTTP 入口不能同为 80/443；请先把服务器配置改为高端口（如 8080）。',
          );
        const { certFile, keyFile } = this.resolveCertPaths(serverId, L.certs);
        const serviceMode: ServiceMode = info.userSystemd ? 'systemd-user' : 'process';

        created = true;
        p('running', '创建目录', '建立 bin/conf/vhost/logs/run 与 challenge 目录（700）');
        const dirs = [L.root, L.bin, L.conf, L.vhost, L.logs, L.run, L.challengeDir];
        await this.remote.exec(
          serverId,
          `mkdir -p -- ${dirs.map(quote).join(' ')} && chmod 700 -- ${dirs.map(quote).join(' ')}`,
        );

        const resources: ManifestResource[] = [];
        for (const d of dirs)
          resources.push({ kind: 'directory', path: d, marked: true, mode: '700' });

        // 二进制：base64 分块 + adminExec 写入，随后 SHA256 校验。
        p('running', '上传程序', 'base64 分块写入二进制');
        await this.adminWrite(serverId, L.binaryPath, binary, '755');
        const remoteDigest = (
          await this.remote.exec(serverId, `sha256sum -- ${quote(L.binaryPath)} | cut -d' ' -f1`)
        ).trim();
        if (remoteDigest !== digest)
          throw new AppError('上传的二进制 SHA256 校验失败，已中止安装。');
        resources.push({
          kind: 'file',
          path: L.binaryPath,
          marked: true,
          sha256: digest,
          mode: '755',
        });

        // 配置 JSON（带应用标记字段；Go 会忽略未知字段）。
        const config = {
          httpAddr: ':80',
          httpsAddr: ':443',
          certFile,
          keyFile,
          upstream: `http://127.0.0.1:${upstreamPort}`,
          challengeDir: L.challengeDir,
          logFile: L.logPath,
          managedBy: CONFIG_MARKER,
        };
        const configText = JSON.stringify(config, null, 2) + '\n';
        await this.writeUser(serverId, L.configPath, configText, '600');
        resources.push({
          kind: 'file',
          path: L.configPath,
          marked: true,
          sha256: this.sha256(configText),
          marker: CONFIG_MARKER,
          mode: '600',
        });

        // 独立 unit：优先 systemd --user；无 user systemd 回退后台进程。
        if (serviceMode === 'systemd-user') {
          p('running', '注册服务', `注册 systemd --user 单元 ${TLS_PROXY_UNIT}（不启用开机自启）`);
          const unitText = this.unitText(L);
          await this.writeUser(serverId, L.unitFile, unitText, '600');
          resources.push({
            kind: 'file',
            path: L.unitFile,
            marked: true,
            sha256: this.sha256(unitText),
            marker: APP_MARKER,
            mode: '600',
          });
          const linkOut = await this.remote.exec(
            serverId,
            `systemctl --user link ${quote(L.unitFile)} 2>&1`,
          );
          unitLink = /Created symlink\s+(\S+)/.exec(linkOut)?.[1] ?? '';
          if (!unitLink)
            throw new AppError(
              `无法定位 systemctl --user link 生成的符号链接：${linkOut.slice(0, 300)}`,
            );
          await this.remote.exec(serverId, 'systemctl --user daemon-reload');
          resources.push({ kind: 'unit', path: unitLink, marked: true });
        }

        // 绑定低端口能力：优先 setcap；非 root 且无 setcap 时明确报错。
        p('running', '绑定能力', '为二进制授予 cap_net_bind_service');
        let setcapApplied = false;
        const canSetcap = await this.remote
          .adminExec(serverId, 'command -v setcap >/dev/null 2>&1 && echo yes || echo no')
          .then((o) => o.trim() === 'yes')
          .catch(() => false);
        if (canSetcap) {
          try {
            await this.remote.adminExec(
              serverId,
              `setcap cap_net_bind_service=+ep ${quote(L.binaryPath)}`,
            );
            setcapApplied = true;
          } catch {
            setcapApplied = false;
          }
        }
        if (!info.root && !setcapApplied)
          throw new AppError(
            '当前为非 root 用户，且无法为二进制授予 cap_net_bind_service（setcap 不可用或文件系统不支持文件能力），无法绑定 80/443。请以 root 连接，或改用支持文件能力的挂载。',
          );
        if (setcapApplied) resources.push({ kind: 'capability', path: L.binaryPath, marked: true });

        // 校验上传的程序可运行且版本匹配。
        const reported = (
          await this.remote.exec(serverId, `${quote(L.binaryPath)} -version`)
        ).trim();
        if (reported !== TLS_PROXY_VERSION)
          throw new AppError(
            `服务端程序版本不匹配（期望 ${TLS_PROXY_VERSION}，实际 ${reported}）。`,
          );

        // 运行时产物与逻辑资源一并登记进清单（逆序卸载）。
        resources.push({ kind: 'file', path: L.logPath, marked: true, runtime: true });
        resources.push({ kind: 'file', path: L.pidPath, marked: true, runtime: true });
        resources.push({ kind: 'process', path: `pid:${L.pidPath}`, marked: true });
        resources.push({ kind: 'port', path: '80', marked: true });
        resources.push({ kind: 'port', path: '443', marked: true });

        const state: RemoteState = {
          schema: STATE_SCHEMA,
          managedBy: STATE_MARKER,
          version: TLS_PROXY_VERSION,
          serverId,
          home: info.home,
          root: L.root,
          arch: info.arch,
          upstreamPort,
          unitName: TLS_PROXY_UNIT,
          serviceMode,
          binaryPath: L.binaryPath,
          configPath: L.configPath,
          statePath: L.statePath,
          unitFile: L.unitFile,
          unitLink,
          logPath: L.logPath,
          pidPath: L.pidPath,
          challengeDir: L.challengeDir,
          certFile,
          keyFile,
          setcap: setcapApplied,
          resources,
          createdAt: Date.now(),
          lastChangedAt: Date.now(),
        };
        // state.json 本身不进清单，卸载时最后删除，保证失败可重试。
        await this.writeUser(serverId, L.statePath, JSON.stringify(state, null, 2) + '\n', '600');

        const status = await this.buildStatus(serverId, L, state);
        await this.persist(status);
        p(
          'succeeded',
          '完成',
          serviceMode === 'systemd-user'
            ? '托管 TLS 实例已安装（systemd --user）。服务保持停止，请点击启动；证书与配置已就位。'
            : '托管 TLS 实例已安装（后台进程模式，不注册开机自启）。服务保持停止，请点击启动。',
        );
        return status;
      } catch (error) {
        if (created) await this.rollback(serverId, layout(info.home), unitLink).catch(() => {});
        p('failed', '失败', this.errorText(error));
        throw error;
      }
    });
  }

  async start(
    input: TlsProxyInput,
    onProgress: ProgressFn = noProgress,
  ): Promise<ManagedTlsStatus> {
    const { serverId, taskId } = input;
    const p = this.reporter(taskId, onProgress);
    const info = await this.remote.connect(serverId);
    return this.remote.locked(serverId, async () => {
      try {
        const L = layout(info.home);
        const state = await this.requireState(serverId, L);
        p('running', '启动服务', '校验证书并启动 TLS 实例');
        await this.startService(serverId, state);
        const status = await this.buildStatus(serverId, L, state);
        await this.persist(status);
        p('succeeded', '完成', 'TLS 实例已启动，80/443 由托管实例持有。');
        return status;
      } catch (error) {
        p('failed', '失败', this.errorText(error));
        throw error;
      }
    });
  }

  async stop(input: TlsProxyInput, onProgress: ProgressFn = noProgress): Promise<ManagedTlsStatus> {
    const { serverId, taskId } = input;
    const p = this.reporter(taskId, onProgress);
    const info = await this.remote.connect(serverId);
    return this.remote.locked(serverId, async () => {
      try {
        const L = layout(info.home);
        const state = await this.requireState(serverId, L);
        p('running', '停止服务', '释放 80/443，证书与配置保留');
        await this.stopService(serverId, state);
        const status = await this.buildStatus(serverId, L, state);
        await this.persist(status);
        p('succeeded', '完成', 'TLS 实例已停止，80/443 已释放；证书与配置保留。');
        return status;
      } catch (error) {
        p('failed', '失败', this.errorText(error));
        throw error;
      }
    });
  }

  /** 让位：仅停止并释放 80/443，证书与配置保留，供用户日后安装 nginx。 */
  async yieldPorts(
    input: TlsProxyInput,
    onProgress: ProgressFn = noProgress,
  ): Promise<ManagedTlsStatus> {
    const { serverId, taskId } = input;
    const p = this.reporter(taskId, onProgress);
    const info = await this.remote.connect(serverId);
    return this.remote.locked(serverId, async () => {
      try {
        const L = layout(info.home);
        const state = await this.requireState(serverId, L);
        p('running', '让位', '停止实例并确认 80/443 释放');
        await this.stopService(serverId, state);
        const owners = await this.portOwners(serverId);
        const stillHeld = owners.filter((o) => o.state !== 'free');
        const status = await this.buildStatus(serverId, L, state);
        status.warning = [
          status.warning,
          stillHeld.length
            ? `让位后端口仍有归属：${stillHeld.map((o) => `${o.port}: ${o.state}`).join('、')}。本工具不会抢占，请人工核实。`
            : '80/443 已释放，可安全安装或启用 nginx 等软件；证书与配置保留，随时可重新启动托管实例。',
        ]
          .filter(Boolean)
          .join('\n');
        await this.persist(status);
        p('succeeded', '完成', status.warning ?? '已让位。');
        return status;
      } catch (error) {
        p('failed', '失败', this.errorText(error));
        throw error;
      }
    });
  }

  /** 清单驱动完全卸载：逆序清理、只删未改动的带标记资源、快照对比产出残留报告。 */
  async uninstall(
    input: TlsProxyInput,
    onProgress: ProgressFn = noProgress,
  ): Promise<TlsProxyUninstallResult> {
    const { serverId, taskId } = input;
    const p = this.reporter(taskId, onProgress);
    const info = await this.remote.connect(serverId);
    return this.remote.locked(serverId, async () => {
      try {
        const L = layout(info.home);
        p('running', '资源快照', '记录卸载前端口/unit/cron/系统路径快照');
        const before = await this.snapshot(serverId);
        const state = await this.readState(serverId, L.statePath, L.root);
        if (!state) {
          await this.persist(null);
          p('succeeded', '完成', '未发现托管实例清单，无需卸载。');
          return {
            note: '未发现托管实例清单（可能已卸载），无需操作。',
            removed: 0,
            kept: [],
            residueReport: this.residueReport(before, before, []),
          };
        }

        p('running', '停止服务', '停止实例并释放 80/443');
        await this.stopService(serverId, state).catch(() => {});

        // 用户 systemd 符号链接与运行时产物的显式清理。
        if (state.serviceMode === 'systemd-user' && state.unitLink) {
          await this.remote.exec(serverId, `rm -f -- ${quote(state.unitLink)}`).catch(() => {});
          await this.remote.exec(serverId, 'systemctl --user daemon-reload').catch(() => {});
        }
        await this.remote
          .exec(
            serverId,
            `rm -f -- ${quote(L.logPath)} ${quote(L.pidPath)}; find ${quote(L.challengeDir)} -maxdepth 1 -type f -delete 2>/dev/null || true`,
          )
          .catch(() => {});

        const kept: Array<{ path: string; reason: string }> = [];
        let removed = 0;
        p('running', '清单清理', '按资源清单逆序清理');
        for (const r of [...state.resources].reverse()) {
          switch (r.kind) {
            case 'directory':
              if (r.path === L.root) break; // state.json 仍在，最后单独处理
              if (await this.rmdir(serverId, r.path)) removed += 1;
              else kept.push({ path: r.path, reason: '目录非空（可能含用户文件），未删除' });
              break;
            case 'unit':
            case 'timer':
            case 'cron':
              await this.remote.exec(serverId, `rm -f -- ${quote(r.path)}`).catch(() => {});
              removed += 1;
              break;
            case 'file':
              if (r.runtime) {
                await this.remote.exec(serverId, `rm -f -- ${quote(r.path)}`).catch(() => {});
                removed += 1;
                break;
              }
              if (await this.safeDeleteFile(serverId, r)) removed += 1;
              else kept.push({ path: r.path, reason: '缺少应用标记或内容已被用户改动，未删除' });
              break;
            case 'process':
            case 'port':
            case 'capability':
            default:
              // 非文件资源：停止/删除文件后自然释放，由快照对比确认。
              break;
          }
        }
        // 删除清单本身（最后），再尝试移除根空目录；state.json 保留到此处以支持失败重试。
        await this.remote.exec(serverId, `rm -f -- ${quote(L.statePath)}`).catch(() => {});
        if (await this.rmdir(serverId, L.root)) removed += 1;
        else kept.push({ path: L.root, reason: '根目录非空（可能含用户文件），保留' });

        p('running', '资源快照', '复核卸载后残留');
        const after = await this.snapshot(serverId);
        await this.persist(null);
        const report = this.residueReport(before, after, kept);
        p('succeeded', '完成', '卸载完成，已生成残留报告。');
        return {
          note: `已按清单逆序清理 ${removed} 项资源；${kept.length ? `保留 ${kept.length} 项被改动/非空资源。` : '无保留资源。'}`,
          removed,
          kept,
          residueReport: report,
        };
      } catch (error) {
        p('failed', '失败', this.errorText(error));
        throw error;
      }
    });
  }

  // ---------------------------------------------------------------------------
  // 远程服务控制
  // ---------------------------------------------------------------------------

  private async startService(serverId: string, state: RemoteState): Promise<void> {
    // 证书/私钥必须存在且当前用户可读，否则明确报错，不「带病启动」。
    await this.remote.exec(
      serverId,
      `test -r ${quote(state.certFile)} && test -r ${quote(state.keyFile)} || { echo '证书或私钥文件不存在/当前用户不可读，请先部署证书'; exit 1; }`,
    );
    if (state.serviceMode === 'systemd-user') {
      await this.remote.exec(serverId, `systemctl --user start ${quote(state.unitName)}`);
      return;
    }
    if (await this.processRunning(serverId, state)) return;
    await this.remote.exec(
      serverId,
      `umask 077; nohup ${quote(state.binaryPath)} -config ${quote(state.configPath)} >/dev/null 2>> ${quote(state.logPath)} < /dev/null & echo $! > ${quote(state.pidPath)}; sleep 1`,
    );
    if (!(await this.processRunning(serverId, state)))
      throw new AppError('托管 TLS 进程启动失败，请查看服务端日志。');
  }

  private async stopService(serverId: string, state: RemoteState): Promise<void> {
    if (state.serviceMode === 'systemd-user') {
      await this.remote
        .exec(serverId, `systemctl --user stop ${quote(state.unitName)}`)
        .catch(() => {});
      return;
    }
    const check = `pid=$(cat ${quote(state.pidPath)} 2>/dev/null || true); case "$pid" in ''|*[!0-9]*) exit 1;; esac; test "$pid" -gt 1 || exit 1; kill -0 "$pid" 2>/dev/null || exit 1; test "$(readlink -f /proc/"$pid"/exe)" = "$(readlink -f ${quote(state.binaryPath)})" || exit 1; tr '\\0' '\\n' < /proc/"$pid"/cmdline | grep -Fx -- ${quote(state.configPath)} >/dev/null || exit 1;`;
    await this.remote
      .exec(
        serverId,
        `${check} kill "$pid"; n=0; while kill -0 "$pid" 2>/dev/null && test "$n" -lt 10; do sleep 1; n=$((n+1)); done; if kill -0 "$pid" 2>/dev/null; then echo '进程未退出'; exit 1; fi; rm -f -- ${quote(state.pidPath)}`,
      )
      .catch(() => {});
    await this.remote.exec(serverId, `rm -f -- ${quote(state.pidPath)}`).catch(() => {});
  }

  private async isRunning(serverId: string, state: RemoteState): Promise<boolean> {
    if (state.serviceMode === 'systemd-user') {
      const out = await this.remote
        .exec(serverId, `systemctl --user is-active ${quote(state.unitName)} 2>/dev/null || true`)
        .catch(() => '');
      return out.trim().split(/\r?\n/).pop()?.trim() === 'active';
    }
    return this.processRunning(serverId, state);
  }

  private async processRunning(serverId: string, state: RemoteState): Promise<boolean> {
    const check = `pid=$(cat ${quote(state.pidPath)} 2>/dev/null || true); case "$pid" in ''|*[!0-9]*) exit 1;; esac; test "$pid" -gt 1 || exit 1; kill -0 "$pid" 2>/dev/null || exit 1; test "$(readlink -f /proc/"$pid"/exe)" = "$(readlink -f ${quote(state.binaryPath)})" || exit 1; tr '\\0' '\\n' < /proc/"$pid"/cmdline | grep -Fx -- ${quote(state.configPath)} >/dev/null || exit 1; echo running`;
    return this.remote
      .exec(serverId, check)
      .then((o) => o.includes('running'))
      .catch(() => false);
  }

  // ---------------------------------------------------------------------------
  // 探测、快照、报告
  // ---------------------------------------------------------------------------

  private async portOwners(serverId: string): Promise<PortOwner[]> {
    const out = await this.remote
      .exec(
        serverId,
        'if command -v ss >/dev/null 2>&1; then ss -ltnp 2>/dev/null; elif command -v netstat >/dev/null 2>&1; then netstat -ltnp 2>/dev/null; fi',
      )
      .catch(() => '');
    const lines = out.split(/\r?\n/);
    const result: PortOwner[] = [];
    for (const port of [80, 443]) {
      const line = lines.find(
        (l) => /LISTEN|tcp/i.test(l) && new RegExp(`:${port}(?:\\s|$)`).test(l),
      );
      if (!line) {
        result.push({ port, state: 'free' });
        continue;
      }
      let proc = /users:\(\("([^"]+)"/.exec(line)?.[1];
      if (!proc) proc = /\b(\d+)\/([\w.-]+)/.exec(line)?.[2];
      const state: PortOwner['state'] = !proc
        ? 'other'
        : /tls-proxy/i.test(proc)
          ? 'managed-tls'
          : /nginx/i.test(proc)
            ? 'system-nginx'
            : 'other';
      result.push({ port, state, process: proc });
    }
    return result;
  }

  private async nginxPresent(serverId: string): Promise<boolean> {
    const out = await this.remote
      .exec(
        serverId,
        `command -v nginx >/dev/null 2>&1 && echo bin; for p in /usr/sbin/nginx /usr/bin/nginx /etc/nginx/nginx.conf; do test -e "$p" && echo path; done; if command -v dpkg >/dev/null 2>&1 && dpkg -s nginx >/dev/null 2>&1; then echo pkg; elif command -v rpm >/dev/null 2>&1 && rpm -q nginx >/dev/null 2>&1; then echo pkg; fi; true`,
      )
      .catch(() => '');
    return /\b(bin|path|pkg)\b/.test(out);
  }

  private async snapshot(serverId: string): Promise<EnvSnapshot> {
    const ports = await this.remote
      .exec(
        serverId,
        `if command -v ss >/dev/null 2>&1; then ss -ltnp 2>/dev/null | grep -E ':80[[:space:]]|:443[[:space:]]' || true; elif command -v netstat >/dev/null 2>&1; then netstat -ltnp 2>/dev/null | grep -E ':80[[:space:]]|:443[[:space:]]' || true; fi`,
      )
      .catch(() => '');
    const userUnits = await this.remote
      .exec(
        serverId,
        `systemctl --user list-units --all --no-legend --no-pager 2>/dev/null | grep -F ${quote(TLS_PROXY_UNIT)} || true`,
      )
      .catch(() => '');
    const cron = await this.remote
      .exec(serverId, `crontab -l 2>/dev/null | grep -F ${quote(TLS_PROXY_UNIT)} || true`)
      .catch(() => '');
    const pathCheck =
      KEY_SYSTEM_PATHS.map((p) => `test -e ${quote(p)} && echo ${quote(p)}`).join('; ') + '; true';
    const sysOut = await this.remote.exec(serverId, pathCheck).catch(() => '');
    return {
      ports: ports.trim(),
      userUnits: userUnits.trim(),
      cron: cron.trim(),
      systemPaths: sysOut
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean)
        .sort(),
    };
  }

  private residueReport(
    before: EnvSnapshot,
    after: EnvSnapshot,
    kept: Array<{ path: string; reason: string }>,
  ): string {
    const lines: string[] = ['=== 托管 TLS 实例卸载残留报告 ==='];
    lines.push(
      after.ports
        ? `[警告] 卸载后 80/443 仍有监听：\n${after.ports}`
        : '[OK] 80/443 已释放（无监听）。',
    );
    lines.push(
      after.userUnits
        ? `[警告] 用户 systemd 仍列有本实例 unit：\n${after.userUnits}`
        : '[OK] 用户 systemd 无本实例 unit 残留。',
    );
    lines.push(
      after.cron
        ? `[警告] crontab 仍有本实例条目：\n${after.cron}`
        : '[OK] crontab 无本实例条目（本工具从不写 cron/timer）。',
    );
    const added = after.systemPaths.filter((p) => !before.systemPaths.includes(p));
    const gone = before.systemPaths.filter((p) => !after.systemPaths.includes(p));
    lines.push(
      added.length || gone.length
        ? `[警告] 关键系统路径发生变化：新增 [${added.join(', ')}] 消失 [${gone.join(', ')}]`
        : '[OK] 关键系统路径（/etc/nginx、/usr/sbin/nginx、/etc/letsencrypt、/var/log/nginx）前后一致，未被本工具创建或修改。',
    );
    if (kept.length) {
      lines.push(`保留（内容被用户改动或目录非空，未删除，共 ${kept.length} 项）：`);
      for (const k of kept) lines.push(`  - ${k.path}：${k.reason}`);
    } else {
      lines.push('[OK] 无保留资源。');
    }
    return lines.join('\n');
  }

  // ---------------------------------------------------------------------------
  // 清单读写与清理辅助
  // ---------------------------------------------------------------------------

  private async readState(
    serverId: string,
    statePath: string,
    root: string,
  ): Promise<RemoteState | null> {
    const text = await this.remote
      .exec(serverId, `cat -- ${quote(statePath)} 2>/dev/null || true`)
      .catch(() => '');
    if (!text.trim()) return null;
    try {
      const parsed = JSON.parse(text) as RemoteState;
      if (
        parsed?.schema === STATE_SCHEMA &&
        parsed?.managedBy === STATE_MARKER &&
        parsed?.root === root &&
        Array.isArray(parsed.resources)
      )
        return parsed;
      return null;
    } catch {
      return null;
    }
  }

  private async requireState(serverId: string, L: Layout): Promise<RemoteState> {
    const state = await this.readState(serverId, L.statePath, L.root);
    if (!state) throw new AppError('该服务器未安装托管 TLS 实例，请先安装。');
    return state;
  }

  private async statePresent(serverId: string, statePath: string): Promise<boolean> {
    const out = await this.remote
      .exec(serverId, `test -e ${quote(statePath)} && echo yes || echo no`)
      .catch(() => 'no');
    return out.trim() === 'yes';
  }

  private async safeDeleteFile(serverId: string, r: ManifestResource): Promise<boolean> {
    if (!r.marked) return false;
    const exists = await this.remote
      .exec(serverId, `test -e ${quote(r.path)} && echo yes || echo no`)
      .then((o) => o.trim() === 'yes')
      .catch(() => false);
    if (!exists) return true; // 已不存在（失败重试场景），视为已清理
    if (r.sha256) {
      const digest = await this.remote
        .exec(serverId, `sha256sum -- ${quote(r.path)} 2>/dev/null | cut -d' ' -f1`)
        .then((o) => o.trim())
        .catch(() => '');
      if (digest !== r.sha256) return false; // 内容已被用户改动，保留
    }
    if (r.marker) {
      const marker = r.marker;
      const ok = await this.remote
        .exec(
          serverId,
          `grep -qF -- ${quote(marker)} ${quote(r.path)} 2>/dev/null && echo yes || echo no`,
        )
        .then((o) => o.trim() === 'yes')
        .catch(() => false);
      if (!ok) return false; // 已无应用标记，保留
    }
    await this.remote.exec(serverId, `rm -f -- ${quote(r.path)}`).catch(() => {});
    return true;
  }

  private async rmdir(serverId: string, target: string): Promise<boolean> {
    const out = await this.remote
      .exec(
        serverId,
        `if test ! -e ${quote(target)}; then echo ok; elif rmdir -- ${quote(target)} 2>/dev/null; then echo ok; else echo keep; fi`,
      )
      .catch(() => 'keep');
    return out.trim() === 'ok';
  }

  private async rollback(serverId: string, L: Layout, unitLink: string): Promise<void> {
    if (unitLink) {
      await this.remote.exec(serverId, `rm -f -- ${quote(unitLink)}`).catch(() => {});
      await this.remote.exec(serverId, 'systemctl --user daemon-reload').catch(() => {});
    }
    await this.remote.adminExec(serverId, `rm -rf -- ${quote(L.root)}`).catch(() => {});
  }

  // ---------------------------------------------------------------------------
  // 远程写入辅助（全部使用 quote 防注入）
  // ---------------------------------------------------------------------------

  /** base64 分块 + adminExec 写入（用于二进制等较大文件）。分片按 4 字符对齐，独立 base64 -d 后追加。 */
  private async adminWrite(
    serverId: string,
    destination: string,
    data: Buffer | string,
    mode: string,
  ): Promise<void> {
    const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    const encoded = buffer.toString('base64');
    const chunkSize = 64 * 1024; // 4 的倍数，保证每片可独立解码
    await this.remote.adminExec(serverId, `rm -f -- ${quote(destination)}`);
    for (let i = 0; i < encoded.length; i += chunkSize) {
      const chunk = encoded.slice(i, i + chunkSize);
      await this.remote.adminExec(
        serverId,
        `printf %s ${quote(chunk)} | base64 -d >> ${quote(destination)}`,
      );
    }
    await this.remote.adminExec(serverId, `chmod ${quote(mode)} -- ${quote(destination)}`);
  }

  /** 小文本用 writeUserFile（用户属主、单块 base64）。 */
  private async writeUser(serverId: string, destination: string, content: string, mode: string) {
    await this.remote.writeUserFile(serverId, destination, content, mode);
  }

  // ---------------------------------------------------------------------------
  // 其它辅助
  // ---------------------------------------------------------------------------

  private localBinary(arch: string): string {
    if (arch !== 'amd64' && arch !== 'arm64') throw new AppError(`不支持的架构 ${arch}。`);
    // dist/main/index.js -> ../../assets/bin（与 index.ts 中 iconDirectory 一致）。
    return path.join(__dirname, '../../assets/bin', `tls-proxy-linux-${arch}`);
  }

  /** 证书路径：优先已部署服务端证书记录的绝对路径，否则用约定路径（不创建/不删除证书文件）。 */
  private resolveCertPaths(
    serverId: string,
    certsDir: string,
  ): { certFile: string; keyFile: string } {
    const records = this.store.data.serverCertificates.filter(
      (c) => c.serverId === serverId && c.certPath && c.keyPath,
    );
    const chosen = records.find((c) => c.deployState === 'deployed') ?? records[0];
    if (chosen && chosen.certPath.startsWith('/') && chosen.keyPath.startsWith('/'))
      return { certFile: chosen.certPath, keyFile: chosen.keyPath };
    return {
      certFile: `${certsDir}/default/fullchain.pem`,
      keyFile: `${certsDir}/default/privkey.pem`,
    };
  }

  private unitText(L: Layout): string {
    const esc = (value: string) => value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return `${APP_MARKER}
[Unit]
Description=Intranet FRP managed TLS proxy (80/443 terminator)

[Service]
Type=simple
WorkingDirectory="${esc(L.root)}"
ExecStart="${esc(L.binaryPath)}" -config "${esc(L.configPath)}"
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
`;
  }

  private async buildStatus(
    serverId: string,
    L: Layout,
    state: RemoteState | null,
  ): Promise<ManagedTlsStatus> {
    const owners = await this.portOwners(serverId);
    const warnings: string[] = [];
    if (await this.nginxPresent(serverId))
      warnings.push(
        '检测到系统已出现 nginx 二进制/包。建议执行「让位」释放 80/443 后再正常使用 nginx；本工具绝不修改或抢占 nginx。',
      );
    for (const o of owners)
      if (o.state === 'other' || o.state === 'system-nginx')
        warnings.push(
          `端口 ${o.port} 当前由 ${o.process ?? '其他进程'} 占用，托管实例无法绑定；本工具绝不自动抢端口，请确认归属或让该服务释放。`,
        );
    const running = state ? await this.isRunning(serverId, state) : false;
    return {
      installed: !!state,
      running,
      serverId,
      root: L.root,
      unitName: TLS_PROXY_UNIT,
      portsHeld: running ? [80, 443] : [],
      version: state?.version ?? '',
      resources: (state?.resources ?? []).map((r) => ({
        kind: r.kind,
        path: r.path,
        marked: r.marked,
      })),
      lastChangedAt: state?.lastChangedAt ?? 0,
      warning: warnings.length ? warnings.join('\n') : undefined,
    };
  }

  private async current(serverId: string): Promise<ManagedTlsStatus> {
    const info = await this.remote.connect(serverId);
    const L = layout(info.home);
    const state = await this.readState(serverId, L.statePath, L.root);
    return this.buildStatus(serverId, L, state);
  }

  private async persist(status: ManagedTlsStatus | null): Promise<void> {
    await this.store.saveManagedTls(status);
    this.changed();
  }

  private reporter(taskId: string, onProgress: ProgressFn): StepReporter {
    return (status, step, message) =>
      onProgress({ taskId, status, step, message, updatedAt: Date.now() });
  }

  private sha256(content: string): string {
    return createHash('sha256').update(content).digest('hex');
  }

  private errorText(error: unknown): string {
    return redact(
      error instanceof Error ? error.message : String(error),
      this.store.allSecrets(),
    ).slice(0, 1200);
  }
}
