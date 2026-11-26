import {
  app,
  BrowserWindow,
  ipcMain,
  dialog,
  safeStorage,
  session,
  Tray,
  Menu,
  nativeImage,
  clipboard,
  shell,
  globalShortcut,
} from 'electron';
import path from 'node:path';
import os from 'node:os';
import { readFile } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Store } from './store';
import { Versions, versionKey } from './versions';
import { progressEvent } from './downloader';
import { VersionResolver } from './version-resolver';
import { Processes, execute } from './processes';
import { Remote } from './remote';
import { parseDiscoveredFrpsConfig } from './service-discovery';
import {
  Certificates,
  normalizeDomains,
  type DnsChallengeRecord,
  type CertificateIssueProgressUpdate,
  type HttpChallengeRunner,
} from './certificates';
import { validateRules } from './frp';
import { ServerCertificates } from './server-certificates';
import { manageAdapterForAccount } from './dns-automation';
import { SiteInspector } from './site-inspector';
import { WebIncludeManager } from './web-include';
import { TlsProxyManager } from './tls-proxy';
import {
  ACTIONS,
  EVENTS,
  CHECKSUM_UNAVAILABLE,
  type IssueServerInput,
  type DnsTestInput,
  type DnsAccountTestInput,
} from '../shared/contracts';
import { notifyRenderer } from './lifecycle';
import { AppError, friendlyError, redact } from '../shared/errors';
import { deployFailureHint } from '../shared/deploy-hint';
import {
  serverSchema,
  instanceSchema,
  settingsSchema,
  installSchema,
  terminalFavoriteSchema,
  dnsAccountSchema,
  type Result,
  type CertificateIssueProgress,
  type TerminalEvent,
  type DownloadProgress,
  type TlsProxyProgress,
  type ServerDeployProgress,
  type ServerDeployProgressUpdate,
} from '../shared/types';

/** 已保存凭据只回传脱敏摘要，避免完整密钥出现在渲染层或 DOM。 */
function maskCredential(value: string): string {
  const clean = value.trim();
  if (!clean) return '';
  if (clean.length <= 8) return `${clean.slice(0, 1)}****${clean.slice(-1)}`;
  return `${clean.slice(0, 4)}****${clean.slice(-4)}`;
}
function savedSecretOf(store: Store, key: string): string {
  try {
    return store.secret(key);
  } catch {
    return '';
  }
}

const iconDirectory = path.join(__dirname, '../../assets/icons');
let window: BrowserWindow | undefined;
let tray: Tray | undefined;
let quitting = false;
let store: Store;
let processes: Processes;
let remote: Remote;
let serverCertificates: ServerCertificates;
let localCertificates: Certificates;
let siteInspector: SiteInspector;
let webInclude: WebIncludeManager;
let tlsProxy: TlsProxyManager;
const certificateIssueControllers = new Map<string, AbortController>();
const dnsChallengeWaiters = new Map<string, (continueIssue: boolean) => void>();
const changed = () => notifyRenderer(window, quitting);

function reportCertificateProgress(
  taskId: string,
  progress:
    CertificateIssueProgressUpdate | Pick<CertificateIssueProgress, 'status' | 'step' | 'message'>,
) {
  const state: CertificateIssueProgress = {
    taskId,
    ...progress,
    updatedAt: Date.now(),
  };
  if (window && !window.isDestroyed()) window.webContents.send(EVENTS.certificateProgress, state);
}

function reportDownloadProgress(progress: DownloadProgress) {
  if (window && !window.isDestroyed()) window.webContents.send(EVENTS.downloadProgress, progress);
}

function reportTlsProxyProgress(progress: TlsProxyProgress) {
  if (window && !window.isDestroyed()) window.webContents.send(EVENTS.tlsProxyProgress, progress);
}

function reportServerDeployProgress(taskId: string, update: ServerDeployProgressUpdate) {
  const progress: ServerDeployProgress = { taskId, ...update, updatedAt: Date.now() };
  if (window && !window.isDestroyed())
    window.webContents.send(EVENTS.serverDeployProgress, progress);
}

// HTTP-01 必须把每个域名的验证请求映射到唯一的表单实例及公网 80 入口。

// 测试使用独立 Electron 用户目录，避免与已安装应用争夺单实例锁。
if (process.env.INTRANET_TEST_DATA) app.setPath('userData', process.env.INTRANET_TEST_DATA);

// 应用只允许一个实例，避免多个进程同时管理相同配置和 FRP。
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => {
    window?.show();
    window?.focus();
  });
  void app
    .whenReady()
    .then(async () => {
      if (process.env.NODE_ENV === 'development')
        globalShortcut.register('CommandOrControl+Shift+I', () => {
          window?.webContents.openDevTools();
        });
      store = new Store(process.env.INTRANET_TEST_DATA || app.getPath('userData'), {
        available: () =>
          safeStorage.isEncryptionAvailable() &&
          (process.platform !== 'linux' ||
            safeStorage.getSelectedStorageBackend() !== 'basic_text'),
        encrypt: (value) => safeStorage.encryptString(value),
        decrypt: (value) => safeStorage.decryptString(value),
      });
      await store.load();
      const network = session.fromPartition('intranet-downloads');
      network.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
      const setProxy = async (url: string) => {
        if (url) {
          let parsed: URL;
          try {
            parsed = new URL(url);
          } catch {
            throw new AppError('代理地址无效。');
          }
          if (
            !['http:', 'https:', 'socks5:'].includes(parsed.protocol) ||
            parsed.username ||
            parsed.password
          )
            throw new AppError('代理仅支持无内嵌凭据的 HTTP、HTTPS、SOCKS5 地址。');
        }
        await network.setProxy(
          url ? { mode: 'fixed_servers', proxyRules: url } : { mode: 'direct' },
        );
        await network.closeAllConnections();
      };
      await setProxy(store.data.settings.proxyUrl);
      const versions = new Versions(
        store,
        (url, init) => network.fetch(url, init),
        (binary) => execute(binary, ['-v']),
      );
      // 使用点（安装服务端 / 创建客户端）的版本自动解析与自动准备包。
      const versionResolver = new VersionResolver(store, versions, reportDownloadProgress, changed);
      processes = new Processes(store, changed);
      remote = new Remote(
        store,
        async (server, fingerprint) => {
          const answer = await dialog.showMessageBox(window!, {
            type: 'question',
            title: '确认 SSH 服务器身份',
            message: `首次连接 ${server.name}（${server.host}:${server.sshPort}）`,
            detail: `SHA256 指纹（十六进制）：\n${fingerprint}\n\n请与服务器管理员提供的指纹核对。确认后才保存信任记录。`,
            buttons: ['取消连接', '信任并连接'],
            defaultId: 0,
            cancelId: 0,
          });
          return answer.response === 1;
        },
        changed,
      );
      siteInspector = new SiteInspector(store, remote);
      webInclude = new WebIncludeManager(store, remote);
      const serverHttpChallenge: HttpChallengeRunner = async (assignments, operation, signal) => {
        if (signal?.aborted) throw new AppError('用户已取消 HTTP-01 验证。', 'CANCELLED');
        const running = assignments.filter((item) => processes.running(item.instanceId));
        const result = await processes.withHttp01Challenge(assignments, operation);
        return result;
      };
      const promptDns = async (records: DnsChallengeRecord[]) => {
        const detail = records
          .map((record) => `${record.record}\nTXT 值：${record.value}`)
          .join('\n\n');
        const answer = await dialog.showMessageBox({
          type: 'info',
          title: '添加 DNS 验证记录',
          message: '请在域名 DNS 服务中添加下面的 TXT 记录。',
          detail,
          buttons: ['取消签发', '已添加，继续验证'],
          defaultId: 0,
          cancelId: 0,
        });
        return answer.response === 1;
      };
      localCertificates = new Certificates(store, changed, promptDns, serverHttpChallenge, (id) =>
        processes.running(id),
      );
      serverCertificates = new ServerCertificates(
        store,
        changed,
        localCertificates,
        serverHttpChallenge,
        webInclude,
        (serverId) => remote.detect(serverId),
      );
      tlsProxy = new TlsProxyManager(store, remote, changed);
      const idSchema = z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/);
      // 渲染层危险操作统一携带 { id, confirmed: true }；兼容早期只传 id 字符串的调用。
      const pickId = (input: unknown) =>
        idSchema.parse(
          typeof input === 'object' && input !== null && 'id' in input
            ? (input as { id: unknown }).id
            : input,
        );
      const alreadyConfirmed = (payload: unknown) =>
        (typeof payload === 'object' &&
          payload !== null &&
          (payload as { confirmed?: unknown }).confirmed === true) ||
        store.data.settings.confirmDangerous === false;
      // 页面已用 ConfirmDialog 确认时不再弹系统原生框，避免双重确认与视觉割裂。
      const yes = async (message: string, detail: string, payload?: unknown) => {
        if (alreadyConfirmed(payload)) return true;
        return (
          (
            await dialog.showMessageBox(window!, {
              type: 'warning',
              message,
              detail,
              buttons: ['取消', '确认'],
              defaultId: 0,
              cancelId: 0,
            })
          ).response === 1
        );
      };
      const tlsInput = z.object({
        taskId: idSchema,
        serverId: idSchema,
        confirmed: z.boolean().optional(),
      });
      const handlers: Record<string, (payload: any) => Promise<unknown> | unknown> = {
        state: () => store.snapshot(),
        runtime: async () => {
          const serviceRuntime = await remote.runtimeServices();
          return {
            clients: processes.allStatus(),
            ssh: remote.allStatus(),
            services: serviceRuntime.services,
            serviceErrors: serviceRuntime.serviceErrors,
          };
        },
        'server:save': async (payload) => {
          const server = serverSchema.parse(payload);
          if (store.data.servers.find((item) => item.id === server.id)?.accessMode === 'readonly')
            throw new AppError('只读服务器不可编辑 FRP 服务端管理配置。');
          if (server.configMode === 'raw' && !server.rawConfig.trim())
            throw new AppError('高级服务端配置不能为空，请重新导入或输入配置。');
          await store.saveServer(server);
          changed();
        },
        'server:uninstall': async (payload) => {
          const value = z
            .object({ id: idSchema, removeRemote: z.boolean().default(false) })
            .parse(payload);
          const id = value.id;
          const server = store.server(id);
          if (store.data.instances.some((i) => i.serverId === id))
            throw new AppError('此服务器仍被客户端实例引用，请先更换关联或删除实例。');
          if (server.deployment) {
            // 渲染层确认框已让用户选择「仅本机移除 / 同时卸载远端」；未带确认标记时兜底。
            if (!alreadyConfirmed(payload)) {
              const answer = await dialog.showMessageBox(window!, {
                type: 'warning',
                title: '卸载服务器配置',
                message: `卸载「${server.name}」？`,
                detail: value.removeRemote
                  ? '将自动连接 SSH，停止并卸载远端服务及记录的程序、配置、日志和 PID 文件；历史备份保留。'
                  : '只移除本机配置并解除管理；远端 FRP 服务和文件继续保留。',
                buttons: ['取消', '仅从本机移除', '同时卸载远端服务'],
                defaultId: 2,
                cancelId: 0,
              });
              if (answer.response === 0) return;
              value.removeRemote = answer.response === 2;
            }
          } else if (
            !(await yes('卸载服务器配置？', `${server.name}\n只移除本机配置。`, payload))
          ) {
            return;
          }
          if (value.removeRemote && server.deployment) {
            if (!remote.connected(id)) await remote.connect(id);
            await remote.uninstall(id);
          } else if (server.deployment) {
            await remote.detach(id);
          }
          remote.disconnect(id);
          store.dropSecrets(`server:${id}:`);
          store.data.servers = store.data.servers.filter((s) => s.id !== id);
          await store.persist();
          changed();
        },
        'server:connect': (p) => remote.connect(pickId(p)),
        'server:disconnect': (p) => remote.disconnect(pickId(p)),
        'terminal:open': async (p) => {
          const value = z
            .object({
              serverId: idSchema,
              terminalId: z.string().uuid(),
              cols: z.number().int().min(20).max(400),
              rows: z.number().int().min(5).max(200),
            })
            .parse(p);
          if (!remote.connected(value.serverId)) await remote.connect(value.serverId);
          return remote.openTerminal(
            value.serverId,
            value.terminalId,
            value.cols,
            value.rows,
            (event: TerminalEvent) => {
              if (window && !window.isDestroyed()) window.webContents.send('terminal:event', event);
            },
          );
        },
        'terminal:history': async (p) => {
          const id = pickId(p);
          if (!remote.connected(id))
            throw new AppError('请先连接服务器 SSH 后再读取 shell history。');
          return remote.shellHistory(id);
        },
        'terminal-favorite:save': async (p) => {
          const favorite = terminalFavoriteSchema.parse(p);
          favorite.updatedAt = Date.now();
          await store.saveTerminalFavorite(favorite);
          changed();
          return favorite;
        },
        'terminal-favorite:delete': async (p) => {
          const id = z.string().min(1).max(100).parse(p);
          await store.deleteTerminalFavorite(id);
          changed();
        },
        'terminal-favorite:reorder': async (p) => {
          const ids = z.array(z.string().min(1).max(100)).max(1000).parse(p);
          await store.reorderTerminalFavorites(ids);
          changed();
        },
        'server:detect': (p) => remote.detect(pickId(p)),
        [ACTIONS.webIncludeInspect]: (p) => webInclude.inspect(pickId(p)),
        [ACTIONS.webIncludeApply]: (p) => {
          const { serverId, flavor } = z
            .object({
              serverId: idSchema,
              flavor: z.enum(['nginx', 'apache']),
            })
            .parse(p);
          return webInclude.apply(serverId, flavor);
        },
        [ACTIONS.webIncludeRemove]: (p) => webInclude.remove(pickId(p)),
        [ACTIONS.siteConfigSave]: (p) => {
          const { serverId, ruleId, content, flavor } = z
            .object({
              serverId: idSchema,
              ruleId: idSchema,
              content: z.string().max(1048576),
              flavor: z.enum(['nginx', 'apache']),
            })
            .parse(p);
          return webInclude.saveSiteConfig(serverId, ruleId, content, flavor);
        },
        [ACTIONS.siteConfigRead]: (p) => {
          const { serverId, ruleId } = z.object({ serverId: idSchema, ruleId: idSchema }).parse(p);
          return webInclude.readSiteConfig(serverId, ruleId);
        },
        'server:status': (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器不提供 FRP 服务端状态管理。');
          return remote.status(id);
        },
        'server:install-precheck': async (p) => {
          const { id, taskId } = z
            .object({ id: idSchema, taskId: z.string().max(80).optional() })
            .parse(p);
          if (!remote.connected(id)) throw new AppError('请先连接服务器 SSH 后再预检安装条件。');
          const report = taskId
            ? (update: Omit<ServerDeployProgressUpdate, 'serverId'>) =>
                reportServerDeployProgress(taskId, { serverId: id, ...update })
            : undefined;
          try {
            return await remote.installPrecheck(id, report);
          } catch (error) {
            const message = (error as Error).message;
            report?.({
              status: 'failed',
              step: '预检失败',
              message,
              percent: null,
              error: message,
              hint: '请检查 SSH 连接与服务器权限后重试；预检只读，不会修改服务器。',
            });
            throw error;
          }
        },
        'server:remove-existing': async (p) => {
          const value = z
            .object({
              id: idSchema,
              service: z.object({
                service: z.string().min(1).max(255),
                manager: z.enum(['systemd', 'openrc', 'sysv', 'process']),
                state: z.string().max(80),
                binary: z.string().max(4096),
                config: z.string().max(4096),
              }),
              confirmed: z.boolean().optional(),
            })
            .parse(p);
          if (store.server(value.id).accessMode === 'readonly')
            throw new AppError('只读连接不可移除服务器上的服务。');
          if (
            !(await yes(
              '移除已有 FRP 服务并安装新服务？',
              `将停止 ${value.service.service}、关闭开机启动、备份其程序与配置（.bak），再删除服务单元。已有配置不会直接删除，可按需回滚。`,
              p,
            ))
          )
            return { cancelled: true };
          return remote.removeExistingFrps(value.id, value.service);
        },
        'server:deploy': async (p) => {
          const { id, key, taskId, overwrite } = z
            .object({
              id: idSchema,
              key: z.string(),
              taskId: z.string().max(80).optional(),
              overwrite: z.boolean().optional(),
            })
            .parse(p);
          const tid = taskId ?? randomUUID();
          const report = (update: Omit<ServerDeployProgressUpdate, 'serverId'>) =>
            reportServerDeployProgress(tid, { serverId: id, ...update });
          if (store.server(id).accessMode === 'readonly') {
            const error = '此服务器为只读连接，不能部署或管理 FRP 服务端。';
            report({
              status: 'failed',
              step: '检查服务器',
              message: error,
              percent: null,
              error,
              hint: '此只读连接不能安装服务端。请在服务器配置中改为可管理模式后再安装。',
            });
            throw new AppError(error);
          }
          if (
            !(await yes(
              '安装 FRP 服务端？',
              '将上传所选 Linux 安装包，写入配置、安装服务并立即启动；不会修改防火墙或云安全组。',
              p,
            ))
          ) {
            report({
              status: 'cancelled',
              step: '已取消',
              message: '已取消安装服务端',
              percent: null,
            });
            return;
          }
          report({
            status: 'starting',
            step: '准备安装',
            message: '已接受安装任务，正在准备',
            percent: 0,
          });
          try {
            const result = await remote.deploy(
              id,
              key,
              (update) => reportServerDeployProgress(tid, update),
              overwrite === true,
            );
            report({
              status: 'succeeded',
              step: '安装完成',
              message: result.note || 'FRP 服务端已安装并启动',
              percent: 100,
            });
            return result;
          } catch (error) {
            const message = (error as Error).message;
            report({
              status: 'failed',
              step: '安装失败',
              message,
              percent: null,
              error: message,
              hint: deployFailureHint(message),
            });
            throw error;
          }
        },
        'server:search-services': async (p) => {
          const value = z
            .object({ id: idSchema, keyword: z.string().max(100).default('') })
            .parse(p);
          if (!remote.connected(value.id)) throw new AppError('请先连接服务器 SSH 后再检索服务。');
          return remote.searchFrpsServices(value.id, value.keyword);
        },
        'server:import-service': async (p) => {
          const value = z
            .object({
              id: idSchema,
              service: z.string().min(1).max(255),
              manager: z.enum(['systemd', 'openrc', 'sysv', 'process']),
              state: z.string().max(80),
              binary: z.string().min(1).max(4096),
              config: z.string().min(1).max(4096),
            })
            .parse(p);
          const server = store.server(value.id);
          if (server.accessMode === 'readonly') throw new AppError('此只读服务器已完成服务检索。');
          if (server.deployment) throw new AppError('此服务器已有本机管理的部署，不能导入为只读。');
          if (!remote.connected(value.id)) throw new AppError('请先连接服务器 SSH 后再读取配置。');
          // 只按服务名与管理器定位最新候选：运行状态、程序/配置路径会随服务重启或升级变化，
          // 用它做全字段相等匹配会让只读保存频繁误报「服务信息已变化」。
          const matches = await remote.searchFrpsServices(value.id, value.service);
          const candidate =
            matches.find(
              (item) => item.service === value.service && item.manager === value.manager,
            ) ??
            matches.find((item) => item.service === value.service) ??
            matches.find((item) => item.config === value.config);
          if (!candidate) throw new AppError('服务信息已变化或不再匹配 FRP，请重新检索。');
          let rawConfig: string;
          try {
            rawConfig = await remote.readRemoteText(value.id, candidate.config);
          } catch (error) {
            const detail = (error as Error).message;
            throw new AppError(
              `无法读取服务端 frps 配置 ${candidate.config}：${detail}。请确认 SSH 账号有读取权限，或改选「移除并重新安装」。`,
            );
          }
          let connection;
          try {
            connection = parseDiscoveredFrpsConfig(rawConfig, candidate.config);
          } catch (error) {
            throw new AppError(
              `服务端配置 ${candidate.config} 未包含可识别的 FRP 连接参数：${(error as Error).message}。可改选「移除并重新安装」。`,
            );
          }
          const securelyStored = await store.saveDiscoveredServerConfig(value.id, connection, {
            name: candidate.service,
            manager: candidate.manager,
            binary: candidate.binary,
            config: candidate.config,
          });
          changed();
          const filled = `连接端口 ${connection.frpPort} / ${connection.httpPort} / ${connection.httpsPort}，令牌已写入安全存储`;
          return {
            note: securelyStored
              ? `已从服务端 ${candidate.config} 读取 ${connection.format.toUpperCase()} 配置并回填到本地服务器：${filled}；已保存为只读连接。`
              : `已从服务端 ${candidate.config} 读取 ${connection.format.toUpperCase()} 配置并回填到本地服务器：${filled}（当前系统安全存储不可用，令牌仅在本次运行期间有效）。`,
          };
        },
        'server:control': (p) => {
          const value = z
            .object({
              id: idSchema,
              action: z.enum(['start', 'stop', 'restart', 'enable', 'disable']),
            })
            .parse(p);
          if (store.server(value.id).accessMode === 'readonly')
            throw new AppError('只读服务器不可控制 FRP 服务端。');
          return remote.control(value.id, value.action);
        },
        'server:logs': (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器不开放服务端日志管理。');
          return remote.logs(id);
        },
        'server:logs:clear': async (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器不开放服务端日志管理。');
          if (
            await yes(
              '清理服务端日志？',
              '只清空此部署的日志文件，不停止服务；systemd journal 日志无法按单个服务安全清理。',
              p,
            )
          )
            return remote.clearLogs(id);
        },
        'server:backups': (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器不开放备份管理。');
          return remote.backups(id);
        },
        'server:restore': async (p) => {
          const value = z.object({ id: idSchema, path: z.string() }).parse(p);
          if (store.server(value.id).accessMode === 'readonly')
            throw new AppError('只读服务器不开放备份恢复。');
          if (
            await yes(
              '恢复部署备份？',
              '服务必须先停止。恢复前备份当前文件，校验通过后恢复，不自动启动。',
              p,
            )
          )
            return remote.restore(value.id, value.path);
        },
        'server:read-config': (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器配置已导入，不能作为服务端管理配置编辑。');
          return remote.readConfig(id);
        },
        'server:autostart': (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器不提供开机启动状态。');
          return remote.autostart(id);
        },
        'server:apply': async (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器不可修改 FRP 服务端配置。');
          if (!(await yes('应用服务端配置？', '将校验新配置、备份旧配置、替换文件并重启服务。', p)))
            return;
          return remote.apply(id);
        },
        'server:version': async (p) => {
          const value = z.object({ id: idSchema, key: z.string() }).parse(p);
          if (store.server(value.id).accessMode === 'readonly')
            throw new AppError('只读服务器不可替换服务端版本。');
          if (
            !(await yes(
              '替换服务端版本？',
              '服务必须先停止。替换前备份程序及配置，不自动转换配置或启动服务。',
              p,
            ))
          )
            return;
          return remote.changeVersion(value.id, value.key);
        },
        'instance:save': async (p) => {
          const item = instanceSchema.parse(p);
          if (item.mode === 'raw' && !item.rawConfig.trim())
            throw new AppError('高级客户端配置不能为空。');
          // 运行中保存配置：先记住状态，落盘后由渲染层统一重启，避免边写边跑读到半份配置。
          const restartAfterSave = processes.running(item.id);
          if (item.mode === 'form') {
            for (const rule of item.proxies)
              if (rule.type === 'http' || rule.type === 'https')
                rule.domains = normalizeDomains(rule.domains.filter(Boolean));
            const server = store.server(item.serverId);
            if (server.httpsPort === 443) {
              const localCerts = store.data.serverCertificates.filter(
                (certificate) =>
                  certificate.serverId === server.id &&
                  certificate.location === 'local' &&
                  certificate.tlsPlan !== 'server',
              );
              for (const rule of item.proxies) {
                if (rule.type !== 'https' || rule.certificateId || rule.certPath) continue;
                const matched =
                  localCerts.find((certificate) =>
                    certificate.domains.some((domain) => rule.domains.includes(domain)),
                  ) ?? localCerts[0];
                if (!matched)
                  throw new AppError(
                    `服务器「${server.name}」的 HTTPS 入口是 443，请先为域名签发本机证书，再创建 HTTPS 规则。`,
                  );
                rule.tlsMode = 'terminate';
                rule.certificateId = matched.localCertificateId ?? matched.id;
              }
            }
            validateRules(item.proxies);
          }
          await store.saveInstance(item);
          changed();
          if (restartAfterSave) {
            await processes.stop(item.id);
            await processes.start(item.id);
          }
          return { restarted: restartAfterSave };
        },
        'instance:delete': async (p) => {
          const id = pickId(p);
          store.instance(id);
          if (!(await yes('删除客户端实例？', '此实例的本机穿透将停止，配置将删除。', p))) return;
          await processes.stop(id);
          store.dropSecrets(`instance:${id}:`);
          store.data.instances = store.data.instances.filter((i) => i.id !== id);
          await store.persist();
          changed();
        },
        'instance:start': async (p) => {
          const id = pickId(p);
          await processes.start(id);
        },
        'instance:stop': (p) => processes.stop(pickId(p)),
        'instance:restart': async (p) => {
          const id = pickId(p);
          await processes.stop(id);
          await processes.start(id);
        },
        'instance:logs': (p) => processes.log(pickId(p)),
        'instance:logs:clear': async (p) => {
          const id = pickId(p);
          if (
            await yes(
              '清理客户端日志？',
              '只清除此实例在应用中保留的日志，不停止客户端；运行时产生的新日志会继续记录。',
              p,
            )
          )
            return processes.clearLogs(id);
        },
        'certificate:cancel': (p) => {
          const id = pickId(p);
          const controller = certificateIssueControllers.get(id);
          if (!controller) throw new AppError('签发任务已结束或不存在。');
          reportCertificateProgress(id, {
            status: 'cancelling',
            step: '正在取消',
            message: '正在中止当前 CA 请求并清理临时验证通道；正在进行的系统调用可能需要短暂返回。',
          });
          controller.abort();
          dnsChallengeWaiters.get(id)?.(false);
          return '正在取消签发并清理临时资源。';
        },
        'certificate:challenge-response': (p) => {
          const value = z.object({ id: idSchema, continueIssue: z.boolean() }).parse(p);
          const answer = dnsChallengeWaiters.get(value.id);
          if (!answer) throw new AppError('当前没有等待确认的 DNS 验证。');
          answer(value.continueIssue);
          return value.continueIssue ? '已确认 DNS 记录，继续验证。' : '已取消签发。';
        },
        'instance:preview': (p) => processes.preview(instanceSchema.parse(p)),
        [ACTIONS.versionCatalog]: (p) => {
          const value =
            typeof p === 'number'
              ? { page: p, force: false }
              : z
                  .object({
                    page: z.number().int().min(1).max(1000).default(1),
                    force: z.boolean().default(false),
                  })
                  .parse(p ?? {});
          return versions.catalog(value.page, { force: value.force });
        },
        // 只解析版本与架构，不联网、不下载；界面据此实时显示「为什么是这个版本」。
        [ACTIONS.versionResolve]: (p) =>
          versionResolver.resolve(
            z
              .object({
                purpose: z.enum(['server', 'client']),
                serverId: z.string().max(100).optional(),
                version: z.string().max(50).optional(),
                platform: z.string().max(30).optional(),
                arch: z.string().max(30).optional(),
              })
              .parse(p ?? {}),
          ),
        // 命中已安装直接复用；否则自动下载 + 校验 + 解包，全程通过 download:progress 上报。
        [ACTIONS.versionEnsure]: async (p) => {
          const value = z
            .object({
              taskId: z.string().min(1).max(100),
              purpose: z.enum(['server', 'client']),
              serverId: z.string().max(100).optional(),
              version: z.string().max(50).optional(),
              platform: z.string().max(30).optional(),
              arch: z.string().max(30).optional(),
              refreshCatalog: z.boolean().optional(),
              confirmed: z.boolean().optional(),
            })
            .parse(p);
          const result = await versionResolver.ensure(value);
          changed();
          return result;
        },
        [ACTIONS.versionInstall]: async (p) => {
          const raw = (p && typeof p === 'object' ? p : {}) as Record<string, unknown>;
          const parsed = installSchema.parse(p);
          const taskId =
            parsed.taskId ??
            (typeof raw.taskId === 'string' ? raw.taskId : randomBytes(12).toString('hex'));
          const version = parsed.version.replace(/^v/, '');
          const key = versionKey(parsed);
          const purpose: 'server' | 'client' | 'manual' =
            raw.purpose === 'server' || raw.purpose === 'client' ? raw.purpose : 'manual';
          const meta = {
            purpose,
            label: `${parsed.localPath ? '导入' : '下载'} FRP ${version} · ${parsed.platform}/${parsed.arch}`,
          };
          const send = (
            status: DownloadProgress['status'],
            message: string,
            patch: Partial<DownloadProgress> = {},
          ) =>
            reportDownloadProgress(
              progressEvent({ taskId, key, version }, { status, message, ...meta, ...patch }),
            );
          // 点击即刻上报，消除 resolveReleaseDigest 造成的静默期。
          send('starting', '正在准备安装包。');
          try {
            const request = await versions.resolveReleaseDigest(parsed);
            // 不再弹 Electron 原生框：抛特定 code 交给渲染层确认后带 confirmed 重试。
            if (!request.digest && raw.confirmed !== true)
              throw new AppError(
                '未能取得 FRP 官方 SHA256 校验值，本次无法与官方摘要核对。请确认下载或导入来源可信后继续。',
                CHECKSUM_UNAVAILABLE,
              );
            const installed = await versions.install(request, {
              taskId,
              onProgress: (progress) => reportDownloadProgress({ ...progress, ...meta }),
            });
            changed();
            return installed;
          } catch (error) {
            // install() 内部已上报 failed；这里只补报进入下载之前的失败。
            if (error instanceof AppError && error.code === CHECKSUM_UNAVAILABLE)
              send('failed', friendlyError(error));
            throw error;
          }
        },
        'version:verify': async (p) => {
          const installed = await versions.verifyInstalledRelease(pickId(p));
          changed();
          return installed;
        },
        'version:delete': async (p) => {
          const key = pickId(p);
          if (await yes('删除本机安装包？', '被实例或部署引用的版本不能删除。', p))
            await versions.remove(key);
          changed();
        },
        [ACTIONS.settingsSave]: async (p) => {
          const raw = z
            .object({
              proxyUrl: z.string().max(2048).optional(),
              dnsProvider: z.enum(['dnspod', 'aliyun', 'cloudflare']).optional(),
              deployDefault: z.enum(['manual', 'auto']).optional(),
              catalogCacheHours: z.number().int().min(1).max(720).optional(),
              downloadRetries: z.number().int().min(0).max(10).optional(),
              managedTlsEnabled: z.boolean().optional(),
              confirmDangerous: z.boolean().optional(),
              theme: z.enum(['light', 'dark', 'system']).optional(),
              dnsCredentials: z.record(z.string().max(4096)).optional(),
              acmeEmail: z.string().max(254).optional(),
              eabKid: z.string().max(4096).optional(),
              eabHmac: z.string().max(4096).optional(),
            })
            .parse(p ?? {});
          // EAB 密钥只放系统安全存储；空字符串表示沿用已保存值。
          if (raw.eabKid) store.putSecret('acme:litessl:eabKid', raw.eabKid);
          if (raw.eabHmac) store.putSecret('acme:litessl:eabHmac', raw.eabHmac);
          // 显式重新填写 EAB 时强制换 ACME 账户：CA 侧旧账户未绑定新 EAB 会报
          // "The client lacks sufficient authorization"。留空沿用不触发。
          if (raw.eabKid || raw.eabHmac) store.dropSecrets('acme:litessl:accountKey');
          const savedSecret = (key: string) => {
            try {
              return store.secret(key);
            } catch {
              return '';
            }
          };
          const eabConfigured = Boolean(
            (raw.eabKid || savedSecret('acme:litessl:eabKid')) &&
            (raw.eabHmac || savedSecret('acme:litessl:eabHmac')),
          );
          const settings = settingsSchema.parse({
            ...store.data.settings,
            ...raw,
            litesslEabConfigured: eabConfigured,
          });
          // 凭据只放系统安全存储，绝不落到 state.json 明文。
          if (raw.dnsCredentials) {
            for (const [name, value] of Object.entries(raw.dnsCredentials))
              store.putSecret(`dns:${settings.dnsProvider}:${name}`, value);
          }
          await setProxy(settings.proxyUrl);
          versions.resetNetworkState();
          store.data.settings = settings;
          await store.persist();
          changed();
        },
        [ACTIONS.dnsAccountSave]: async (p) => {
          const raw = z
            .object({
              id: z
                .string()
                .regex(/^[a-zA-Z0-9_-]{1,80}$/)
                .optional(),
              name: z.string().min(1).max(100),
              provider: dnsAccountSchema.shape.provider,
              secretId: z.string().max(512).optional(),
              secretKey: z.string().max(512).optional(),
              token: z.string().max(4096).optional(),
              endpoint: z.string().max(512).optional(),
            })
            .parse(p ?? {});
          const existing = raw.id
            ? store.data.dnsAccounts.find((account) => account.id === raw.id)
            : undefined;
          const id = raw.id ?? randomUUID();
          const account = dnsAccountSchema.parse({
            id,
            name: raw.name.trim(),
            provider: raw.provider,
            createdAt: existing?.createdAt ?? Date.now(),
          });
          // 空白凭据表示沿用已保存值；绝不把明文写进 state.json。
          for (const [field, value] of [
            ['secretId', raw.secretId],
            ['secretKey', raw.secretKey],
            ['token', raw.token],
            ['endpoint', raw.endpoint],
          ] as const)
            if (value) store.putSecret(`dns:account:${id}:${field}`, value);
          store.data.dnsAccounts = existing
            ? store.data.dnsAccounts.map((item) => (item.id === id ? account : item))
            : [...store.data.dnsAccounts, account];
          await store.persist();
          changed();
          return account;
        },
        [ACTIONS.dnsAccountDelete]: async (p) => {
          const id = z
            .string()
            .regex(/^[a-zA-Z0-9_-]{1,80}$/)
            .parse(p);
          store.data.dnsAccounts = store.data.dnsAccounts.filter((account) => account.id !== id);
          store.dropSecrets(`dns:account:${id}:`);
          await store.persist();
          changed();
        },
        [ACTIONS.dnsAccountTest]: async (p) => {
          const value = z
            .object({
              id: z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/),
              name: z.string().min(1).max(100),
              provider: dnsAccountSchema.shape.provider,
              secretId: z.string().max(512).optional(),
              secretKey: z.string().max(512).optional(),
              token: z.string().max(4096).optional(),
              endpoint: z.string().max(512).optional(),
            })
            .parse(p ?? {}) as DnsAccountTestInput;
          return serverCertificates.testAccount(value);
        },
        [ACTIONS.dnsAccountMasked]: async (p) => {
          const id = z
            .string()
            .regex(/^[a-zA-Z0-9_-]{1,80}$/)
            .parse(p);
          const account = store.data.dnsAccounts.find((item) => item.id === id);
          if (!account) return {};
          const fields = ['secretId', 'secretKey', 'token', 'endpoint'] as const;
          const result: Record<string, string> = {};
          for (const field of fields)
            result[field] = maskCredential(savedSecretOf(store, `dns:account:${id}:${field}`));
          return result;
        },
        [ACTIONS.acmeMasked]: async () => ({
          eabKid: maskCredential(savedSecretOf(store, 'acme:litessl:eabKid')),
          eabHmac: maskCredential(savedSecretOf(store, 'acme:litessl:eabHmac')),
        }),
        [ACTIONS.dnsDomains]: async (p) => {
          const value = z
            .object({
              accountId: z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/),
              provider: dnsAccountSchema.shape.provider,
            })
            .parse(p ?? {});
          const account = store.data.dnsAccounts.find((item) => item.id === value.accountId);
          if (!account) throw new AppError('DNS 账户不存在，请重新选择。');
          return manageAdapterForAccount(account.provider, store, value.accountId).listDomains();
        },
        [ACTIONS.dnsRecords]: async (p) => {
          const value = z
            .object({
              accountId: z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/),
              provider: dnsAccountSchema.shape.provider,
              domain: z.string().min(1).max(253),
            })
            .parse(p ?? {});
          const account = store.data.dnsAccounts.find((item) => item.id === value.accountId);
          if (!account) throw new AppError('DNS 账户不存在，请重新选择。');
          return manageAdapterForAccount(account.provider, store, value.accountId).listRecords(
            value.domain,
          );
        },
        [ACTIONS.dnsRecordSave]: async (p) => {
          const value = z
            .object({
              accountId: z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/),
              provider: dnsAccountSchema.shape.provider,
              domain: z.string().min(1).max(253),
              recordId: z.string().max(120).optional(),
              name: z.string().min(1).max(253),
              type: z.string().min(1).max(20),
              value: z.string().min(1).max(4096),
              ttl: z.number().int().min(1).max(86400),
              line: z.string().max(60).optional(),
              priority: z.number().int().min(0).max(65535).optional(),
              proxied: z.boolean().optional(),
            })
            .parse(p ?? {});
          const account = store.data.dnsAccounts.find((item) => item.id === value.accountId);
          if (!account) throw new AppError('DNS 账户不存在，请重新选择。');
          const adapter = manageAdapterForAccount(account.provider, store, value.accountId);
          const record = {
            name: value.name,
            type: value.type.toUpperCase(),
            value: value.value,
            ttl: value.ttl,
            line: value.line,
            priority: value.priority,
            proxied: value.proxied,
          };
          if (value.recordId) await adapter.updateRecord(value.domain, value.recordId, record);
          else await adapter.createRecord(value.domain, record);
        },
        [ACTIONS.dnsRecordDelete]: async (p) => {
          const value = z
            .object({
              accountId: z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/),
              provider: dnsAccountSchema.shape.provider,
              domain: z.string().min(1).max(253),
              recordId: z.string().min(1).max(120),
            })
            .parse(p ?? {});
          const account = store.data.dnsAccounts.find((item) => item.id === value.accountId);
          if (!account) throw new AppError('DNS 账户不存在，请重新选择。');
          await manageAdapterForAccount(account.provider, store, value.accountId).deleteRecord(
            value.domain,
            value.recordId,
          );
        },
        'file:pick': async (p) => {
          const purpose = z.enum(['key', 'archive', 'config', 'certificate']).parse(p);
          const options: Electron.OpenDialogOptions = {
            properties: ['openFile'],
            title: purpose === 'archive' ? '选择 FRP 完整安装包' : '选择文件',
          };
          if (purpose === 'key') {
            options.defaultPath = path.join(os.homedir(), '.ssh');
          }
          const selected = await dialog.showOpenDialog(window!, options);
          return selected.canceled ? '' : selected.filePaths[0];
        },
        'file:read-config': async (p) => {
          const selected = await dialog.showOpenDialog(window!, {
            properties: ['openFile'],
            title: '导入原始配置',
            filters: [{ name: '配置', extensions: ['toml', 'ini', 'yaml', 'yml', 'json'] }],
          });
          if (selected.canceled) return null;
          const content = await readFile(selected.filePaths[0], 'utf8');
          if (content.length > 1048576) throw new AppError('配置文件超过 1MB。');
          const extension = path.extname(selected.filePaths[0]).slice(1);
          return { content, format: extension === 'yml' ? 'yaml' : extension };
        },
        'token:generate': () => randomBytes(24).toString('hex'),
        clipboard: (p) => clipboard.writeText(z.string().max(1048576).parse(p)),
        'link:open': async (p) => {
          const url = new URL(z.string().parse(p));
          if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password)
            throw new AppError('仅允许打开 HTTP/HTTPS 地址。');
          await shell.openExternal(url.toString());
        },
        // ── 服务端证书：只读探测、签发、部署、环境复核、续期 ──
        [ACTIONS.tlsPlan]: async (p) => {
          const value = z.object({ serverId: idSchema }).parse(p);
          return serverCertificates.plan(value.serverId);
        },
        [ACTIONS.certificateInspect]: async (p) => {
          const value = z
            .object({
              serverId: idSchema,
              domains: z.array(z.string().max(253)).max(100).optional(),
            })
            .parse(p);
          const domains = value.domains?.length
            ? value.domains
            : store.data.serverCertificates
                .filter((certificate) => certificate.serverId === value.serverId)
                .flatMap((certificate) => certificate.domains);
          const report = await siteInspector.inspect(value.serverId, domains);
          await store.saveInspection(value.serverId, report);
          changed();
          return report;
        },
        [ACTIONS.certificateIssueServer]: async (p) => {
          const value = z
            .object({
              taskId: idSchema,
              serverId: idSchema,
              name: z.string().max(100).default(''),
              domains: z.array(z.string().max(253)).min(1).max(100),
              provider: z.enum(['letsencrypt', 'litessl']),
              email: z.string().email().max(254),
              challenge: z.enum(['http-01', 'dns-01']),
              dnsAutomation: z.enum(['api', 'cname', 'reuse', 'manual']).optional(),
              dnsAccountId: z
                .string()
                .regex(/^[a-zA-Z0-9_-]{1,80}$/)
                .optional(),
              httpInstanceId: z
                .string()
                .regex(/^[a-zA-Z0-9_-]{1,80}$/)
                .optional(),
              certTarget: z.enum(['local', 'server']).optional(),
              localCertificateId: z
                .string()
                .regex(/^[a-zA-Z0-9_-]{1,80}$/)
                .optional(),
              termsAgreed: z.boolean(),
              eabKid: z.string().max(4096).optional(),
              eabHmac: z.string().max(4096).optional(),
              keySize: z.union([z.literal(2048), z.literal(3072), z.literal(4096)]).optional(),
              ruleId: z
                .string()
                .regex(/^[a-zA-Z0-9_-]{1,80}$/)
                .optional(),
            })
            .parse(p) as IssueServerInput;
          if (certificateIssueControllers.has(value.taskId))
            throw new AppError('此证书签发任务已存在。');
          const controller = new AbortController();
          certificateIssueControllers.set(value.taskId, controller);
          try {
            const record = await serverCertificates.issue(value, {
              taskId: value.taskId,
              signal: controller.signal,
              onProgress: (progress) => reportCertificateProgress(value.taskId, progress),
            });
            // 方案 B 新增隐藏 HTTPS 伴随规则后，运行中的 frpc 需要重载才能暴露 443 入口。
            if (record.instanceId && processes.running(record.instanceId)) {
              await processes.stop(record.instanceId);
              await processes.start(record.instanceId);
            }
            changed();
            return record;
          } catch (error) {
            reportCertificateProgress(value.taskId, {
              status: controller.signal.aborted ? 'cancelled' : 'failed',
              step: '签发结束',
              message:
                error instanceof Error ? redact(error.message, store.allSecrets()) : String(error),
            });
            throw error;
          } finally {
            dnsChallengeWaiters.delete(value.taskId);
            certificateIssueControllers.delete(value.taskId);
          }
        },
        [ACTIONS.certificateReadPem]: async (p) => {
          const value = z.object({ id: idSchema }).parse(p);
          return localCertificates.readPem(value.id);
        },
        [ACTIONS.certificateDetail]: async (p) => {
          const id = pickId(p);
          // 规则 SSL 面板在方案 B 下传的是本机证书 id（localCertificateId / 伴随规则 id），
          // 不是服务端证书记录 id。先按签发记录的 localCertificateId 回查，再兜到本机证书库，
          // 保证「存放位置」始终可读，而不是一律报「证书不存在或已被删除」。
          const cert =
            store.data.serverCertificates.find((item) => item.id === id) ??
            store.data.serverCertificates.find((item) => item.localCertificateId === id);
          // 路径是纯计算，不依赖文件是否仍存在；内容读取单独容错，避免一个文件读不到
          // 就把「存放位置」也一起吞掉。
          const readLocalPem = async (localId: string) => {
            try {
              return await localCertificates.readPem(localId);
            } catch {
              return { certPem: '', keyPem: '' };
            }
          };
          if (!cert) {
            const local = store.data.certificates.find((item) => item.id === id);
            if (!local) throw new AppError('证书不存在或已被删除。');
            const pem = await readLocalPem(id);
            return {
              id,
              storage: 'local' as const,
              certPath: local.certPath,
              keyPath: local.keyPath,
              certPem: pem.certPem,
              keyPem: pem.keyPem,
            };
          }
          if (cert.tlsPlan === 'server') {
            const certPath = cert.serverCertPath ?? '';
            const keyPath = cert.serverKeyPath ?? '';
            let certPem = '';
            let keyPem = '';
            try {
              const admin = remote.nginxAdmin(cert.serverId);
              if (certPath) certPem = await admin.read(certPath);
              if (keyPath) keyPem = await admin.read(keyPath);
            } catch {
              // SSH 未连接或远端文件已移除时，仍返回已记录的存放位置。
            }
            return {
              id: cert.id,
              storage: 'server' as const,
              certPath,
              keyPath,
              configPath: cert.serverConfigPath ?? '',
              certPem,
              keyPem,
            };
          }
          const localId = cert.localCertificateId ?? cert.id;
          const paths = localCertificates.pathFor(localId);
          const pem = await readLocalPem(localId);
          return {
            id: cert.id,
            storage: 'local' as const,
            certPath: paths.certPath,
            keyPath: paths.keyPath,
            certPem: pem.certPem,
            keyPem: pem.keyPem,
          };
        },
        [ACTIONS.certificateDelete]: async (p) => {
          const outcome = await serverCertificates.removeById(pickId(p));
          if (processes.running(outcome.instanceId)) {
            await processes.stop(outcome.instanceId);
            await processes.start(outcome.instanceId);
          }
          changed();
          return outcome;
        },
        [ACTIONS.certificateImportPem]: async (p) => {
          const value = z
            .object({
              instanceId: idSchema,
              name: z.string().max(100).default(''),
              domains: z.array(z.string().max(253)).min(1).max(100),
              certPem: z.string().max(1048576).min(1),
              keyPem: z.string().max(1048576).min(1),
            })
            .parse(p);
          const instance = store.instance(value.instanceId);
          if (instance.mode !== 'form')
            throw new AppError('高级原始配置实例不能通过表单启用证书。');
          const record = await localCertificates.importPemText({
            name: value.name || value.domains[0],
            domains: value.domains,
            certPem: value.certPem,
            keyPem: value.keyPem,
          });
          const wasRunning = processes.running(instance.id);
          await serverCertificates.enableLocalCertificate(
            value.instanceId,
            value.domains,
            record.id,
          );
          if (wasRunning) {
            await processes.stop(instance.id);
            await processes.start(instance.id);
          }
          changed();
          return record;
        },
        [ACTIONS.certificateRemove]: async (p) => {
          const value = z.object({ instanceId: idSchema, ruleId: idSchema }).parse(p);
          const wasRunning = processes.running(value.instanceId);
          const outcome = await serverCertificates.removeForRule(value.instanceId, value.ruleId);
          if (wasRunning) {
            await processes.stop(value.instanceId);
            await processes.start(value.instanceId);
          }
          changed();
          return outcome;
        },
        [ACTIONS.certificateDeploy]: async (p) => {
          const value = z
            .object({
              certificateId: idSchema,
              level: z.enum(['L0', 'L1', 'L2']),
              target: z.string().max(4096).optional(),
              confirmed: z.boolean().default(false),
            })
            .parse(p);
          const outcome = await serverCertificates.deploy(
            value.certificateId,
            value.level,
            value.target,
            value.confirmed,
          );
          changed();
          return outcome;
        },
        [ACTIONS.certificateRefreshEnv]: async (p) => {
          const value = z
            .object({ serverId: idSchema, certificateId: idSchema.optional() })
            .parse(p);
          const outcome = await serverCertificates.refreshEnvironment(value.serverId);
          changed();
          return outcome;
        },
        [ACTIONS.certificateRenewNow]: async (p) => {
          const value = z
            .object({
              certificateId: idSchema,
              serverId: idSchema.optional(),
              confirmed: z.boolean().optional(),
            })
            .parse(p);
          const taskId = `renew-${value.certificateId}`.slice(0, 80);
          const record = await serverCertificates.renewNow(value.certificateId, {
            taskId,
            signal: new AbortController().signal,
            onProgress: (progress) => reportCertificateProgress(taskId, progress),
          });
          changed();
          return record;
        },
        [ACTIONS.certificateDnsTest]: async (p) => {
          const value = z
            .object({
              provider: z.string().max(64),
              domain: z.string().max(253).optional(),
              secretId: z.string().max(512).optional(),
              secretKey: z.string().max(512).optional(),
              token: z.string().max(4096).optional(),
              endpoint: z.string().max(512).optional(),
            })
            .parse(p) as DnsTestInput;
          return serverCertificates.testDns(value);
        },
        // ── 托管 TLS 实例：隔离安装 / 启停 / 让位 / 一键卸载 ──
        [ACTIONS.tlsProxyStatus]: async (p) => {
          const value = z.object({ serverId: idSchema }).parse(p);
          const status = await tlsProxy.status(value.serverId);
          changed();
          return status;
        },
        [ACTIONS.tlsProxyInstall]: async (p) => {
          const status = await tlsProxy.install(tlsInput.parse(p), reportTlsProxyProgress);
          changed();
          return status;
        },
        [ACTIONS.tlsProxyStart]: async (p) => {
          const status = await tlsProxy.start(tlsInput.parse(p), reportTlsProxyProgress);
          changed();
          return status;
        },
        [ACTIONS.tlsProxyStop]: async (p) => {
          const status = await tlsProxy.stop(tlsInput.parse(p), reportTlsProxyProgress);
          changed();
          return status;
        },
        [ACTIONS.tlsProxyYield]: async (p) => {
          const status = await tlsProxy.yieldPorts(tlsInput.parse(p), reportTlsProxyProgress);
          changed();
          return status;
        },
        [ACTIONS.tlsProxyUninstall]: async (p) => {
          const result = await tlsProxy.uninstall(tlsInput.parse(p), reportTlsProxyProgress);
          changed();
          return result;
        },
        // ── 版本库：启动秒开缓存 / 取消 / 断点重试 ──
        [ACTIONS.versionCatalogCached]: () => versions.cachedCatalog(),
        [ACTIONS.versionDownloadCancel]: (p) => {
          const value = z
            .object({
              taskId: z.string().max(100),
              key: z.string().max(300).optional(),
              discard: z.boolean().optional(),
            })
            .parse(p);
          return versions.cancelDownload(value.taskId, value.discard ?? false);
        },
        [ACTIONS.versionDownloadRetry]: async (p) => {
          const value = z
            .object({ taskId: z.string().max(100), key: z.string().max(300).optional() })
            .parse(p);
          const installed = await versions.retryDownload(value.taskId);
          changed();
          return installed;
        },
        'app:quit': () => app.quit(),
      };
      ipcMain.handle('rpc', async (event, action: string, payload: unknown): Promise<Result> => {
        if (
          !window ||
          event.sender !== window.webContents ||
          event.senderFrame !== window.webContents.mainFrame
        )
          return { ok: false, error: '无权调用主进程。' };
        try {
          if (typeof action !== 'string' || !Object.hasOwn(handlers, action))
            throw new AppError('不支持的操作。');
          const data = await handlers[action](payload);
          return { ok: true, data };
        } catch (error) {
          return {
            ok: false,
            error: redact(friendlyError(error), store.allSecrets()),
            code: error instanceof AppError ? error.code : 'FAILED',
          };
        }
      });
      const isMainFrame = (event: Electron.IpcMainEvent) =>
        !!window &&
        event.sender === window.webContents &&
        event.senderFrame === window.webContents.mainFrame;
      ipcMain.on('terminal:input', (event, payload: unknown) => {
        if (!isMainFrame(event)) return;
        const value = z
          .object({ terminalId: z.string().uuid(), data: z.string().max(262144) })
          .safeParse(payload);
        if (value.success) remote.writeTerminal(value.data.terminalId, value.data.data);
      });
      ipcMain.on('terminal:resize', (event, payload: unknown) => {
        if (!isMainFrame(event)) return;
        const value = z
          .object({
            terminalId: z.string().uuid(),
            cols: z.number().int().min(20).max(400),
            rows: z.number().int().min(5).max(200),
          })
          .safeParse(payload);
        if (value.success)
          remote.resizeTerminal(value.data.terminalId, value.data.cols, value.data.rows);
      });
      ipcMain.on('terminal:close', (event, payload: unknown) => {
        if (!isMainFrame(event)) return;
        const value = z.string().uuid().safeParse(payload);
        if (value.success) remote.closeTerminal(value.data);
      });
      const opt: Electron.BrowserWindowConstructorOptions = {
        width: 1280,
        height: 850,
        minWidth: 980,
        minHeight: 650,
        title: '穿透工作台',
        backgroundColor: '#f4f6fa',
        icon: path.join(iconDirectory, '256x256.png'),
        webPreferences: {
          preload: path.join(__dirname, 'index.preload.js'),
          contextIsolation: true,
          nodeIntegration: false,
          sandbox: true,
        },
      };
      if (process.env.NODE_ENV === 'development') opt.width = 3280;
      window = new BrowserWindow(opt);
      // 打包时 preload 输出重命名见构建脚本，开发时使用同一文件名。
      window.on('closed', () => {
        window = undefined;
      });
      // window.webContents.openDevTools();
      window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
      window.webContents.on('will-navigate', (event, url) => {
        if (url !== window?.webContents.getURL()) event.preventDefault();
      });
      window.webContents.session.setPermissionRequestHandler(
        (_webContents, _permission, callback) => callback(false),
      );
      window.on('close', (event) => {
        if (!quitting && tray) {
          event.preventDefault();
          window?.hide();
        }
      });
      // macOS 模板图由系统自动适配主题，Windows/Linux 使用高对比彩色小图。
      const icon = nativeImage.createFromPath(
        path.join(
          iconDirectory,
          process.platform === 'darwin' ? 'trayTemplate.png' : 'trayColor.png',
        ),
      );
      if (process.platform === 'darwin') icon.setTemplateImage(true);
      tray = new Tray(icon);
      tray.setToolTip('穿透工作台');
      tray.setContextMenu(
        Menu.buildFromTemplate([
          { label: '打开穿透工作台', click: () => window?.show() },
          { type: 'separator' },
          { label: '退出并停止本机穿透', click: () => app.quit() },
        ]),
      );
      tray.on('double-click', () => window?.show());
      Menu.setApplicationMenu(
        Menu.buildFromTemplate([
          {
            label: '穿透工作台',
            submenu: [
              { label: '打开窗口', click: () => window?.show() },
              { label: '退出并停止本机穿透', click: () => app.quit() },
            ],
          },
          {
            label: '编辑',
            submenu: [
              { role: 'undo' },
              { role: 'redo' },
              { type: 'separator' },
              { role: 'cut' },
              { role: 'copy' },
              { role: 'paste' },
              { role: 'selectAll' },
            ],
          },
        ]),
      );
      if (process.env.VITE_DEV_SERVER_URL) await window.loadURL(process.env.VITE_DEV_SERVER_URL);
      else await window.loadFile(path.join(__dirname, '../renderer/index.html'));
      app.on('activate', () => window?.show());
    })
    .catch((error) => {
      dialog.showErrorBox('启动失败', friendlyError(error));
      quitting = true;
      app.quit();
    });
}
app.on('before-quit', (event) => {
  for (const controller of certificateIssueControllers.values()) controller.abort();
  if (quitting || !processes) return;
  event.preventDefault();
  quitting = true;
  void processes.shutdown().finally(() => {
    remote.closeAll();
    tray?.destroy();
    app.quit();
  });
});
app.on('window-all-closed', () => {
  if (!tray) app.quit();
});
