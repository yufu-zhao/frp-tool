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
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { Store } from './store';
import { Versions } from './versions';
import { Processes, execute } from './processes';
import { Remote, quote } from './remote';
import { applyNginxSite, removeHttpInclude } from './server-sites';
import { parseDiscoveredFrpsConfig } from './service-discovery';
import {
  Certificates,
  normalizeDomains,
  type DnsChallengeRecord,
  type CertificateIssueProgressUpdate,
} from './certificates';
import { validateRules } from './frp';
import { notifyRenderer } from './lifecycle';
import { AppError, friendlyError, redact } from '../shared/errors';
import {
  serverSchema,
  instanceSchema,
  settingsSchema,
  installSchema,
  terminalFavoriteSchema,
  type Result,
  type Instance,
  type Server,
  type CertificateIssueProgress,
  type TerminalEvent,
} from '../shared/types';

const iconDirectory = path.join(__dirname, '../../assets/icons');
let window: BrowserWindow | undefined;
let tray: Tray | undefined;
let quitting = false;
let store: Store;
let processes: Processes;
let remote: Remote;
let certificates: Certificates;
let certificateRenewalTimer: ReturnType<typeof setInterval> | undefined;
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
  if (window && !window.isDestroyed()) window.webContents.send('certificate:progress', state);
}

// HTTP-01 必须把每个域名的验证请求映射到唯一的表单实例及公网 80 入口。
function resolveHttp01Assignments(instances: Instance[], servers: Server[], domains: string[]) {
  const assignments = new Map<string, Set<string>>();
  for (const domain of domains) {
    const matches = instances.flatMap((instance) =>
      instance.mode === 'form'
        ? instance.proxies
            .filter(
              (rule) =>
                (rule.type === 'http' || rule.type === 'https') &&
                rule.domains.some((candidate) => candidate.toLowerCase() === domain),
            )
            .map((rule) => ({ instance, rule }))
        : [],
    );
    if (matches.length !== 1)
      throw new AppError(
        `域名 ${domain} 必须恰好关联一条表单 HTTP/HTTPS 规则，才能通过 FRP 完成 HTTP-01 验证。`,
      );
    const { instance } = matches[0];
    const server = servers.find((item) => item.id === instance.serverId);
    // TODO 临时注释
    // if (!server || server.configMode !== 'form' || server.httpPort !== 80)
    //   throw new AppError(
    //     `域名 ${domain} 对应的服务器未确认 FRP HTTP 入口为公网 80 端口，请改用手动 DNS-01。`,
    //   );
    const instanceDomains = assignments.get(instance.id) ?? new Set<string>();
    instanceDomains.add(domain);
    assignments.set(instance.id, instanceDomains);
  }
  return [...assignments].map(([instanceId, values]) => ({
    instanceId,
    domains: [...values],
  }));
}

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
      certificates = new Certificates(
        store,
        changed,
        async (records: DnsChallengeRecord[]) => {
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
        },
        async (assignments, operation, signal) => {
          const running = assignments.filter((item) => processes.running(item.instanceId));
          if (running.length) {
            const names = running.map((item) => store.instance(item.instanceId).name).join('、');
            const answer = await dialog.showMessageBox({
              type: 'warning',
              title: 'HTTP-01 验证需要临时重启客户端实例',
              message: '签发期间相关实例会短暂中断。',
              detail: `以下实例会添加临时验证规则；验证结束后恢复原配置并重新启动：${names}。确认继续？`,
              buttons: ['取消', '确认并继续'],
              defaultId: 0,
              cancelId: 0,
            });
            if (answer.response !== 1) throw new AppError('用户取消了 HTTP-01 临时重启。');
          }
          if (signal?.aborted) throw new AppError('用户已取消 HTTP-01 临时重启。', 'CANCELLED');
          const result = await processes.withHttp01Challenge(assignments, operation);
          for (const { instanceId } of running) await certificates.instanceStarted(instanceId);
          return result;
        },
        (id) => processes.running(id),
      );
      const checkCertificateRenewals = () =>
        certificates
          .renewDue((certificate) =>
            resolveHttp01Assignments(store.data.instances, store.data.servers, certificate.domains),
          )
          .catch((error: unknown) => {
            const message = error instanceof Error ? error.message : String(error);
            console.warn(`SSL 自动续期检查失败：${redact(message, store.allSecrets())}`);
          });
      void checkCertificateRenewals();
      certificateRenewalTimer = setInterval(() => void checkCertificateRenewals(), 60 * 60 * 1000);
      certificateRenewalTimer.unref();
      const idSchema = z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/);
      const pickId = (input: unknown) => idSchema.parse(input);
      const yes = async (message: string, detail: string) =>
        (
          await dialog.showMessageBox(window!, {
            type: 'warning',
            message,
            detail,
            buttons: ['取消', '确认'],
            defaultId: 0,
            cancelId: 0,
          })
        ).response === 1;
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
          if (remote.connected(server.id))
            throw new AppError('请先断开 SSH 再修改服务器连接配置。');
          await store.saveServer(server);
          changed();
        },
        'server:uninstall': async (payload) => {
          const value = z
            .object({ id: idSchema, removeRemote: z.boolean().default(false) })
            .parse(payload);
          const id = value.id;
          const server = store.server(id);
          if (store.data.serverSites.some((site) => site.serverId === id))
            throw new AppError(
              '此服务器仍有应用管理的 Nginx 站点，请先删除站点后再卸载服务器配置。',
            );
          if (store.data.instances.some((i) => i.serverId === id))
            throw new AppError('此服务器仍被客户端实例引用，请先更换关联或删除实例。');
          if (server.deployment) {
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
          } else if (!(await yes('卸载服务器配置？', `${server.name}\n只移除本机配置。`))) {
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
        'server:status': (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器不提供 FRP 服务端状态管理。');
          return remote.status(id);
        },
        'server:deploy': async (p) => {
          const { id, key } = z.object({ id: idSchema, key: z.string() }).parse(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('此服务器为只读连接，不能部署或管理 FRP 服务端。');
          if (
            !(await yes(
              '安装 FRP 服务端？',
              '将上传所选 Linux 安装包，写入配置并安装可用的服务管理方式。安装后需要单独点击启动；不会修改防火墙或云安全组。',
            ))
          )
            return;
          return remote.deploy(id, key);
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
          const matches = await remote.searchFrpsServices(value.id, value.service);
          const candidate = matches.find(
            (item) =>
              item.service === value.service &&
              item.manager === value.manager &&
              item.binary === value.binary &&
              item.config === value.config,
          );
          if (!candidate) throw new AppError('服务信息已变化或不再匹配 FRP，请重新检索。');
          const rawConfig = await remote.readRemoteText(value.id, candidate.config);
          const connection = parseDiscoveredFrpsConfig(rawConfig, candidate.config);
          const securelyStored = await store.saveDiscoveredServerConfig(value.id, connection, {
            name: candidate.service,
            manager: candidate.manager,
            binary: candidate.binary,
            config: candidate.config,
          });
          changed();
          return {
            note: securelyStored
              ? `已读取 ${connection.format.toUpperCase()} 配置并保存为只读服务器；FRP 令牌使用系统安全存储保护。`
              : `已读取 ${connection.format.toUpperCase()} 配置并保存为只读服务器；当前系统安全存储不可用，令牌只在本次应用运行期间保留，重启后需重新检索。`,
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
        'server:apply': async (p) => {
          const id = pickId(p);
          if (store.server(id).accessMode === 'readonly')
            throw new AppError('只读服务器不可修改 FRP 服务端配置。');
          if (
            !(await yes(
              '应用服务端配置？',
              '将校验新配置、备份旧配置并替换文件。服务不会自动重启。',
            ))
          )
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
            ))
          )
            return;
          return remote.changeVersion(value.id, value.key);
        },
        'instance:save': async (p) => {
          const item = instanceSchema.parse(p);
          if (item.mode === 'raw' && !item.rawConfig.trim())
            throw new AppError('高级客户端配置不能为空。');
          if (processes.running(item.id)) throw new AppError('请先停止实例再修改配置。');
          if (item.mode === 'form') {
            for (const rule of item.proxies)
              if (rule.type === 'http' || rule.type === 'https') {
                console.log(rule.domains.filter(Boolean));
                rule.domains = normalizeDomains(rule.domains.filter(Boolean));
              }
            validateRules(item.proxies);
            const coveredDomains = (domains: string[]) =>
              new Set(domains.map((domain) => domain.toLowerCase().replace(/\.$/, '')));
            for (const rule of item.proxies) {
              if (rule.type !== 'https' || rule.tlsMode !== 'terminate' || !rule.certificateId)
                continue;
              const certificate = store.data.certificates.find(
                (candidate) => candidate.id === rule.certificateId,
              );
              if (!certificate) throw new AppError(`${rule.name} 关联的证书不存在。`);
              const covered = coveredDomains(certificate.domains);
              if (!rule.domains.every((domain) => covered.has(domain)))
                throw new AppError(`${rule.name} 的域名未被关联证书全部覆盖。`);
            }
          }
          await store.saveInstance(item);
          changed();
        },
        'instance:delete': async (p) => {
          const id = pickId(p);
          store.instance(id);
          if (!(await yes('删除客户端实例？', '此实例的本机穿透将停止，配置将删除。'))) return;
          await processes.stop(id);
          store.data.serverSites = store.data.serverSites.map((site) =>
            site.instanceId === id ? { ...site, outOfSync: true } : site,
          );
          store.dropSecrets(`instance:${id}:`);
          store.data.instances = store.data.instances.filter((i) => i.id !== id);
          await store.persist();
          changed();
        },
        'site:create': async (p) => {
          const input = z
            .object({
              instanceId: idSchema,
              ruleId: idSchema,
              mainConfig: z.string().max(4096).optional(),
            })
            .parse(p);
          const instance = store.instance(input.instanceId);
          const server = store.server(instance.serverId);
          if (server.accessMode === 'readonly')
            throw new AppError('只读服务器不可修改 Nginx 站点。');
          if (!remote.connected(server.id)) throw new AppError('请先连接目标服务器的 SSH。');
          if (instance.mode !== 'form')
            throw new AppError('高级配置实例无法自动读取 HTTP 域名，请使用表单模式。');
          const rule = instance.proxies.find((item) => item.id === input.ruleId);
          if (!rule || rule.type !== 'http' || !rule.domains.length)
            throw new AppError('来源规则必须是含域名的 HTTP 规则。');
          if (
            store.data.serverSites.some(
              (site) =>
                site.serverId === server.id &&
                site.domains.some((domain) => rule.domains.includes(domain)),
            )
          )
            throw new AppError('该服务器已有站点使用这些域名。');
          const taskId = randomBytes(12).toString('hex');
          const progress = (step: string, message: string) =>
            window?.webContents.send('server-site:progress', {
              taskId,
              status: step === '完成' ? 'completed' : 'running',
              step,
              message,
              updatedAt: Date.now(),
            });
          return remote.locked(server.id, async () => {
            progress('检测权限', '确认 root 或免密 sudo 权限');
            const admin = remote.nginxAdmin(server.id);
            await admin.run('command -v nginx >/dev/null && nginx -t');
            progress('发现配置', '读取 Nginx 主配置路径');
            const dump = await admin.run('nginx -T 2>&1');
            const detected = /^nginx: the configuration file (\S+) syntax is ok/m.exec(dump)?.[1];
            const mainConfig = input.mainConfig || detected;
            if (!mainConfig || !mainConfig.startsWith('/'))
              throw new AppError('无法从 nginx -T 定位主配置。可再次创建并填写主配置绝对路径。');
            const info = await remote.detect(server.id);
            const root = `${info.home}/.local/share/intranet-frp`;
            const site = {
              id: randomBytes(12).toString('hex'),
              name: rule.name,
              domains: rule.domains,
              upstreamPort: server.httpPort,
              acmeRoot: `${root}/acme/http01`,
            };
            progress('备份并写入', '保存 Nginx 配置备份并生成站点');
            await admin.run(
              `mkdir -p -- ${quote(`${root}/vhost/nginx`)} ${quote(`${root}/acme/http01/.well-known/acme-challenge`)} ${quote(`${root}/backups`)}`,
            );
            const applied = await applyNginxSite(admin, mainConfig, site);
            const record = {
              ...site,
              serverId: server.id,
              instanceId: instance.id,
              ruleId: rule.id,
              configPath: applied.configPath,
              mainConfig,
              includeCreatedByApp: applied.includeCreatedByApp,
              createdAt: Date.now(),
              outOfSync: false,
            };
            await store.saveServerSite(record);
            progress('完成', 'Nginx 语法检查与重载成功');
            changed();
            return record;
          });
        },
        'site:delete': async (p) => {
          const { id } = z.object({ id: idSchema }).parse(p);
          const site = store.data.serverSites.find((item) => item.id === id);
          if (!site) throw new AppError('站点记录不存在。');
          if (store.server(site.serverId).accessMode === 'readonly')
            throw new AppError('只读服务器不可删除 Nginx 站点。');
          if (
            !(await yes(
              '删除 Nginx 站点？',
              `${site.domains.join('、')}\n只删除应用创建的站点配置，并测试、重载 Nginx。`,
            ))
          )
            return;
          if (!remote.connected(site.serverId)) await remote.connect(site.serverId);
          return remote.locked(site.serverId, async () => {
            const admin = remote.nginxAdmin(site.serverId);
            const path = site.configPath;
            const content = await admin.read(path);
            if (!content.includes('# 由穿透工作台管理；修改前请在应用中操作。'))
              throw new AppError(
                '站点配置已不再带有本应用标记，为避免删除用户修改后的文件，已停止操作。',
              );
            const backup = `${path}.intranet-backup-${Date.now()}`;
            const remaining = store.data.serverSites.filter(
              (item) => item.serverId === site.serverId && item.id !== id,
            );
            const mainConfig = site.mainConfig;
            const includeRoot = path.split('/vhost/nginx/')[0];
            const includePath = `${includeRoot}/vhost/nginx/*.conf`;
            const removeInclude = !remaining.length && !!mainConfig && site.includeCreatedByApp;
            const mainContent = removeInclude && mainConfig ? await admin.read(mainConfig) : '';
            const mainMode = removeInclude && mainConfig ? await admin.mode(mainConfig) : '644';
            const mainBackup = removeInclude
              ? `${includeRoot}/backups/nginx-main-remove-${Date.now()}.conf`
              : '';
            if (removeInclude && mainConfig && (await admin.read(mainConfig)) !== mainContent)
              throw new AppError('Nginx 主配置在操作期间发生变化，请重试以避免覆盖外部修改。');
            await admin.run(
              `${removeInclude && mainConfig ? `cp -p -- ${quote(mainConfig)} ${quote(mainBackup)} && ` : ''}cp -p -- ${quote(path)} ${quote(backup)} && rm -f -- ${quote(path)}`,
            );
            try {
              if (removeInclude && mainConfig)
                await admin.write(
                  mainConfig,
                  removeHttpInclude(mainContent, includePath),
                  mainMode,
                );
              await admin.run('nginx -t && nginx -s reload');
            } catch (error) {
              await admin.write(path, content, '644').catch(() => {});
              if (removeInclude && mainConfig)
                await admin.write(mainConfig, mainContent, mainMode).catch(() => {});
              await admin.run('nginx -t && nginx -s reload').catch(() => {});
              throw error;
            }
            store.data.serverSites = store.data.serverSites.filter((item) => item.id !== id);
            await store.persist();
            changed();
            return { note: 'Nginx 站点已删除。' };
          });
        },
        'instance:start': async (p) => {
          const id = pickId(p);
          await processes.start(id);
          await certificates.instanceStarted(id);
        },
        'instance:stop': (p) => processes.stop(pickId(p)),
        'instance:restart': async (p) => {
          const id = pickId(p);
          await processes.stop(id);
          await processes.start(id);
          await certificates.instanceStarted(id);
        },
        'instance:logs': (p) => processes.log(pickId(p)),
        'instance:logs:clear': async (p) => {
          const id = pickId(p);
          if (
            await yes(
              '清理客户端日志？',
              '只清除此实例在应用中保留的日志，不停止客户端；运行时产生的新日志会继续记录。',
            )
          )
            return processes.clearLogs(id);
        },
        'certificate:import': async (p) => {
          const value = z
            .object({
              name: z.string().max(100).default(''),
              domains: z.array(z.string().max(253)).min(1).max(100),
              certificatePath: z.string().min(1).max(4096),
              privateKeyPath: z.string().min(1).max(4096),
            })
            .parse(p);
          const certificate = await certificates.importManual(value);
          changed();
          return certificate;
        },
        'certificate:issue': async (p) => {
          const value = z
            .object({
              taskId: idSchema,
              name: z.string().max(100).default(''),
              domains: z.array(z.string().max(253)).min(1).max(100),
              provider: z.enum(['letsencrypt', 'litessl']),
              email: z.string().email().max(254),
              challenge: z.enum(['http-01', 'dns-01']),
              termsAgreed: z.boolean(),
              eabKid: z.string().max(4096).optional(),
              eabHmac: z.string().max(4096).optional(),
            })
            .parse(p);
          if (certificateIssueControllers.has(value.taskId))
            throw new AppError('此证书签发任务已存在。');
          const controller = new AbortController();
          certificateIssueControllers.set(value.taskId, controller);
          let currentStep = '校验域名与签发参数';
          reportCertificateProgress(value.taskId, {
            status: 'running',
            step: currentStep,
            message: '正在检查域名、验证方式和证书机构配置。',
          });
          try {
            const domains = normalizeDomains(value.domains);
            const assignments =
              value.challenge === 'http-01'
                ? resolveHttp01Assignments(store.data.instances, store.data.servers, domains)
                : [];
            const record = await certificates.issue({ ...value, domains }, assignments, undefined, {
              taskId: value.taskId,
              signal: controller.signal,
              onProgress: (progress) => {
                currentStep = progress.step;
                reportCertificateProgress(value.taskId, progress);
              },
              promptDnsChallenge: (records) =>
                new Promise<boolean>((resolve) => {
                  const finish = (continueIssue: boolean) => {
                    dnsChallengeWaiters.delete(value.taskId);
                    controller.signal.removeEventListener('abort', onAbort);
                    resolve(continueIssue);
                  };
                  const onAbort = () => finish(false);
                  dnsChallengeWaiters.set(value.taskId, finish);
                  controller.signal.addEventListener('abort', onAbort, { once: true });
                  if (controller.signal.aborted) onAbort();
                  else
                    reportCertificateProgress(value.taskId, {
                      status: 'waiting-user',
                      step: currentStep,
                      message: '请按下面的记录添加 DNS TXT；确认解析生效后继续。',
                      dnsRecords: records,
                    });
                }),
            });
            changed();
            return record;
          } catch (error) {
            const cancelled = controller.signal.aborted;
            reportCertificateProgress(value.taskId, {
              status: cancelled ? 'cancelled' : 'failed',
              step: currentStep,
              message: cancelled
                ? '签发已取消；临时验证配置已开始清理。'
                : redact(friendlyError(error), store.allSecrets()).slice(0, 1200),
            });
            throw error;
          } finally {
            dnsChallengeWaiters.delete(value.taskId);
            certificateIssueControllers.delete(value.taskId);
          }
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
        'certificate:associate': async (p) => {
          const value = z
            .object({
              certificateId: idSchema,
              targets: z
                .array(z.object({ instanceId: idSchema, ruleId: idSchema }))
                .min(1)
                .max(100),
            })
            .parse(p);
          return certificates.associate(value.certificateId, value.targets);
        },
        'certificate:auto-renew': async (p) => {
          const value = z.object({ id: idSchema, enabled: z.boolean() }).parse(p);
          return certificates.setAutoRenew(value.id, value.enabled);
        },
        'certificate:delete': async (p) => {
          const id = pickId(p);
          if (!(await yes('删除 SSL 证书？', '证书和私钥文件将从本机应用目录删除。'))) return;
          await certificates.remove(id);
        },
        'instance:preview': (p) => processes.preview(instanceSchema.parse(p)),
        'version:catalog': (p) =>
          versions.catalog(
            z
              .number()
              .int()
              .min(1)
              .max(1000)
              .parse(p ?? 1),
          ),
        'version:install': async (p) => {
          const request = await versions.resolveReleaseDigest(installSchema.parse(p));
          if (
            !request.digest &&
            !(await yes(
              '安装未经发布校验的程序？',
              '未能取得发布方 SHA256，本次无法与官方摘要核对。请确认下载或导入来源可信；本机安装时仍会执行程序检查实际版本。',
            ))
          )
            return;
          const installed = await versions.install(request);
          changed();
          return installed;
        },
        'version:verify': async (p) => {
          const installed = await versions.verifyInstalledRelease(z.string().parse(p));
          changed();
          return installed;
        },
        'version:delete': async (p) => {
          const key = z.string().parse(p);
          if (await yes('删除本机安装包？', '被实例或部署引用的版本不能删除。'))
            await versions.remove(key);
          changed();
        },
        'settings:save': async (p) => {
          const settings = settingsSchema.parse(p);
          await setProxy(settings.proxyUrl);
          versions.resetNetworkState();
          store.data.settings = settings;
          await store.persist();
          changed();
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
  if (certificateRenewalTimer) clearInterval(certificateRenewalTimer);
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
