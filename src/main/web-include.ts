import { randomBytes } from 'node:crypto';
import { AppError } from '../shared/errors';
import type {
  WebIncludeCandidate,
  WebIncludeFlavor,
  WebIncludeManagedFile,
  WebIncludeProbe,
  WebIncludeStatus,
} from '../shared/types';
import {
  certDirFor,
  certFileName,
  hasManagedInclude,
  HTTP01_CONFIG_FILE,
  HTTP01_ROOT,
  http01Marker,
  includeBlockFor,
  includeDirectiveFor,
  keyFileName,
  managedDirFor,
  nginxHttp01ServerConfig,
  resolveTlsSiteConfig,
  mergeTlsSiteConfig,
  probeConfigFor,
  probeDumpCommand,
  probePathFor,
  removeManagedInclude,
  siteConfigFileName,
} from '../shared/web-include';
import type { NginxAdmin } from './server-sites';
import type { Remote } from './remote';
import { quote } from './remote';
import {
  insertHttpSnippet,
  withNginxTransaction,
  type WebServiceTransactionCommands,
} from './server-sites';
import type { Store } from './store';

const NGINX_PROBE = `if command -v nginx >/dev/null 2>&1; then nginx -T 2>&1 || true; elif command -v openresty >/dev/null 2>&1; then openresty -T 2>&1 || true; else printf '__NO_WEB__\\n'; fi`;
const APACHE_PROBE = `if command -v apachectl >/dev/null 2>&1; then apachectl -V 2>&1 || true; elif command -v httpd >/dev/null 2>&1; then httpd -V 2>&1 || true; else printf '__NO_WEB__\\n'; fi`;

/** 升级前的 challenge 文件名；新版本改用排序最前的 HTTP01_CONFIG_FILE，清理旧残留。 */
const LEGACY_HTTP01_CONFIG_FILE = 'http01.conf';

function parseNginxMain(output: string): string {
  return (
    /configuration file (\S+) syntax is ok/i.exec(output)?.[1] ??
    /--conf-path=(\S+)/.exec(output)?.[1] ??
    ''
  );
}

function parseApacheMain(output: string): string {
  const file = /SERVER_CONFIG_FILE:\s*"([^"]+)"/i.exec(output)?.[1] ?? '';
  if (!file) return '';
  if (file.startsWith('/')) return file;
  const root = /HTTPD_ROOT:\s*"([^"]+)"/i.exec(output)?.[1] ?? '';
  return root ? `${root.replace(/\/$/, '')}/${file}` : '';
}

function commandsFor(flavor: WebIncludeFlavor, serviceName: string): WebServiceTransactionCommands {
  if (flavor === 'nginx') return { validate: 'nginx -t', reload: 'nginx -s reload' };
  const service = quote(serviceName || 'apache2');
  return {
    validate: 'apachectl configtest 2>&1 || httpd -t 2>&1',
    reload: `if command -v systemctl >/dev/null 2>&1 && systemctl is-active ${service} >/dev/null 2>&1; then systemctl reload ${service}; else apachectl graceful 2>&1 || httpd -k graceful 2>&1; fi`,
  };
}

/** 在配置 dump 中查找哨兵标记；Nginx 严格判定，Apache 的 dump 能力因版本而异，只记录提示。 */
async function checkProbe(
  admin: NginxAdmin,
  flavor: WebIncludeFlavor,
  token: string,
  path: string,
): Promise<WebIncludeProbe> {
  let dump = '';
  let note: string | undefined;
  try {
    dump = await admin.run(probeDumpCommand(flavor));
  } catch (error) {
    note = `读取 Web 服务配置失败：${error instanceof Error ? error.message : String(error)}`;
  }
  const ok = dump.includes(token);
  if (!ok && !note && flavor === 'nginx')
    note = '配置 dump 未包含探针标记，未能确认 include 生效。';
  if (!ok && !note) note = '当前 Apache 版本未提供可解析的配置 dump，未能自动确认 include 生效。';
  return { path, token, ok, checkedAt: Date.now(), note };
}

function newProbeToken(): string {
  return `intranet-frp-${randomBytes(8).toString('hex')}`;
}

const FLAVORS: Array<{
  flavor: WebIncludeFlavor;
  services: string[];
  label: string;
  probe: string;
  parse: (output: string) => string;
}> = [
  {
    flavor: 'nginx',
    services: ['nginx', 'openresty'],
    label: 'Nginx',
    probe: NGINX_PROBE,
    parse: parseNginxMain,
  },
  {
    flavor: 'apache',
    services: ['apache2', 'httpd'],
    label: 'Apache',
    probe: APACHE_PROBE,
    parse: parseApacheMain,
  },
];

export class WebIncludeManager {
  constructor(
    private readonly store: Store,
    private readonly remote: Remote,
  ) {}

  /** 只读探测：列出可注入的 Web 服务、主配置与本工具已写入的配置。 */
  async inspect(serverId: string): Promise<WebIncludeStatus> {
    this.store.server(serverId);
    const info = await this.remote.detect(serverId);
    const admin = this.remote.nginxAdmin(serverId);
    const warnings: string[] = [];
    const probes = new Map<WebIncludeFlavor, string>();
    for (const definition of FLAVORS) {
      try {
        probes.set(definition.flavor, await admin.run(definition.probe));
      } catch (error) {
        warnings.push(
          `${definition.label} 配置探测失败：${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    const candidates: WebIncludeCandidate[] = [];
    for (const definition of FLAVORS) {
      const service = info.webServices.find(
        (item) => definition.services.includes(item.name) && (item.installed || item.running),
      );
      if (!service) continue;
      const mainConfig = definition.parse(probes.get(definition.flavor) ?? '');
      const privileged = info.root || info.sudo;
      const reason = !mainConfig
        ? '未能定位主配置文件，请确认已安装完整 Web 服务。'
        : !privileged
          ? '修改 Web 服务主配置需要 root 或免密 sudo。'
          : undefined;
      candidates.push({
        flavor: definition.flavor,
        serviceName: service.name,
        mainConfig,
        running: service.running,
        supported: !reason,
        reason,
      });
    }
    if (!candidates.length)
      warnings.push('未探测到可注入的 Nginx/Apache 服务；Caddy / Lighttpd 暂不支持自动注入。');

    const injected = this.store.data.webIncludes[serverId];
    let probe: WebIncludeProbe | undefined;
    let managedFiles: WebIncludeManagedFile[] = [];
    if (injected) {
      if (injected.probe?.token) {
        probe = await checkProbe(admin, injected.flavor, injected.probe.token, injected.probe.path);
        if (!probe.ok) warnings.push(`include 探针未确认生效：${probe.note ?? '未知原因'}`);
      }
      try {
        const output = await admin.run(
          `find ${quote(injected.managedDir)} -maxdepth 1 -type f -name '*.conf' -printf '%f\\t%s\\t%T@\\n' 2>/dev/null || true`,
        );
        managedFiles = output
          .split('\n')
          .map((line) => {
            const [name, size, modified] = line.trim().split('\t');
            return {
              name: name ?? '',
              size: Number(size ?? 0),
              modifiedAt: Number(modified ?? 0) * 1000,
            };
          })
          .filter((item) => item.name.endsWith('.conf'));
      } catch (error) {
        warnings.push(
          `读取本工具配置目录失败：${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    return {
      serverId,
      candidates,
      injected,
      probe,
      managedFiles,
      warnings,
      root: info.root,
      sudo: info.sudo,
    };
  }

  /** 注入 include；带标记、先备份、二次读取、校验、重载，失败按快照回滚。 */
  async apply(serverId: string, flavor: WebIncludeFlavor) {
    return this.remote.locked(serverId, async () => {
      const status = await this.inspect(serverId);
      const candidate = status.candidates.find((item) => item.flavor === flavor);
      if (!candidate?.supported)
        throw new AppError(candidate?.reason ?? '当前服务器没有可安全注入的 Web 服务。');
      const admin = this.remote.nginxAdmin(serverId);
      const managedDir = managedDirFor(flavor);
      const backupDir = `${managedDir}/backups`;
      await admin.run(
        `mkdir -p -- ${quote(backupDir)} && chmod 755 -- ${quote(managedDir)} ${quote(backupDir)}`,
      );
      const before = await admin.read(candidate.mainConfig);
      const token = newProbeToken();
      const probePath = probePathFor(managedDir);
      const probeContent = probeConfigFor(flavor, token);
      const baseRecord = {
        serverId,
        flavor,
        serviceName: candidate.serviceName,
        mainConfig: candidate.mainConfig,
        managedDir,
        includeDirective: includeDirectiveFor(flavor, managedDir),
      };
      const withProbeVerify = () => {
        const commands = commandsFor(flavor, candidate.serviceName);
        let result!: WebIncludeProbe;
        commands.verify = async () => {
          result = await checkProbe(admin, flavor, token, probePath);
          // Nginx 能稳定 dump 全量配置，探针不生效必须按事务回滚；Apache dump 能力因版本而异。
          if (flavor === 'nginx' && !result.ok)
            throw new AppError('include 探针未在 Nginx 配置中生效，已回滚。');
        };
        return { commands, getResult: () => result };
      };

      if (hasManagedInclude(before, flavor)) {
        const { commands, getResult } = withProbeVerify();
        await withNginxTransaction(
          admin,
          backupDir,
          [{ path: probePath, content: probeContent, mode: '644' }],
          commands,
        );
        const existing = this.store.data.webIncludes[serverId];
        await this.store.saveWebInclude(serverId, {
          ...baseRecord,
          backupPath: existing?.backupPath ?? '',
          injectedAt: existing?.injectedAt ?? Date.now(),
          probe: getResult(),
        });
        return { note: '主配置已包含本工具的 include，探针已写入并校验。', flavor };
      }

      const block = includeBlockFor(flavor, managedDir);
      const next =
        flavor === 'nginx'
          ? insertHttpSnippet(before, block)
          : `${before.replace(/\s*$/, '')}\n\n${block}\n`;
      const mode = await admin.mode(candidate.mainConfig).catch(() => '644');
      const { commands, getResult } = withProbeVerify();
      const { backups } = await withNginxTransaction(
        admin,
        backupDir,
        [
          { path: candidate.mainConfig, content: next, mode },
          { path: probePath, content: probeContent, mode: '644' },
        ],
        commands,
      );
      await this.store.saveWebInclude(serverId, {
        ...baseRecord,
        backupPath: backups[0] ?? '',
        injectedAt: Date.now(),
        probe: getResult(),
      });
      const probeNote = getResult().ok
        ? 'include 探针已生效。'
        : 'include 探针已写入，但未能自动确认生效，请查看注入管理提示。';
      return {
        note: `已将 ${includeDirectiveFor(flavor, managedDir)} 注入 ${candidate.mainConfig}，校验通过并已重载 ${candidate.serviceName}。${probeNote}`,
        flavor,
      };
    });
  }

  /** 撤销注入：只删本工具标记块，托管配置移入备份目录，不碰其他站点。 */
  async remove(serverId: string) {
    return this.remote.locked(serverId, async () => {
      const record = this.store.data.webIncludes[serverId];
      if (!record) return { note: '当前服务器没有本工具的 include 注入记录。' };
      const admin = this.remote.nginxAdmin(serverId);
      const before = await admin.read(record.mainConfig).catch(() => undefined);
      if (before && removeManagedInclude(before) !== before) {
        const mode = await admin.mode(record.mainConfig).catch(() => '644');
        await withNginxTransaction(
          admin,
          `${record.managedDir}/backups`,
          [{ path: record.mainConfig, content: removeManagedInclude(before), mode }],
          commandsFor(record.flavor, record.serviceName),
        );
      }
      await admin
        .run(
          `if test -d ${quote(record.managedDir)}; then mkdir -p -- ${quote(`${record.managedDir}/backups`)}; for f in ${quote(record.managedDir)}/*.conf; do test -f "$f" && mv -- "$f" ${quote(`${record.managedDir}/backups`)}/; done; fi`,
        )
        .catch(() => {});
      await this.store.saveWebInclude(serverId, null);
      return { note: '已解除本工具注入的 include；托管配置（含探针文件）已移入备份目录。' };
    });
  }

  /** Web 规则「保存配置」：写入托管目录的独立 .conf，校验通过后重载。 */
  async saveSiteConfig(
    serverId: string,
    ruleId: string,
    content: string,
    flavor: WebIncludeFlavor,
  ) {
    const record = this.store.data.webIncludes[serverId];
    if (!record) throw new AppError('此服务器尚未注入 include，请先在服务器面板点击「注入」。');
    if (record.flavor !== flavor)
      throw new AppError(
        `服务器注入的是 ${record.flavor === 'nginx' ? 'Nginx' : 'Apache'} 配置，与当前编辑器语法不一致，请切换或重新生成配置。`,
      );
    if (flavor !== 'nginx' && flavor !== 'apache')
      throw new AppError('当前 Web 软件不支持自动保存配置。');
    if (!content.trim()) throw new AppError('配置内容为空，未写入服务器。');
    return this.remote.locked(serverId, async () => {
      const admin = this.remote.nginxAdmin(serverId);
      const backupDir = `${record.managedDir}/backups`;
      const destination = `${record.managedDir}/${siteConfigFileName(ruleId)}`;
      await admin.run(
        `mkdir -p -- ${quote(backupDir)} && chmod 755 -- ${quote(record.managedDir)} ${quote(backupDir)}`,
      );
      await withNginxTransaction(
        admin,
        backupDir,
        [{ path: destination, content, mode: '644' }],
        commandsFor(record.flavor, record.serviceName),
      );
      return { path: destination, note: `配置已写入 ${destination}，校验通过并已重载 Web 服务。` };
    });
  }

  /** 从服务器托管目录读取规则对应的真实配置；文件不存在时返回本地模板供编辑。 */
  async readSiteConfig(serverId: string, ruleId: string) {
    const record = this.store.data.webIncludes[serverId];
    if (!record) throw new AppError('此服务器尚未注入 include，暂无可读取的托管配置。');
    const path = `${record.managedDir}/${siteConfigFileName(ruleId)}`;
    const content = await this.remote
      .nginxAdmin(serverId)
      .read(path)
      .catch(() => undefined);
    return {
      path,
      content: content ?? '',
      exists: typeof content === 'string' && content.trim().length > 0,
      flavor: record.flavor,
    };
  }

  /** 方案 A：把 PEM 证书写到服务器托管目录，并生成 listen 443 ssl 的 server 块。 */
  async installServerCertificate(input: {
    serverId: string;
    ruleId: string;
    certificateId: string;
    domains: string[];
    httpPort: number;
    certPem: string;
    keyPem: string;
    /** 规则生成的站点配置；服务器已有 TLS 配置时只更新证书路径。 */
    siteConfig?: string;
  }) {
    const record = this.store.data.webIncludes[input.serverId];
    if (!record) throw new AppError('此服务器尚未注入 include，无法部署服务器证书。');
    if (record.flavor !== 'nginx')
      throw new AppError('方案 A 的 server 块模板仅支持 Nginx；Apache 请手动适配。');
    return this.remote.locked(input.serverId, async () => {
      const admin = this.remote.nginxAdmin(input.serverId);
      const backupDir = `${record.managedDir}/backups`;
      const certDir = certDirFor(record.managedDir);
      const certPath = `${certDir}/${certFileName(input.certificateId)}`;
      const keyPath = `${certDir}/${keyFileName(input.certificateId)}`;
      const configPath = `${record.managedDir}/${siteConfigFileName(input.ruleId)}`;
      // 防御：上层传入的模板必须是 443 ssl server 块，否则退回内置 TLS 模板，
      // 防止证书已签发却写入 listen 80 的 HTTP 配置导致 HTTPS 不可用。
      const generated = resolveTlsSiteConfig({
        siteConfig: input.siteConfig,
        domains: input.domains,
        certPath,
        keyPath,
        httpPort: input.httpPort,
        certificateId: input.certificateId,
      });
      // 服务器已有 TLS 配置时保留用户改动并补齐缺失的 HTTP server 块；否则写入完整模板。
      const existing = await admin.read(configPath).catch(() => undefined);
      const content = mergeTlsSiteConfig({
        existing,
        generated,
        domains: input.domains,
        certPath,
        keyPath,
        httpPort: input.httpPort,
      });
      await admin.run(
        `mkdir -p -- ${quote(backupDir)} ${quote(certDir)} && chmod 755 -- ${quote(record.managedDir)} ${quote(backupDir)} ${quote(certDir)}`,
      );
      await withNginxTransaction(
        admin,
        backupDir,
        [
          { path: certPath, content: input.certPem, mode: '644' },
          { path: keyPath, content: input.keyPem, mode: '600' },
          { path: configPath, content, mode: '644' },
        ],
        commandsFor(record.flavor, record.serviceName),
      );
      return { certPath, keyPath, configPath };
    });
  }

  /**
   * 删除服务器证书文件；可同时把站点配置恢复成 HTTP 版本，实现移除证书后回退。
   * paths 中的配置文件由 restore 覆盖，不在此处删除。
   */
  async removeServerCertificate(
    serverId: string,
    paths: string[],
    restore?: { path: string; content: string },
  ) {
    const record = this.store.data.webIncludes[serverId];
    if (!record || !paths.length) return;
    return this.remote.locked(serverId, async () => {
      const admin = this.remote.nginxAdmin(serverId);
      const backupDir = `${record.managedDir}/backups`;
      const files = paths.filter((file) => file !== restore?.path);
      const writes = restore ? [{ path: restore.path, content: restore.content, mode: '644' }] : [];
      await admin.run(`mkdir -p -- ${quote(backupDir)}`).catch(() => {});
      if (writes.length)
        await withNginxTransaction(
          admin,
          backupDir,
          writes,
          commandsFor(record.flavor, record.serviceName),
        );
      for (const file of files) await admin.run(`rm -f -- ${quote(file)}`).catch(() => {});
      if (!writes.length)
        await admin
          .run(commandsFor(record.flavor, record.serviceName).reload ?? 'true')
          .catch(() => {});
    });
  }

  /** 方案 A 的 HTTP-01：部署只匹配目标域名的 challenge server 块，避免影响其它站点。 */
  async installHttp01Challenge(serverId: string, domains: string[]) {
    const record = this.store.data.webIncludes[serverId];
    if (!record) throw new AppError('HTTP-01 需要服务器已注入 include。');
    if (record.flavor !== 'nginx') throw new AppError('HTTP-01 自动应答当前仅支持 Nginx。');
    const httpPort = this.store.server(serverId).httpPort;
    return this.remote.locked(serverId, async () => {
      const admin = this.remote.nginxAdmin(serverId);
      const backupDir = `${record.managedDir}/backups`;
      const configPath = `${record.managedDir}/${HTTP01_CONFIG_FILE}`;
      const legacyPath = `${record.managedDir}/${LEGACY_HTTP01_CONFIG_FILE}`;
      const root = HTTP01_ROOT;
      const content = nginxHttp01ServerConfig({ domains, root, httpPort });
      await admin.run(
        `mkdir -p -- ${quote(backupDir)} ${quote(root)}/.well-known/acme-challenge && chmod 755 -- ${quote(record.managedDir)} ${quote(backupDir)} ${quote(root)}`,
      );
      // 升级场景：旧版 challenge 文件若残留会与规则 server 块冲突且无法被 remove 清理。
      await admin.run(`rm -f -- ${quote(legacyPath)}`).catch(() => {});
      await withNginxTransaction(
        admin,
        backupDir,
        [{ path: configPath, content, mode: '644' }],
        commandsFor(record.flavor, record.serviceName),
      );
      return { root, configPath };
    });
  }

  /** HTTP-01：写 token 文件；CA 通过服务器 nginx 的 challenge server 块读取。 */
  async setHttp01Token(serverId: string, root: string, token: string, value: string) {
    const admin = this.remote.nginxAdmin(serverId);
    const safeToken = token.replace(/[^a-zA-Z0-9_-]/g, '');
    if (!safeToken) throw new AppError('HTTP-01 token 无效。');
    const path = `${root.replace(/\/$/, '')}/.well-known/acme-challenge/${safeToken}`;
    await admin.write(path, value, '644');
  }

  async removeHttp01Token(serverId: string, root: string, token: string) {
    const admin = this.remote.nginxAdmin(serverId);
    const safeToken = token.replace(/[^a-zA-Z0-9_-]/g, '');
    const path = `${root.replace(/\/$/, '')}/.well-known/acme-challenge/${safeToken}`;
    await admin.run(`rm -f -- ${quote(path)}`).catch(() => {});
  }

  /** HTTP-01 结束后移除 challenge server 块，避免长期占用域名 80 路径。 */
  async removeHttp01Challenge(serverId: string) {
    const record = this.store.data.webIncludes[serverId];
    if (!record) return;
    return this.remote.locked(serverId, async () => {
      const admin = this.remote.nginxAdmin(serverId);
      const configPath = `${record.managedDir}/${HTTP01_CONFIG_FILE}`;
      const legacyPath = `${record.managedDir}/${LEGACY_HTTP01_CONFIG_FILE}`;
      await admin.run(`rm -f -- ${quote(configPath)} ${quote(legacyPath)}`).catch(() => {});
      await admin
        .run(commandsFor(record.flavor, record.serviceName).reload ?? 'true')
        .catch(() => {});
    });
  }
}
