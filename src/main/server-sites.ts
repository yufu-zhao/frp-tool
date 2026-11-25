import path from 'node:path';
import { AppError } from '../shared/errors';
import type { DeployLevel, SiteInspection } from '../shared/types';
import { quote } from './remote';

export interface NginxSiteRecord {
  id: string;
  name: string;
  domains: string[];
  upstreamPort: number;
  ssl?: { certPath: string; keyPath: string };
  acmeRoot: string;
}

export interface NginxAdmin {
  run(command: string): Promise<string>;
  read(path: string): Promise<string>;
  mode(path: string): Promise<string>;
  write(path: string, content: string, mode?: string): Promise<void>;
}

// ─────────────── 旧站点管理（保留兼容，新证书部署绝不使用） ───────────────
// 下列三个函数会读写 nginx.conf 主配置以插入 include，违背新方案「绝不改主配置」的硬约束。
// 仅保留给旧版 site:create / site:delete 处理器，待主 agent 迁移后移除。

function findNginxHttpBlock(config: string): number {
  let quoteChar = '';
  let comment = false;
  let depth = 0;
  let httpStart = -1;
  for (let index = 0; index < config.length; index += 1) {
    const char = config[index];
    if (comment) {
      if (char === '\n') comment = false;
      continue;
    }
    if (quoteChar) {
      if (char === quoteChar && config[index - 1] !== '\\') quoteChar = '';
      continue;
    }
    if (char === '#') comment = true;
    else if (char === '"' || char === "'") quoteChar = char;
    else if (char === '{') {
      const start = config.lastIndexOf('}', index - 1) + 1;
      const candidate = config.slice(start, index).trim();
      if (depth === 0 && /^http\s*$/.test(candidate)) httpStart = index;
      depth += 1;
    } else if (char === '}') {
      depth -= 1;
      if (depth === 0 && httpStart >= 0) return httpStart;
    }
  }
  throw new AppError(
    '无法在 Nginx 主配置中安全定位完整的 http {} 块，请检查配置或指定正确的主配置文件。',
  );
}

/** 在 http {} 块开头原样插入一段配置文本，不额外包裹 include。 */
export function insertHttpSnippet(config: string, snippet: string): string {
  const httpStart = findNginxHttpBlock(config);
  const indented = snippet
    .split('\n')
    .map((line) => (line.trim() ? `  ${line}` : line))
    .join('\n');
  const rest = config.slice(httpStart + 1).replace(/^\r?\n/, '');
  return `${config.slice(0, httpStart + 1)}\n${indented}\n${rest}`;
}

/** @deprecated 新证书部署禁止使用（会改 nginx.conf 主配置）。 */
export function insertHttpInclude(config: string, includePath: string): string {
  const escaped = includePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (new RegExp(`^\\s*include\\s+${escaped};`, 'm').test(config)) return config;
  return insertHttpSnippet(config, `include ${includePath};`);
}

/** @deprecated 新证书部署禁止使用（会改 nginx.conf 主配置）。 */
export function removeHttpInclude(config: string, includePath: string): string {
  const escaped = includePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return config.replace(new RegExp(`^[\\t ]*include\\s+${escaped};[\\t ]*\\r?\\n?`, 'm'), '');
}

export function renderNginxSite(site: NginxSiteRecord): string {
  const domains = [...new Set(site.domains.map((domain) => domain.toLowerCase()))];
  if (
    !domains.length ||
    domains.some(
      (domain) =>
        !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain),
    )
  )
    throw new AppError('站点域名格式无效。');
  if (!Number.isInteger(site.upstreamPort) || site.upstreamPort < 1 || site.upstreamPort > 65535)
    throw new AppError('FRP HTTP 入口端口无效。');
  const ssl = site.ssl
    ? `\n    listen 443 ssl;\n    ssl_certificate ${site.ssl.certPath};\n    ssl_certificate_key ${site.ssl.keyPath};`
    : '';
  return `# 由穿透工作台管理；修改前请在应用中操作。\nserver {\n    listen 80;${ssl}\n    server_name ${domains.join(' ')};\n\n    location ^~ /.well-known/acme-challenge/ {\n        root ${site.acmeRoot};\n        default_type text/plain;\n    }\n\n    location / {\n        proxy_pass http://127.0.0.1:${site.upstreamPort};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n`;
}

/** @deprecated 旧站点创建入口，会改主配置；新证书部署走 deployCertificate。 */
export async function applyNginxSite(admin: NginxAdmin, mainConfig: string, site: NginxSiteRecord) {
  const managedRoot = `${site.acmeRoot.replace(/\/acme\/http01$/, '')}`;
  const includePath = `${managedRoot}/vhost/nginx/*.conf`;
  const sitePath = `${managedRoot}/vhost/nginx/${site.id}.conf`;
  const siteBackup = `${sitePath}.intranet-backup-${Date.now()}`;
  const base = await admin.read(mainConfig);
  const mainMode = await admin.mode(mainConfig);
  const nginxDump = await admin.run('nginx -T 2>&1');
  const domainPattern = new RegExp(
    `\\bserver_name\\s+[^;]*\\b(?:${site.domains.map((d) => d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\b`,
    'i',
  );
  if (domainPattern.test(nginxDump))
    throw new AppError('Nginx 中已有相同域名配置；为避免覆盖现有站点，已停止操作。');
  const nextMain = insertHttpInclude(base, includePath);
  const nextSite = renderNginxSite(site);
  const managedBackupDir = `${managedRoot}/backups`;
  const managedMainBackup = `${managedBackupDir}/nginx-main-${Date.now()}.conf`;
  const backupCommand = `mkdir -p -- ${quote(managedBackupDir)} && cp -p -- ${quote(mainConfig)} ${quote(managedMainBackup)} && if test -e ${quote(sitePath)}; then cp -p -- ${quote(sitePath)} ${quote(siteBackup)}; fi`;
  await admin.run(backupCommand);
  let wroteMain = false;
  let wroteSite = false;
  try {
    if ((await admin.read(mainConfig)) !== base)
      throw new AppError('Nginx 主配置在操作期间发生变化，请重试以避免覆盖外部修改。');
    wroteMain = true;
    await admin.write(mainConfig, nextMain, mainMode);
    wroteSite = true;
    await admin.write(sitePath, nextSite, '644');
    await admin.run('nginx -t');
    await admin.run('nginx -s reload');
    return {
      configPath: sitePath,
      mainBackup: managedMainBackup,
      siteBackup,
      includeCreatedByApp: nextMain !== base,
    };
  } catch (error) {
    if (wroteMain || wroteSite)
      await admin
        .run(
          `if test ${wroteMain ? '1' : '0'} -eq 1; then cp -p -- ${quote(managedMainBackup)} ${quote(mainConfig)}; fi; if test -e ${quote(siteBackup)}; then cp -p -- ${quote(siteBackup)} ${quote(sitePath)}; elif test ${wroteSite ? '1' : '0'} -eq 1; then rm -f -- ${quote(sitePath)}; fi; nginx -t && nginx -s reload`,
        )
        .catch(() => {});
    throw new AppError(
      `Nginx 配置未能应用，已尝试回滚：${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

// ─────────────── 新证书部署：安全事务框架 + L0/L1/L2 分级 ───────────────
// 硬约束：
//   · 绝不改 nginx.conf 主配置（本文件不接收 mainConfig 参数）。
//   · 绝不 stop/restart，只 nginx -t → nginx -s reload。
//   · 绝不碰已有 server 块的 location（L1 只覆盖证书文件，L2 只写新独立 conf）。
//   · 所有写入：备份 → 二次读取校验 → 写入 → nginx -t → reload → 失败按快照回滚。

export interface TransactionFile {
  path: string;
  content: string;
  mode?: string;
}

interface Snapshot extends TransactionFile {
  before?: string;
  beforeMode: string;
  backup?: string;
  existed: boolean;
  wrote: boolean;
}

export interface NginxTransactionResult {
  backups: string[];
}

export interface WebServiceTransactionCommands {
  validate?: string;
  reload?: string;
  /** 写入并 reload 后执行；失败同样按快照回滚。 */
  verify?: () => Promise<void>;
}

/**
 * 复用 applyNginxSite 的备份/二次读取/nginx -t/回滚框架，但完全不触碰主配置。
 * 只操作显式传入的文件（证书文件或新 conf），任何一步失败都按快照还原并重载。
 * 默认命令是 nginx；Web 服务注入会传入 apache 的校验与重载命令。
 */
export async function withNginxTransaction(
  admin: NginxAdmin,
  backupDir: string,
  files: TransactionFile[],
  commands: WebServiceTransactionCommands = {},
): Promise<NginxTransactionResult> {
  const validate = commands.validate ?? 'nginx -t';
  const reload = commands.reload ?? 'nginx -s reload';
  if (!files.length) return { backups: [] };
  const snapshots: Snapshot[] = await Promise.all(
    files.map(async (file) => {
      const before = await admin.read(file.path).catch(() => undefined);
      const beforeMode = await admin.mode(file.path).catch(() => '600');
      return {
        ...file,
        before,
        beforeMode,
        existed: before !== undefined,
        wrote: false,
      };
    }),
  );
  const stamp = Date.now();
  const backups: string[] = [];
  const backupCommands = [`mkdir -p -- ${quote(backupDir)}`];
  snapshots.forEach((snapshot, index) => {
    if (!snapshot.existed) return;
    const backup = `${backupDir}/${index}-${path.posix.basename(snapshot.path)}.intranet-backup-${stamp}`;
    snapshot.backup = backup;
    backups.push(backup);
    backupCommands.push(`cp -p -- ${quote(snapshot.path)} ${quote(backup)}`);
  });
  await admin.run(backupCommands.join(' && '));

  const rollback = async () => {
    for (const snapshot of snapshots) {
      if (!snapshot.wrote) continue;
      if (snapshot.existed)
        await admin.write(snapshot.path, snapshot.before!, snapshot.beforeMode).catch(() => {});
      else await admin.run(`rm -f -- ${quote(snapshot.path)}`).catch(() => {});
    }
    await admin.run(`${validate} && ${reload}`).catch(() => {});
  };

  try {
    // 二次读取校验，防止覆盖操作期间的外部修改。
    for (const snapshot of snapshots) {
      const current = await admin.read(snapshot.path).catch(() => undefined);
      if (current !== snapshot.before)
        throw new AppError('Nginx 相关文件在操作期间发生变化，请重试以避免覆盖外部修改。');
    }
    for (const snapshot of snapshots) {
      await admin.write(snapshot.path, snapshot.content, snapshot.mode ?? snapshot.beforeMode);
      snapshot.wrote = true;
    }
    await admin.run(validate);
    await admin.run(reload);
    if (commands.verify) await commands.verify();
    return { backups };
  } catch (error) {
    await rollback();
    throw new AppError(
      `Nginx 部署未能应用，已按快照回滚：${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export interface CertificateDeployOptions {
  level: DeployLevel;
  certificateId: string;
  domains: string[];
  // 服务端证书独立目录中的源路径（L0/L2 片段与 conf 直接引用）。
  certPath: string;
  keyPath: string;
  certPem: string;
  keyPem: string;
  // frps 高端口（L2 location / 反代目标），绝不为 80/443。
  upstreamPort: number;
  inspection: SiteInspection;
  // 服务端备份目录（如 ~/.local/share/intranet-frp/certs/<id>/backups）。
  backupDir: string;
  // L2 写入新 server 块前必须二次确认。
  confirmed: boolean;
}

export interface CertificateDeployResult {
  level: DeployLevel;
  deployTarget?: string;
  configSnippet: string;
  backups: string[];
  note: string;
}

function assertHighPort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 80 || port === 443)
    throw new AppError('FRP 的 HTTP/HTTPS 入口端口必须是非 80/443 的高端口。');
}

function renderProxyLocations(upstreamPort: number): string {
  assertHighPort(upstreamPort);
  return `    location / {\n        proxy_pass http://127.0.0.1:${upstreamPort};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n`;
}

/** 可复制的 nginx 配置片段（L0 主产物，L1/L2 也给出参考）。 */
export function renderDeploySnippet(options: CertificateDeployOptions): string {
  const domains = [...new Set(options.domains.map((domain) => domain.toLowerCase()))].join(' ');
  return [
    `# 由穿透工作台生成；证书位于服务端独立目录，TLS 在此终止后反代到 frps 高端口 ${options.upstreamPort}。`,
    '# 请确认 nginx 主进程对下列证书目录有读取权限（目录 700 / 文件 600）。',
    'server {',
    '    listen 443 ssl;',
    `    server_name ${domains};`,
    `    ssl_certificate ${options.certPath};`,
    `    ssl_certificate_key ${options.keyPath};`,
    renderProxyLocations(options.upstreamPort).trimEnd(),
    '}',
    '',
  ].join('\n');
}

/** L2：往「已有 include 目录」写的独立 server conf；不碰任何已有 server 块。 */
export function renderL2Conf(options: CertificateDeployOptions): string {
  const domains = [...new Set(options.domains.map((domain) => domain.toLowerCase()))].join(' ');
  return [
    '# 由穿透工作台管理（L2）；删除前请在应用中操作，勿手改已有站点。',
    `server {\n    listen 443 ssl;\n    server_name ${domains};`,
    `    ssl_certificate ${options.certPath};`,
    `    ssl_certificate_key ${options.keyPath};`,
    renderProxyLocations(options.upstreamPort).trimEnd(),
    '}',
    '',
  ].join('\n');
}

/**
 * 部署分级：
 *  L0 只落盘 + 给可复制片段（零改动）；
 *  L1 备份后同路径覆盖已有 ssl_certificate/key（nginx 配置零改动，仅 -t → reload）；
 *  L2 在已有 include 目录写独立 conf（需二次确认）。
 */
export async function deployCertificate(
  admin: NginxAdmin,
  options: CertificateDeployOptions,
): Promise<CertificateDeployResult> {
  const snippet = renderDeploySnippet(options);
  if (options.level === 'L0')
    return {
      level: 'L0',
      configSnippet: snippet,
      backups: [],
      note: 'L0：证书已落盘服务端独立目录，未改动任何 Nginx 配置。请复制上方片段自行配置 TLS 持有者。',
    };

  if (options.level === 'L2' && !options.confirmed)
    throw new AppError('L2 会在 Nginx include 目录写入新 server 块，请二次确认后再执行。');

  if (options.level === 'L1') {
    const fileMap = new Map<string, string>();
    for (const info of options.inspection.domains) {
      if (info.sharedCert)
        throw new AppError(
          `域名 ${info.domain} 的证书被多站点共用，L1 覆盖会影响其他站点，请改用 L2 或 L0。`,
        );
      if (info.certPath && info.keyPath) {
        fileMap.set(info.certPath, options.certPem);
        fileMap.set(info.keyPath, options.keyPem);
      }
    }
    if (!fileMap.size)
      throw new AppError('L1 需要站点已有独立的 ssl_certificate/ssl_certificate_key 路径。');
    const files: TransactionFile[] = [...fileMap].map(([filePath, content]) => ({
      path: filePath,
      content,
    }));
    const { backups } = await withNginxTransaction(admin, options.backupDir, files);
    return {
      level: 'L1',
      deployTarget: [...fileMap.keys()].join(', '),
      configSnippet: snippet,
      backups,
      note: 'L1：已备份并同路径覆盖现有证书/私钥文件，Nginx 配置零改动，仅 nginx -t → reload。',
    };
  }

  // L2
  const includeDir = options.inspection.nginx.includeDir;
  if (!includeDir)
    throw new AppError('L2 需要 Nginx 已有且可写的 include 目录；当前探测未找到，请改用 L0/L1。');
  const confPath = `${includeDir}/${options.certificateId}.conf`;
  const files: TransactionFile[] = [
    { path: confPath, content: renderL2Conf(options), mode: '644' },
  ];
  const { backups } = await withNginxTransaction(admin, options.backupDir, files);
  return {
    level: 'L2',
    deployTarget: confPath,
    configSnippet: snippet,
    backups,
    note: `L2：已在已有 include 目录写入独立 conf（${confPath}），未改主配置、未碰已有 server 块。`,
  };
}
