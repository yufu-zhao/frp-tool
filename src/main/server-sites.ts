import { AppError } from '../shared/errors';
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

// 识别不在注释或引号中的 http 块，避免把 include 错加进 server/location。
export function insertHttpInclude(config: string, includePath: string): string {
  const escaped = includePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (new RegExp(`^\\s*include\\s+${escaped};`, 'm').test(config)) return config;
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
      if (depth === 0 && httpStart >= 0) {
        return `${config.slice(0, httpStart + 1)}\n  include ${includePath};${config.slice(httpStart + 1)}`;
      }
    }
  }
  throw new AppError(
    '无法在 Nginx 主配置中安全定位完整的 http {} 块，请检查配置或指定正确的主配置文件。',
  );
}

// 最后一个托管站点移除时，只移除本工具精确添加的 include 行。
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

// Nginx 主配置和站点文件均保留回滚点，测试及重载任一失败即恢复。
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
