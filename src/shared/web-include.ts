import type { WebIncludeFlavor } from './types';

// 本工具在服务器上创建的站点配置都放在这里；目录 755、文件 644，便于 Web 服务读取。
export const WEB_INCLUDE_ROOT = '/etc/intranet-frp/sites';
export const WEB_INCLUDE_MARKER_BEGIN = '# >>> intranet-frp web include (managed) >>>';
export const WEB_INCLUDE_MARKER_END = '# <<< intranet-frp web include (managed) <<<';
export const WEB_INCLUDE_PROBE_FILE = 'default.conf';

export const managedDirFor = (flavor: WebIncludeFlavor): string => `${WEB_INCLUDE_ROOT}/${flavor}`;
export const probePathFor = (managedDir: string): string =>
  `${managedDir}/${WEB_INCLUDE_PROBE_FILE}`;

/** 注入成功后写入托管目录的哨兵文件；只含注释，不占用端口、不抢 default_server。 */
export function probeConfigFor(flavor: WebIncludeFlavor, token: string): string {
  return [
    `# intranet-frp include probe ${token}`,
    '# 此文件由穿透工作台创建，用于确认 include 已生效；解除注入时会一并移除。',
    flavor === 'nginx'
      ? '# 位于 http {} 上下文，只含注释。'
      : '# 位于 Apache 主配置上下文，只含注释。',
    '',
  ].join('\n');
}

/** 用配置 dump 中是否出现哨兵标记来判断 include 是否真的被加载。 */
export function probeDumpCommand(flavor: WebIncludeFlavor): string {
  return flavor === 'nginx'
    ? 'nginx -T 2>&1'
    : 'if command -v apachectl >/dev/null 2>&1; then apachectl -t -D DUMP_CONFIG 2>&1 || true; elif command -v httpd >/dev/null 2>&1; then httpd -t -D DUMP_CONFIG 2>&1 || true; fi';
}

export function includeDirectiveFor(flavor: WebIncludeFlavor, managedDir = managedDirFor(flavor)) {
  const path = `${managedDir}/*.conf`;
  return flavor === 'nginx' ? `include ${path};` : `IncludeOptional ${path}`;
}

export function includeBlockFor(flavor: WebIncludeFlavor, managedDir = managedDirFor(flavor)) {
  return [
    WEB_INCLUDE_MARKER_BEGIN,
    includeDirectiveFor(flavor, managedDir),
    WEB_INCLUDE_MARKER_END,
  ].join('\n');
}

// 方案 A：证书与私钥落在服务器托管目录，server 块引用这里的文件。
export const WEB_INCLUDE_CERT_DIR = 'certs';
export const certDirFor = (managedDir: string): string => `${managedDir}/${WEB_INCLUDE_CERT_DIR}`;
export const certFileName = (certificateId: string): string =>
  `${certificateId.replace(/[^a-zA-Z0-9_-]/g, '')}.crt`;
export const keyFileName = (certificateId: string): string =>
  `${certificateId.replace(/[^a-zA-Z0-9_-]/g, '')}.key`;

/** 方案 A 的 Nginx server 块：443 终止 TLS，明文回源到 frps 的 vhostHTTPPort。 */
/** HTTP server 块：方案 A 有证书时仍保留明文访问，与 443 ssl 块共存。 */
export function nginxHttpServerBlock(input: { domains: string[]; httpPort: number }): string {
  const names = input.domains.join(' ');
  return [
    '# HTTP：与 HTTPS 共存，保留明文访问',
    'server {',
    '    listen 80;',
    `    server_name ${names};`,
    '    location / {',
    `        proxy_pass http://127.0.0.1:${input.httpPort};`,
    '        proxy_set_header Host $host;',
    '        proxy_set_header X-Real-IP $remote_addr;',
    '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
    '        proxy_set_header X-Forwarded-Proto $scheme;',
    '    }',
    '}',
  ].join('\n');
}

/**
 * 方案 A 完整站点模板：一个站点规则对应一个配置文件，HTTP(80) 与 HTTPS(443) 两个 server 块共存。
 */
export function nginxTlsServerConfig(input: {
  domains: string[];
  certPath: string;
  keyPath: string;
  httpPort: number;
  certificateId: string;
}): string {
  return [
    '# >>> intranet-frp tls server (managed) >>>',
    `# 证书：${input.certificateId}`,
    nginxHttpServerBlock({ domains: input.domains, httpPort: input.httpPort }),
    '',
    '# HTTPS：TLS 由服务器 nginx 终止',
    'server {',
    '    listen 443 ssl;',
    '    http2 on;',
    `    server_name ${input.domains.join(' ')};`,
    `    ssl_certificate ${input.certPath};`,
    `    ssl_certificate_key ${input.keyPath};`,
    '    ssl_session_cache shared:intranet-frp:10m;',
    '    ssl_session_timeout 10m;',
    '    location / {',
    `        proxy_pass http://127.0.0.1:${input.httpPort};`,
    '        proxy_set_header Host $host;',
    '        proxy_set_header X-Real-IP $remote_addr;',
    '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
    '        proxy_set_header X-Forwarded-Proto $scheme;',
    '    }',
    '}',
    '# <<< intranet-frp tls server (managed) <<<',
    '',
  ].join('\n');
}

/**
 * 方案 A 已有站点配置时的合并：保留用户 443 ssl 块的自定义内容与证书路径替换；
 * 若缺 HTTP server 块则补齐，避免历史配置（只有 443）导致 HTTP 访问失效。
 * 没有 443 ssl 块时视为普通 HTTP 配置，直接用完整模板覆盖。
 */
export function mergeTlsSiteConfig(input: {
  existing?: string;
  generated: string;
  domains: string[];
  certPath: string;
  keyPath: string;
  httpPort: number;
}): string {
  const existing = input.existing?.trim();
  if (!existing || !/listen\s+443\s+ssl/.test(existing)) return input.generated;
  let merged = existing
    .replace(/^\s*ssl_certificate\s+[^;]+;/gm, `    ssl_certificate ${input.certPath};`)
    .replace(/^\s*ssl_certificate_key\s+[^;]+;/gm, `    ssl_certificate_key ${input.keyPath};`);
  if (!/\blisten\s+80\s*;/.test(merged)) {
    merged = `${merged}\n\n${nginxHttpServerBlock({ domains: input.domains, httpPort: input.httpPort })}`;
  }
  return merged;
}

/**
 * 方案 A 部署时选择最终写入的站点配置。
 * 只有包含 `listen 443 ssl` 的模板才是有效的 TLS server 块；HTTP 模板一律退回内置 TLS 模板，
 * 避免误写 listen 80 导致证书已签发但 HTTPS 仍不可访问。
 */
export function resolveTlsSiteConfig(input: {
  siteConfig?: string;
  domains: string[];
  certPath: string;
  keyPath: string;
  httpPort: number;
  certificateId: string;
}): string {
  const candidate = input.siteConfig?.trim();
  return candidate && /listen\s+443\s+ssl/.test(candidate)
    ? candidate
    : nginxTlsServerConfig({
        domains: input.domains,
        certPath: input.certPath,
        keyPath: input.keyPath,
        httpPort: input.httpPort,
        certificateId: input.certificateId,
      });
}

// challenge 配置文件名必须以 '000-' 开头：nginx 对相同 server_name 取先定义的 server 块，
// include 用 *.conf 按文件名序加载，规则配置名是 UUID（首位 0-9a-f，均 < h），
// 若沿用 http01.conf 则规则块先加载、challenge 请求落到 proxy_pass，CA 拿到 404。
// '000-' 的第 4 个字符是 '-'（ASCII 45），小于任何 hex 字符，确保 challenge 块最先定义。
export const HTTP01_CONFIG_FILE = '000-http01.conf';

/**
 * 方案 A 的 HTTP-01 验证 server 块。
 * 必须排在同域名站点 server 块之前（见 HTTP01_CONFIG_FILE），因此这里同时保留 location /
 * 回源 frps，确保验证期间该域名的正常 HTTP 访问不受影响。
 */
export function nginxHttp01ServerConfig(input: {
  domains: string[];
  root: string;
  httpPort: number;
}): string {
  return [
    '# >>> intranet-frp http-01 challenge (managed) >>>',
    'server {',
    '    listen 80;',
    `    server_name ${input.domains.join(' ')};`,
    '    location = /.well-known/acme-challenge/ { return 404; }',
    `    location /.well-known/acme-challenge/ { root ${input.root}; }`,
    '    location / {',
    `        proxy_pass http://127.0.0.1:${input.httpPort};`,
    '        proxy_set_header Host $host;',
    '        proxy_set_header X-Real-IP $remote_addr;',
    '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
    '        proxy_set_header X-Forwarded-Proto $scheme;',
    '    }',
    '}',
    '# <<< intranet-frp http-01 challenge (managed) <<<',
    '',
  ].join('\n');
}

export const HTTP01_ROOT = '/etc/intranet-frp/acme';
export const HTTP01_BEGIN = '# >>> intranet-frp http-01 challenge (managed) >>>';
export const HTTP01_END = '# <<< intranet-frp http-01 challenge (managed) <<<';
export const http01Marker = { begin: HTTP01_BEGIN, end: HTTP01_END };

/** 规则 ID 已由 schema 限制为安全字符，这里再做一次收紧，避免意外路径分隔。 */
export function siteConfigFileName(ruleId: string): string {
  const safe = ruleId.replace(/[^a-zA-Z0-9_-]/g, '');
  if (!safe) throw new Error('规则 ID 无效，无法生成服务端配置文件名。');
  if (safe === 'default') throw new Error('default.conf 是注入探针保留文件，规则不能占用。');
  return `${safe}.conf`;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** 标记块或同名 include 已存在时都不再重复注入。 */
export function hasManagedInclude(config: string, flavor: WebIncludeFlavor): boolean {
  return (
    config.includes(WEB_INCLUDE_MARKER_BEGIN) ||
    new RegExp(`^\\s*${escapeRegExp(includeDirectiveFor(flavor))}\\s*$`, 'm').test(config)
  );
}

/** 删除本工具写入的标记块；没有标记时原样返回，绝不碰其他配置。 */
export function removeManagedInclude(config: string): string {
  const begin = escapeRegExp(WEB_INCLUDE_MARKER_BEGIN);
  const end = escapeRegExp(WEB_INCLUDE_MARKER_END);
  return config
    .replace(
      new RegExp(
        `^[^\\S\\n]*${begin}[^\\S\\n]*\\r?\\n[\\s\\S]*?^[^\\S\\n]*${end}[^\\S\\n]*\\r?\\n?`,
        'gm',
      ),
      '',
    )
    .replace(
      new RegExp(
        `^[^\\S\\n]*${begin}[^\\S\\n]*\\r?\\n[\\s\\S]*?^[^\\S\\n]*${end}[^\\S\\n]*$`,
        'gm',
      ),
      '',
    );
}
