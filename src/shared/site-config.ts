import type { HostInfo, ProxyRule, Server } from './types';
import { certDirFor, certFileName, keyFileName, managedDirFor } from './web-include';

export type SiteConfigFlavor = 'nginx' | 'apache' | 'caddy' | 'lighttpd' | 'unknown';

export interface SiteFlavorDetection {
  flavor: SiteConfigFlavor;
  serviceName?: string;
  detected: boolean;
}

export interface SiteConfigInput {
  rule: ProxyRule;
  server?: Server;
  hostInfo?: HostInfo;
  /** 方案 A（服务器终止 TLS）生成 server ssl 模板；方案 B 生成 stream 透传模板。 */
  tlsMode?: 'server' | 'local';
  /** 方案 A 已部署证书的 ID；传入后模板直接引用真实证书路径，而非占位符。 */
  certificateId?: string;
}

export interface GeneratedSiteConfig {
  flavor: SiteConfigFlavor;
  serviceName?: string;
  content: string;
  warnings: string[];
}

const SERVICE_FLAVORS: Record<string, SiteConfigFlavor> = {
  nginx: 'nginx',
  openresty: 'nginx',
  apache2: 'apache',
  httpd: 'apache',
  caddy: 'caddy',
  lighttpd: 'lighttpd',
};

export const siteFlavorLabel = (flavor: SiteConfigFlavor): string =>
  ({
    nginx: 'Nginx',
    apache: 'Apache',
    caddy: 'Caddy',
    lighttpd: 'Lighttpd',
    unknown: '通用配置',
  })[flavor];

/** 按服务器探测结果选择配置语法；运行中的服务优先于仅安装的服务。 */
export function detectSiteFlavor(hostInfo?: HostInfo): SiteFlavorDetection {
  const services = (hostInfo?.webServices ?? []).filter((item) => item.installed || item.running);
  const preferred =
    services.find((item) => item.running && SERVICE_FLAVORS[item.name]) ??
    services.find((item) => SERVICE_FLAVORS[item.name]);
  if (!preferred) return { flavor: 'unknown', detected: false };
  return {
    flavor: SERVICE_FLAVORS[preferred.name] ?? 'unknown',
    serviceName: preferred.name,
    detected: true,
  };
}

function normalizedDomains(rule: ProxyRule): string[] {
  return [...new Set(rule.domains.map((domain) => domain.trim().toLowerCase()).filter(Boolean))];
}

function slug(domains: string[]): string {
  return (
    (domains[0] ?? 'frp-site').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'frp-site'
  );
}

function upstreamPort(input: SiteConfigInput): number {
  return input.rule.type === 'https'
    ? (input.server?.httpsPort ?? 8443)
    : (input.server?.httpPort ?? 8080);
}

function headers(): string {
  return [
    '    proxy_set_header Host $host;',
    '    proxy_set_header X-Real-IP $remote_addr;',
    '    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
    '    proxy_set_header X-Forwarded-Proto $scheme;',
  ].join('\n');
}

function nginxConfig(input: SiteConfigInput, domains: string[], port: number): string {
  const secure = input.rule.type === 'https' || !!input.rule.publicHttps;
  const name = domains.join(' ') || 'example.com';
  const header = [
    '# 由穿透工作台生成 · Nginx 站点反代模板',
    `# 规则：${input.rule.name} | 本地：${input.rule.localIP}:${input.rule.localPort}`,
    `# 目标：frps vhost ${port}；请按实际端口映射调整。`,
    '# 可通过规则「配置文件」页保存到服务器托管目录并校验生效。',
    '',
  ].join('\n');
  if (secure && input.tlsMode === 'server') {
    const certDir = certDirFor(managedDirFor('nginx'));
    const certPath = input.certificateId
      ? `${certDir}/${certFileName(input.certificateId)}`
      : `${certDir}/<证书ID>.crt`;
    const keyPath = input.certificateId
      ? `${certDir}/${keyFileName(input.certificateId)}`
      : `${certDir}/<证书ID>.key`;
    // 一个站点规则对应一个配置文件：HTTP(80) 保留明文访问，HTTPS(443) 由服务器 nginx 终止 TLS。
    return `${header}# 方案 A：TLS 由服务器 nginx 终止，证书由工具部署到托管目录。
# HTTP 与 HTTPS 两个 server 块共存；请放到 http { ... } 上下文。
server {
    listen 80;
    server_name ${name};

    location / {
        proxy_pass http://127.0.0.1:${port};
${headers()}
    }
}

server {
    listen 443 ssl;
    http2 on;
    server_name ${name};

    ssl_certificate ${certPath};
    ssl_certificate_key ${keyPath};

    location / {
        proxy_pass http://127.0.0.1:${port};
${headers()}
    }
}
`;
  }
  if (secure) {
    return `${header}# 方案 B：HTTPS 规则由本机 frpc 终止 TLS，需在 nginx 的 stream 上下文代理 443。
# 请将本段放入 stream { ... }，不要放进 http 块。
stream {
    server {
        listen 443;
        proxy_pass 127.0.0.1:${port};
    }
}

# 如需由 nginx 终止证书，请改用 server { listen 443 ssl; ... } 并配置证书路径。
`;
  }
  return `${header}server {
    listen 80;
    server_name ${name};

    location / {
        proxy_pass http://127.0.0.1:${port};
${headers()}
    }
}
`;
}

function apacheConfig(input: SiteConfigInput, domains: string[], port: number): string {
  const primary = domains[0] ?? 'example.com';
  const aliases = domains.slice(1).join(' ');
  const site = slug(domains);
  const scheme = input.rule.type === 'https' ? 'https' : 'http';
  return `# 由穿透工作台生成 · Apache 站点反代模板
# 规则：${input.rule.name} | 本地：${input.rule.localIP}:${input.rule.localPort}
# 目标：frps vhost ${port}；启用前请确认已加载 proxy_http、headers、ssl 模块。
# 仅保存在规则数据中，不会自动写入服务器或重载 Web 服务。

<VirtualHost *:${input.rule.type === 'https' ? 443 : 80}>
    ServerName ${primary}
${aliases ? `    ServerAlias ${aliases}\n` : ''}
    ProxyPreserveHost On
    ProxyPass / ${scheme}://127.0.0.1:${port}/
    ProxyPassReverse / ${scheme}://127.0.0.1:${port}/
    RequestHeader set X-Real-IP %{REMOTE_ADDR}e
    RequestHeader set X-Forwarded-Proto %{REQUEST_SCHEME}e
${input.rule.type === 'https' ? '    SSLProxyEngine On\n    SSLProxyVerify none\n' : ''}
    ErrorLog \${APACHE_LOG_DIR}/${site}-error.log
    CustomLog \${APACHE_LOG_DIR}/${site}-access.log combined
</VirtualHost>
`;
}

function caddyConfig(input: SiteConfigInput, domains: string[], port: number): string {
  const name = domains.join(', ') || 'example.com';
  const secure = input.rule.type === 'https';
  const upstream = `${secure ? 'https' : 'http'}://127.0.0.1:${port}`;
  return `# 由穿透工作台生成 · Caddy v2 站点反代模板
# 规则：${input.rule.name} | 本地：${input.rule.localIP}:${input.rule.localPort}
# 目标：frps vhost ${port}；仅保存在规则数据中，不会自动写入服务器。

${name} {
    reverse_proxy ${upstream} {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
${secure ? '        transport http {\n            tls_insecure_skip_verify\n        }\n' : ''}    }
}
`;
}

function lighttpdConfig(input: SiteConfigInput, domains: string[], port: number): string {
  const pattern = domains.join('|') || 'example.com';
  return `# 由穿透工作台生成 · Lighttpd 站点反代模板
# 规则：${input.rule.name} | 本地：${input.rule.localIP}:${input.rule.localPort}
# 目标：frps vhost ${port}；启用前请确认已加载 mod_proxy。
# 仅保存在规则数据中，不会自动写入服务器。

\$HTTP["host"] =~ "^(${pattern})\$" {
    proxy.server = ( "" => (( "host" => "127.0.0.1", "port" => ${port} )) )
    proxy.forwarded = ( "for" => 1, "proto" => 1, "host" => 1 )
}
`;
}

/** 根据规则、frps 端口和服务器探测到的 Web 软件生成可编辑配置模板。 */
export function generateSiteConfig(input: SiteConfigInput): GeneratedSiteConfig {
  const detection = detectSiteFlavor(input.hostInfo);
  const flavor = detection.flavor === 'unknown' ? 'unknown' : detection.flavor;
  const domains = normalizedDomains(input.rule);
  const port = upstreamPort(input);
  const warnings: string[] = [];
  if (!detection.detected)
    warnings.push('未探测到服务器上的常见 Web 服务，已按 Nginx 语法生成，可手动修改后复制。');
  if (!domains.length) warnings.push('规则尚未填写公网域名，模板使用 example.com 占位。');
  if (port === 80 || port === 443)
    warnings.push(
      '当前 frps vhost 端口为 80/443，站点反代通常不需要；如由 Web 软件持有 80/443，请把 frps 端口改为高端口。',
    );
  if ((input.rule.type === 'https' || input.rule.publicHttps) && input.tlsMode === 'server')
    warnings.push('此模板由服务器 nginx 终止 TLS；证书需先通过「申请证书」部署到服务器。');

  const content =
    flavor === 'apache'
      ? apacheConfig(input, domains, port)
      : flavor === 'caddy'
        ? caddyConfig(input, domains, port)
        : flavor === 'lighttpd'
          ? lighttpdConfig(input, domains, port)
          : nginxConfig(input, domains, port);

  return {
    flavor,
    serviceName: detection.serviceName,
    content,
    warnings,
  };
}
