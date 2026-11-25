import type { ProxyRule, Server } from './types';

// 仅生成访问地址，不将 Node 或配置解析器打包到界面。
export function accessAddress(rule: ProxyRule, server: Server): string {
  if (rule.type === 'http' || rule.type === 'https') {
    const domain = rule.domains[0] ?? '';
    // 方案 A：HTTP 规则仅用于回源，公网入口是服务器 nginx 的 443。
    if (rule.type === 'http' && rule.publicHttps) return `https://${domain}`;
    const port = rule.type === 'http' ? server.httpPort : server.httpsPort;
    return `${rule.type}://${domain}${port === (rule.type === 'http' ? 80 : 443) ? '' : `:${port}`}`;
  }
  const host = server.publicHost.includes(':') ? `[${server.publicHost}]` : server.publicHost;
  return `${host}:${rule.remotePort}`;
}
