import type { ProxyRule, Server } from './types';

// 仅生成访问地址，不将 Node 或配置解析器打包到界面。
export function accessAddress(rule: ProxyRule, server: Server): string {
  if (rule.type === 'http' || rule.type === 'https') {
    const p = rule.type === 'http' ? server.httpPort : server.httpsPort;
    const domain = rule.domains[0] ?? '';
    return `${rule.type}://${domain}${p === (rule.type === 'http' ? 80 : 443) ? '' : `:${p}`}`;
  }
  const host = server.publicHost.includes(':') ? `[${server.publicHost}]` : server.publicHost;
  return `${host}:${rule.remotePort}`;
}
