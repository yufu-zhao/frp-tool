import TOML from '@iarna/toml';
import type { Instance, Server, ProxyRule } from '../shared/types';
import { AppError } from '../shared/errors';

export const frpAdapter = {
  name: 'frp',
  supportsForm(version: string) {
    const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version);
    return !!match && (Number(match[1]) > 0 || Number(match[2]) >= 52);
  },
  binary(role: 'client' | 'server', platform: string) {
    return `${role === 'client' ? 'frpc' : 'frps'}${platform === 'windows' ? '.exe' : ''}`;
  },
};

export function validateRules(rules: ProxyRule[]) {
  const names = new Set<string>();
  const ports = new Set<string>();
  for (const rule of rules) {
    if (names.has(rule.name)) throw new AppError(`代理名称重复：${rule.name}`);
    names.add(rule.name);
    if (rule.type === 'tcp' || rule.type === 'udp') {
      if (!rule.remotePort) throw new AppError(`${rule.name} 缺少公网端口。`);
      const key = `${rule.type}:${rule.remotePort}`;
      if (ports.has(key)) throw new AppError(`公网端口重复：${key}`);
      ports.add(key);
    } else if (!rule.domain || /[\s/:]/.test(rule.domain))
      throw new AppError(`${rule.name} 请填写不含协议和端口的域名。`);
    if (rule.type === 'https' && rule.tlsMode === 'terminate' && (!rule.certPath || !rule.keyPath))
      throw new AppError(`${rule.name} HTTPS 转换需要证书及私钥路径。`);
  }
}
export function clientConfig(instance: Instance, server: Server, token: string): string {
  validateRules(instance.proxies);
  if (!instance.proxies.length) throw new AppError('请至少添加一个代理规则。');
  const config = {
    serverAddr: server.publicHost,
    serverPort: server.frpPort,
    auth: { method: 'token', token },
    loginFailExit: false,
    log: { to: 'console', level: 'info', disablePrintColor: true },
    proxies: instance.proxies.map((rule) => {
      const common = { name: `${instance.id}_${rule.name}`, type: rule.type };
      if (rule.type === 'https' && rule.tlsMode === 'terminate')
        return {
          ...common,
          customDomains: [rule.domain],
          plugin: {
            type: 'https2http',
            localAddr: `${rule.localIP.includes(':') ? `[${rule.localIP}]` : rule.localIP}:${rule.localPort}`,
            crtPath: rule.certPath,
            keyPath: rule.keyPath,
          },
        };
      return {
        ...common,
        localIP: rule.localIP,
        localPort: rule.localPort,
        ...(rule.type === 'tcp' || rule.type === 'udp'
          ? { remotePort: rule.remotePort }
          : { customDomains: [rule.domain] }),
      };
    }),
  };
  return TOML.stringify(config as TOML.JsonMap);
}
export function serverConfig(server: Server, token: string): string {
  if (!token) throw new AppError('服务端需要认证令牌，请先在服务器配置中填写。');
  if (new Set([server.frpPort, server.httpPort, server.httpsPort]).size !== 3)
    throw new AppError('FRP 连接、HTTP、HTTPS 入口端口不能重复。');
  return TOML.stringify({
    bindPort: server.frpPort,
    vhostHTTPPort: server.httpPort,
    vhostHTTPSPort: server.httpsPort,
    auth: { method: 'token', token },
    log: { to: 'console', level: 'info', disablePrintColor: true },
  });
}
