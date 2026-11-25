import { createHash } from 'node:crypto';
import { AppError, redact } from '../shared/errors';
import type { DeployLevel, DomainSiteInfo, PortOwner, SiteInspection } from '../shared/types';
import type { Store } from './store';
import type { Remote } from './remote';
import { quote } from './remote';

interface ServerBlock {
  file: string;
  names: string[];
  certPath?: string;
  keyPath?: string;
  ssl: boolean;
  defaultServer: boolean;
}

interface ListenInfo {
  listening: boolean;
  process?: string;
  pid?: number;
}

// 站点检查只读：所有命令都是 ss / test / cat / nginx -T 之类的探测，绝不写服务端、绝不 reload。
// 结果仅缓存到本机 store.saveInspection，供部署分级与环境漂移比对使用。

function stripComments(text: string): string {
  return text.replace(/#[^\n\r]*/g, '');
}

function matchBrace(text: string, open: number): { body: string; close: number } {
  let depth = 0;
  let quoteChar = '';
  for (let index = open; index < text.length; index += 1) {
    const char = text[index];
    if (quoteChar) {
      if (char === quoteChar && text[index - 1] !== '\\') quoteChar = '';
      continue;
    }
    if (char === '"' || char === "'") {
      quoteChar = char;
      continue;
    }
    if (char === '{') depth += 1;
    else if (char === '}') {
      depth -= 1;
      if (depth === 0) return { body: text.slice(open + 1, index), close: index };
    }
  }
  return { body: text.slice(open + 1), close: text.length };
}

function cleanDirective(value?: string): string | undefined {
  if (!value) return undefined;
  const trimmed = value
    .trim()
    .replace(/^["']|["']$/g, '')
    .trim();
  return trimmed || undefined;
}

// 解析 nginx -T 输出里的 server {} 块：覆盖泛域名 *.、正则 ~^、default_server。
export function extractServerBlocks(dump: string): ServerBlock[] {
  const cleaned = stripComments(dump);
  const blocks: ServerBlock[] = [];
  const marker = /^# configuration file (.+):\s*$/gm;
  const sections: Array<{ file: string; content: string }> = [];
  let previous: { file: string; start: number } | undefined;
  let match: RegExpExecArray | null;
  while ((match = marker.exec(dump)) !== null) {
    if (previous)
      sections.push({ file: previous.file, content: dump.slice(previous.start, match.index) });
    previous = { file: match[1].trim(), start: match.index + match[0].length };
  }
  if (previous) sections.push({ file: previous.file, content: dump.slice(previous.start) });
  // nginx -T 失败时可能没有文件标记，仍尽力从原文解析。
  if (!sections.length && dump.trim()) sections.push({ file: '(unknown)', content: dump });

  for (const section of sections) {
    const text = stripComments(section.content);
    const serverRe = /\bserver\s*\{/g;
    let serverMatch: RegExpExecArray | null;
    while ((serverMatch = serverRe.exec(text)) !== null) {
      const open = text.indexOf('{', serverMatch.index);
      if (open < 0) continue;
      const { body, close } = matchBrace(text, open);
      serverRe.lastIndex = close + 1;
      const namesRaw = /\bserver_name\s+([^;]+);/i.exec(body)?.[1] ?? '';
      const names = namesRaw.trim() ? namesRaw.trim().split(/\s+/).filter(Boolean) : [];
      const certPath = cleanDirective(/\bssl_certificate\s+([^;]+);/i.exec(body)?.[1]);
      const keyPath = cleanDirective(/\bssl_certificate_key\s+([^;]+);/i.exec(body)?.[1]);
      const listens = [...body.matchAll(/\blisten\s+([^;]+);/gi)].map((item) => item[1]);
      const ssl = listens.some((line) => /\bssl\b/i.test(line)) || Boolean(certPath);
      const defaultServer = listens.some((line) => /default_server/i.test(line));
      blocks.push({ file: section.file, names, certPath, keyPath, ssl, defaultServer });
    }
  }
  return blocks;
}

// 从 nginx -T 的 include 指令提取 nginx 真正加载的目录（L2 只能写这些已有目录）。
function extractIncludeDirs(dump: string): string[] {
  const cleaned = stripComments(dump);
  const dirs = new Set<string>();
  for (const match of cleaned.matchAll(/\binclude\s+([^;]+);/gi)) {
    const pattern = cleanDirective(match[1]);
    if (!pattern || !pattern.includes('*') || !pattern.startsWith('/')) continue;
    const star = pattern.indexOf('*');
    const dir = pattern
      .slice(0, star)
      .replace(/[^/]*$/, '')
      .replace(/\/+$/, '');
    if (dir.startsWith('/')) dirs.add(dir);
  }
  return [...dirs];
}

function parseListen(output: string): Record<number, ListenInfo> {
  const result: Record<number, ListenInfo> = {
    80: { listening: false },
    443: { listening: false },
  };
  for (const line of output.split(/\r?\n/)) {
    const address = /\s(?:[\d.]+|\[[0-9a-fA-F:]+\]):(80|443)(?:\s|$)/.exec(line);
    if (!address) continue;
    const port = Number(address[1]);
    const ssProcess = /users:\(\("([^"]+)",pid=(\d+)/.exec(line);
    const netstatProcess = /\s(\d+)\/([^\s/]+)\s*$/.exec(line);
    result[port] = {
      listening: true,
      process: ssProcess?.[1] ?? netstatProcess?.[2],
      pid: ssProcess
        ? Number(ssProcess[2])
        : netstatProcess
          ? Number(netstatProcess[1])
          : undefined,
    };
  }
  return result;
}

function domainMatches(name: string, domain: string): boolean {
  const candidate = name.trim().toLowerCase().replace(/\.$/, '');
  const target = domain.toLowerCase();
  if (!candidate || candidate === '_') return false;
  if (candidate === target) return true;
  if (candidate.startsWith('*.')) {
    const suffix = candidate.slice(2);
    return target.endsWith(`.${suffix}`) && !target.slice(0, -(suffix.length + 1)).includes('.');
  }
  if (candidate.startsWith('~')) {
    try {
      return new RegExp(candidate.slice(1), 'i').test(target);
    } catch {
      return false;
    }
  }
  return false;
}

function buildDomainInfo(domain: string, blocks: ServerBlock[]): DomainSiteInfo {
  const matched = blocks.filter((block) => block.names.some((name) => domainMatches(name, domain)));
  const primary = matched.find((block) => block.certPath) ?? matched[0];
  const certPath = primary?.certPath;
  const users = certPath ? blocks.filter((block) => block.certPath === certPath) : [];
  const sharedCert = users.length > 1;
  const sharedWith = sharedCert
    ? [...new Set(users.flatMap((block) => block.names).filter((name) => name !== '_'))].filter(
        (name) => !domainMatches(name, domain),
      )
    : [];
  return {
    domain,
    hasSite: matched.length > 0,
    siteFile: primary?.file,
    certPath,
    keyPath: primary?.keyPath,
    sharedCert,
    sharedWith,
    serverNames: [...new Set(matched.flatMap((block) => block.names))],
  };
}

function signatureOf(
  ports: PortOwner[],
  nginx: SiteInspection['nginx'],
  domains: DomainSiteInfo[],
): string {
  const canonical = {
    ports: ports.map((port) => ({ port: port.port, state: port.state, process: port.process })),
    nginx: {
      present: nginx.present,
      mainConfig: nginx.mainConfig,
      dumpOk: nginx.dumpOk,
      managedByPanel: nginx.managedByPanel,
      includeDir: nginx.includeDir,
    },
    domains: domains.map((info) => ({
      domain: info.domain,
      hasSite: info.hasSite,
      siteFile: info.siteFile,
      certPath: info.certPath,
      keyPath: info.keyPath,
      sharedCert: info.sharedCert,
    })),
  };
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

const PROBE_COMMAND = `
printf '__LISTEN__\\n'
ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true
printf '__DIRS__\\n'
for d in /etc/nginx/conf.d /etc/nginx/sites-enabled /etc/nginx/vhost /etc/nginx/conf.d/vhost /www/server/panel/vhost/nginx /usr/local/nginx/conf/vhost /usr/local/openresty/nginx/conf/vhost /opt/1panel/apps/openresty/openresty/conf/vhost; do
  if test -d "$d"; then w=readonly; test -w "$d" && w=writable; printf '%s\\t%s\\n' "$d" "$w"; fi
done
printf '__PANEL__\\n'
for p in /www/server/panel /www/server/nginx /opt/1panel /usr/local/openresty; do test -e "$p" && printf '%s\\n' "$p"; done
printf '__NGINX_BIN__\\n'
command -v nginx 2>/dev/null || true
printf '__END__\\n'
`.trim();

function section(output: string, name: string): string {
  const start = output.indexOf(`__${name}__`);
  if (start < 0) return '';
  const begin = start + name.length + 4;
  const rest = output.slice(begin);
  const end = rest.indexOf('__');
  return end < 0 ? rest : rest.slice(0, end);
}

export class SiteInspector {
  constructor(
    private readonly store: Store,
    private readonly remote: Remote,
  ) {}

  /** 只读探测 80/443 归属、nginx 站点配置、证书共享与可用 include 目录。 */
  async inspect(serverId: string, domains: string[]): Promise<SiteInspection> {
    this.store.server(serverId); // 校验服务器存在
    const admin = this.remote.nginxAdmin(serverId);
    const warnings: string[] = [];
    let probeOutput = '';
    let dump = '';
    try {
      probeOutput = await admin.run(PROBE_COMMAND);
    } catch (error) {
      warnings.push(
        `端口与面板探测失败：${redact(error instanceof Error ? error.message : String(error), this.store.allSecrets()).slice(0, 200)}`,
      );
    }
    try {
      dump = await admin.run(
        'if command -v nginx >/dev/null 2>&1; then nginx -T 2>&1 || true; else printf "__NO_NGINX__\\n"; fi',
      );
    } catch (error) {
      warnings.push(
        `nginx -T 读取失败：${redact(error instanceof Error ? error.message : String(error), this.store.allSecrets()).slice(0, 200)}`,
      );
    }

    const listen = parseListen(section(probeOutput, 'LISTEN'));
    const dirsOutput = section(probeOutput, 'DIRS');
    const existingDirs = new Map<string, string>();
    for (const line of dirsOutput.split(/\r?\n/)) {
      const [dir, mode] = line.trim().split('\t');
      if (dir) existingDirs.set(dir, mode ?? '');
    }
    const panelOutput = section(probeOutput, 'PANEL');
    const nginxBin = section(probeOutput, 'NGINX_BIN').trim().split(/\r?\n/)[0] ?? '';

    const mainConfig = /nginx: the configuration file (\S+) syntax is ok/m.exec(dump)?.[1] ?? '';
    const dumpOk = /syntax is ok|test is successful/.test(dump) && !/__NO_NGINX__/.test(dump);
    const blocks = extractServerBlocks(dump);
    const nginxIncludeDirs = extractIncludeDirs(dump);
    // L2 只写 Nginx 真正 include 的目录；绝不猜一个"看起来像"的目录。
    const includeDir = nginxIncludeDirs.find((dir) => existingDirs.has(dir));
    if (includeDir && existingDirs.get(includeDir) === 'readonly')
      warnings.push(`Nginx include 目录 ${includeDir} 当前用户不可写，L2 需要免密 sudo。`);
    if (nginxIncludeDirs.length && !includeDir)
      warnings.push('Nginx 配置包含 include 目录，但探测阶段未确认其存在；L2 暂不可用。');

    const managedByPanel =
      panelOutput.split(/\r?\n/).some(Boolean) ||
      /\/www\/server|\/opt\/1panel|openresty/i.test(mainConfig) ||
      blocks.some((block) => /\/www\/server|\/opt\/1panel|openresty/i.test(block.file));
    if (managedByPanel)
      warnings.push(
        '检测到宝塔/1Panel 等面板管理 Nginx，请优先在面板内确认，工具不会自动改主配置。',
      );

    const managedTls = this.store.data.managedTls;
    const ports: PortOwner[] = [80, 443].map((port) => {
      const info = listen[port] ?? { listening: false };
      let state: PortOwner['state'] = 'free';
      if (info.listening) {
        if (
          managedTls?.serverId === serverId &&
          managedTls.running &&
          managedTls.portsHeld.includes(port)
        )
          state = 'managed-tls';
        else if (/nginx|openresty/i.test(info.process ?? '')) state = 'system-nginx';
        else state = 'other';
      }
      return { port, state, process: info.process, pid: info.pid };
    });

    const domainInfos = domains.map((domain) => buildDomainInfo(domain, blocks));
    const nginx = {
      present: Boolean(nginxBin) || blocks.length > 0 || dumpOk,
      mainConfig,
      dumpOk,
      managedByPanel,
      includeDir,
    };

    if (!dumpOk && nginx.present)
      warnings.push('nginx -T 未能成功导出完整配置，server 块解析可能不完整。');
    if (ports.every((port) => port.state === 'free'))
      warnings.push('80/443 均空闲，证书签发后保持 pending，需由 TLS 持有者或人工部署后才生效。');
    const nonNginx = ports.find((port) => port.port === 80 && port.state === 'other');
    if (nonNginx)
      warnings.push(
        `80 端口被非 Nginx 进程（${nonNginx.process ?? '未知'}）占用，HTTP-01 已禁用并降级 DNS-01。`,
      );
    for (const info of domainInfos)
      if (info.sharedCert)
        warnings.push(
          `域名 ${info.domain} 的证书被多站点共用（${info.sharedWith.join('、') || '其他站点'}），L1 覆盖会影响其他站点。`,
        );

    // 只读校验已知 cert/key 路径是否可读（不写入）。
    const paths = [...new Set(domainInfos.flatMap((info) => [info.certPath, info.keyPath]))].filter(
      (value): value is string => Boolean(value),
    );
    if (paths.length) {
      const check = paths
        .map((item) => `test -r ${quote(item)} || printf 'unreadable\\t%s\\n' ${quote(item)}`)
        .join('; ');
      const unreadable = await admin.run(check).catch(() => '');
      for (const line of unreadable.split(/\r?\n/)) {
        const value = line.trim().split('\t')[1];
        if (value) warnings.push(`证书文件 ${value} 当前用户不可读，L1 需要免密 sudo。`);
      }
    }

    const recommendations = domainInfos.map((info) => {
      const levels: DeployLevel[] = ['L0'];
      const reasons = ['L0：仅落盘并给出可复制配置片段，Nginx 零改动。'];
      if (info.certPath && info.keyPath && !info.sharedCert) {
        levels.push('L1');
        reasons.push('L1：已有独立 ssl_certificate/key，备份后同路径覆盖，仅 nginx -t → reload。');
      } else if (info.certPath && info.sharedCert) {
        reasons.push('L1 不可用：证书被多站点共用，覆盖会波及其他站点。');
      } else if (info.hasSite) {
        reasons.push('L1 不可用：尚未找到该站点独立的 ssl_certificate/key 路径。');
      }
      if (includeDir) {
        levels.push('L2');
        reasons.push(`L2：可往已有 include 目录 ${includeDir} 写独立 conf（需二次确认）。`);
      }
      return { domain: info.domain, levels, reason: reasons.join(' ') };
    });

    const inspection: SiteInspection = {
      serverId,
      inspectedAt: Date.now(),
      ports,
      nginx,
      domains: domainInfos,
      recommendations,
      environmentSignature: signatureOf(ports, nginx, domainInfos),
      warnings,
    };
    await this.store.saveInspection(serverId, inspection);
    return inspection;
  }

  /** 供部署前强制刷新：直接复用 inspect（探测本身零变更）。 */
  async refresh(serverId: string, domains: string[]): Promise<SiteInspection> {
    return this.inspect(serverId, domains);
  }
}
