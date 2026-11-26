import TOML from '@iarna/toml';
import { AppError } from '../shared/errors';
import type { FrpsServiceCandidate } from '../shared/types';

export interface DiscoveredFrpsConfig {
  frpPort: number;
  httpPort: number;
  httpsPort: number;
  token: string;
  format: 'toml' | 'ini' | 'yaml' | 'json';
}

function unquote(value: string) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  )
    return trimmed.slice(1, -1);
  return trimmed;
}

// 只提取客户端连接必需字段；不把其他服务端秘密或配置复制到本机。
export function parseDiscoveredFrpsConfig(content: string, filePath: string): DiscoveredFrpsConfig {
  if (!content.trim() || content.length > 1024 * 1024)
    throw new AppError('FRP 服务端配置为空或超过 1 MB，无法检索。');
  const extension = filePath.toLowerCase().split('.').pop();
  let format: DiscoveredFrpsConfig['format'];
  let fields = new Map<string, unknown>();
  try {
    if (
      (extension === 'toml' || /^\s*(?:bindPort|auth\s*=)/m.test(content)) &&
      extension !== 'yaml' &&
      extension !== 'yml'
    ) {
      format = 'toml';
      const parsed = TOML.parse(content) as Record<string, any>;
      fields.set(
        'bindPort',
        parsed.bindPort ?? parsed.bind_port ?? parsed.serverPort ?? parsed.server_port,
      );
      fields.set('httpPort', parsed.vhostHTTPPort ?? parsed.vhost_http_port);
      fields.set('httpsPort', parsed.vhostHTTPSPort ?? parsed.vhost_https_port);
      fields.set('token', parsed.auth?.token ?? parsed.token);
    } else if (extension === 'json' || /^\s*\{/.test(content)) {
      format = 'json';
      const parsed = JSON.parse(content) as Record<string, any>;
      fields.set(
        'bindPort',
        parsed.bindPort ?? parsed.bind_port ?? parsed.serverPort ?? parsed.server_port,
      );
      fields.set('httpPort', parsed.vhostHTTPPort ?? parsed.vhost_http_port);
      fields.set('httpsPort', parsed.vhostHTTPSPort ?? parsed.vhost_https_port);
      fields.set('token', parsed.auth?.token ?? parsed.token);
    } else if (extension === 'yaml' || extension === 'yml') {
      format = 'yaml';
      const normalized = content.replace(/^\s*#.*$/gm, '');
      for (const [key, pattern] of [
        ['bindPort', /^\s*(?:bindPort|bind_port|serverPort|server_port)\s*:\s*(.+?)\s*$/m],
        ['httpPort', /^\s*(?:vhostHTTPPort|vhost_http_port)\s*:\s*(.+?)\s*$/m],
        ['httpsPort', /^\s*(?:vhostHTTPSPort|vhost_https_port)\s*:\s*(.+?)\s*$/m],
        ['token', /^\s*token\s*:\s*(.+?)\s*$/m],
      ] as const) {
        const value = pattern.exec(normalized)?.[1];
        if (value !== undefined) fields.set(key, unquote(value));
      }
    } else {
      format = 'ini';
      let section = '';
      for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#') || line.startsWith(';')) continue;
        const sectionMatch = /^\[([^\]]+)\]$/.exec(line);
        if (sectionMatch) {
          section = sectionMatch[1].toLowerCase();
          continue;
        }
        const match = /^([\w_]+)\s*=\s*(.*?)\s*$/.exec(line);
        if (!match) continue;
        const name = match[1].toLowerCase();
        const key =
          name === 'bind_port' || name === 'server_port' || name === 'bindport'
            ? 'bindPort'
            : name === 'vhost_http_port' || name === 'vhosthttpport'
              ? 'httpPort'
              : name === 'vhost_https_port' || name === 'vhosthttpsport'
                ? 'httpsPort'
                : name === 'token'
                  ? 'token'
                  : '';
        if (key && (!section || section === 'common' || section === 'auth'))
          fields.set(key, unquote(match[2]));
      }
    }
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(
      `无法解析 FRP 服务端配置：${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const port = (key: string, fallback: number) => {
    const raw = fields.get(key);
    if (raw === undefined || raw === null || raw === '') return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 1 || value > 65535)
      throw new AppError(`FRP 配置中的 ${key} 不是有效端口。`);
    return value;
  };
  const token = String(fields.get('token') ?? '').trim();
  if (!token)
    throw new AppError('已找到 FRP 服务，但配置中没有可读取的认证令牌；请检查配置路径和认证方式。');
  return {
    frpPort: port('bindPort', 7000),
    httpPort: port('httpPort', 8080),
    httpsPort: port('httpsPort', 8443),
    token,
    format,
  };
}

// 解析 systemctl 属性输出，兼容不支持 --value 的 CentOS 7。
// ExecStart 常见写法差异很大：多个 argv[]、sh -c 包装、-c=/path、引号路径都要识别，
// 否则检测出的服务会在「只读读取」和「移除」时因为路径不对而失败。
function baseName(value: string) {
  return value.split(/[\\/]/).pop()?.toLowerCase() ?? '';
}
function systemdArgv(start: string): string[] {
  // argv[] 的值用 \; 转义分号，先按转义规则切出完整片段再还原。
  const result: string[] = [];
  const pattern = /argv\[\]=((?:\\.|[^;])*)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(start))) {
    const value = match[1].replace(/\\([;"])/g, '$1').trim();
    if (value) result.push(value);
  }
  return result;
}
/** 极简 POSIX 分词：只处理引号与反斜杠，不解释命令、变量或通配符。 */
export function tokenizeShellCommand(command: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;
  let started = false;
  for (const char of command) {
    if (escaped) {
      current += char;
      escaped = false;
      started = true;
      continue;
    }
    if (char === '\\' && quote !== "'") {
      escaped = true;
      started = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      else current += char;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      started = true;
      continue;
    }
    if (/\s/.test(char)) {
      if (started) {
        tokens.push(current);
        current = '';
        started = false;
      }
      continue;
    }
    current += char;
    started = true;
  }
  if (started) tokens.push(current);
  return tokens;
}
const shells = new Set(['sh', 'bash', 'dash', 'ash', 'zsh']);

/** 从 ExecStart 参数里定位真正的 frps 程序与配置路径，兼容 sh -c 包装与等号写法。 */
export function extractFrpsLaunch(
  argv: string[],
  allowFallback = false,
): { binary: string; config: string } | undefined {
  let tokens = argv.flatMap(tokenizeShellCommand);
  if (tokens.length >= 3 && shells.has(baseName(tokens[0])) && tokens[1] === '-c') {
    tokens = tokenizeShellCommand(tokens.slice(2).join(' '));
  }
  let binaryIndex = tokens.findIndex(
    (token) => /(^|[-_.])frps$/.test(baseName(token)) && !/frpc/i.test(token),
  );
  if (binaryIndex < 0 && allowFallback) binaryIndex = tokens.findIndex((t) => t.startsWith('/'));
  // 不放弃路径兜底时拒绝：避免把 nginx -c /etc/nginx/nginx.conf 误判成 FRP。
  if (binaryIndex < 0) return undefined;
  let config = '';
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    const equal = /^(?:--config|-c)=(.*)$/i.exec(token);
    if (equal) {
      config = unquote(equal[1]);
      break;
    }
    if (/^(?:-c|--config)$/i.test(token) && tokens[index + 1]) {
      config = unquote(tokens[index + 1]);
      break;
    }
  }
  if (!config || config.startsWith('-')) return undefined;
  return { binary: tokens[binaryIndex], config };
}

export function parseSystemdFrpsCandidate(
  service: string,
  output: string,
): FrpsServiceCandidate | undefined {
  const values = new Map<string, string>();
  for (const line of output.split(/\r?\n/)) {
    const separator = line.indexOf('=');
    if (separator > 0) values.set(line.slice(0, separator), line.slice(separator + 1));
  }
  const launch = extractFrpsLaunch(
    systemdArgv(values.get('ExecStart') ?? ''),
    /intranet-frps/i.test(service),
  );
  if (!launch) return undefined;
  return {
    service,
    manager: 'systemd',
    state: values.get('ActiveState') ?? 'unknown',
    binary: launch.binary,
    config: launch.config,
  };
}

// 从登录用户的持久化 history 文件提取命令，不执行 history 内容。
export function parseShellHistory(shell: string, output: string) {
  const marker = '__TERMINAL_SHELL__';
  const start = output.indexOf(`${marker}`);
  if (start < 0) return { shell: 'unknown', available: false, commands: [] as string[] };
  const headerEnd = output.indexOf('\n', start);
  const shellName = output
    .slice(start + marker.length, headerEnd < 0 ? undefined : headerEnd)
    .trim();
  const raw = output.slice(headerEnd < 0 ? output.length : headerEnd + 1);
  if (raw.includes('__NO_HISTORY__'))
    return { shell: shellName || shell, available: false, commands: [] as string[] };
  const commands: string[] = [];
  if (shellName === 'zsh') {
    for (const line of raw.split(/\r?\n/)) {
      const match = /^:\s+\d+:\d+;(.*)$/.exec(line);
      const command = (match?.[1] ?? line).trim();
      if (command) commands.push(command);
    }
  } else if (shellName === 'fish') {
    for (const line of raw.split(/\r?\n/)) {
      const match = /^-\s+cmd:\s?(.*)$/.exec(line);
      if (match)
        commands.push(match[1].replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\\\/g, '\\'));
    }
  } else {
    for (const line of raw.split(/\r?\n/)) {
      if (/^#\d+$/.test(line)) continue;
      if (line.trim()) commands.push(line);
    }
  }
  // 最近的 history 往往被大量重复的 history/ll/pwd 刷屏。按命令去重、保留最近一次，
  // 让「记录」面板真正用于快速重放最近用过的不同命令，而不是重复项占满列表。
  const recent = commands.slice(-500).reverse();
  const seen = new Set<string>();
  const deduped = recent.filter((command) => {
    if (seen.has(command)) return false;
    seen.add(command);
    return true;
  });
  return { shell: shellName || shell, available: true, commands: deduped };
}
