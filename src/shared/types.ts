import { z } from 'zod';

// 所有来自界面的参数都由主进程再次校验，不信任渲染进程输入。
const id = z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/);
const port = z.number().int().min(1).max(65535);
const text = z.string().max(4096);
const proxyBaseSchema = z.object({
  id,
  name: z.string().min(1).max(100),
  type: z.enum(['tcp', 'udp', 'http', 'https']),
  localIP: z.string().min(1).max(253),
  localPort: port,
  remotePort: port.optional(),
  // domain 用于读取旧版本单域名记录；解析后统一转为 domains。
  domain: z.string().max(253).optional(),
  domains: z.array(z.string().max(253)).max(100).default([]),
  tlsMode: z.enum(['passthrough', 'terminate']).default('passthrough'),
  certificateId: id.optional(),
  certPath: text.default(''),
  keyPath: text.default(''),
});
export const proxySchema = z.preprocess(
  (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
    const rule = value as Record<string, unknown>;
    return {
      ...rule,
      domains:
        Array.isArray(rule.domains) && rule.domains.length
          ? rule.domains
          : typeof rule.domain === 'string' && rule.domain
            ? [rule.domain]
            : [],
    };
  },
  proxyBaseSchema.transform(({ domain: _legacyDomain, ...rule }) => rule),
);
export const certificateSchema = z.object({
  id,
  name: z.string().min(1).max(100),
  provider: z.enum(['manual', 'letsencrypt', 'litessl']),
  domains: z.array(z.string().min(1).max(253)).min(1).max(100),
  email: z.string().email().optional(),
  certPath: text,
  keyPath: text,
  expiresAt: z.string().datetime().optional(),
  autoRenew: z.boolean().default(false),
  challenge: z.enum(['http-01', 'dns-01']).optional(),
  pendingRestart: z.boolean().default(false),
  pendingRestartInstances: z.array(id).default([]),
  createdAt: z.number().int().nonnegative(),
});
export const deploymentSchema = z.object({
  binary: text,
  config: text,
  log: text,
  pidFile: text,
  mode: z.enum(['system', 'user', 'process']),
  manager: z.enum(['systemd', 'openrc', 'sysv', 'process']).optional(),
  servicePath: text.optional(),
  logMode: z.enum(['file', 'journal']).optional(),
  service: z.string().regex(/^[a-zA-Z0-9_.@-]+$/),
  managed: z.boolean(),
  versionKey: z.string(),
  version: z.string(),
});
export const serverSchema = z.object({
  id,
  name: z.string().min(1).max(100),
  host: z.string().min(1).max(253),
  sshPort: port,
  username: z.string().min(1).max(100),
  auth: z.enum(['password', 'key']),
  keyPath: text.default(''),
  publicHost: z.string().min(1).max(253),
  frpPort: port,
  httpPort: port.default(8080),
  httpsPort: port.default(8443),
  password: text.optional(),
  passphrase: text.optional(),
  token: text.optional(),
  fingerprint: text.optional(),
  deployment: deploymentSchema.optional(),
  configMode: z.enum(['form', 'raw']).default('form'),
  rawConfig: z.string().max(1048576).default(''),
  rawFormat: z.enum(['toml', 'ini', 'yaml', 'json']).default('toml'),
});
export const instanceSchema = z.object({
  id,
  name: z.string().min(1).max(100),
  serverId: id,
  versionKey: z.string().min(1),
  mode: z.enum(['form', 'raw']),
  rawConfig: z.string().max(1048576).default(''),
  rawFormat: z.enum(['toml', 'ini', 'yaml', 'json']).default('toml'),
  proxies: z.array(proxySchema).max(100),
});
export const settingsSchema = z.object({ proxyUrl: z.string().max(2048).default('') });
export const installSchema = z.object({
  version: z.string().regex(/^v?\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.-]+)?$/),
  platform: z.enum(['darwin', 'windows', 'linux']),
  arch: z.enum(['amd64', 'arm64']),
  url: z.string().max(4096).optional(),
  localPath: text.optional(),
  digest: text.optional(),
});
export type Server = z.infer<typeof serverSchema>;
export type Deployment = z.infer<typeof deploymentSchema>;
export type Instance = z.infer<typeof instanceSchema>;
export type ProxyRule = z.infer<typeof proxySchema>;
export type CertificateRecord = z.infer<typeof certificateSchema>;
export type Settings = z.infer<typeof settingsSchema>;
export type InstallRequest = z.infer<typeof installSchema>;
export interface Asset {
  name: string;
  url: string;
  digest?: string;
  size?: number;
}
export interface Release {
  assetError?: string;
  version: string;
  publishedAt: string;
  assets: Asset[];
}
export interface InstalledVersion {
  key: string;
  version: string;
  platform: InstallRequest['platform'];
  arch: InstallRequest['arch'];
  directory: string;
  source: string;
  installedAt: string;
  verified: boolean;
  digest: string;
}
export interface Catalog {
  source?: 'api' | 'github-web';
  releases: Release[];
  updatedAt: string;
  cached: boolean;
  warning?: string;
  page: number;
  hasMore: boolean;
}
export interface State {
  servers: Server[];
  instances: Instance[];
  certificates: CertificateRecord[];
  versions: InstalledVersion[];
  settings: Settings;
  secureStorage: boolean;
  platform: string;
  arch: string;
}
export interface Runtime {
  status: 'stopped' | 'starting' | 'running' | 'connected' | 'error';
  message: string;
  proxies: Record<string, string>;
}
export interface HostInfo {
  home: string;
  supported: boolean;
  distribution: string;
  version: string;
  kernel: string;
  arch: string;
  cpuModel: string;
  cpuCores: number | null;
  memoryTotalKB: number | null;
  memoryAvailableKB: number | null;
  diskTotalKB: number | null;
  diskAvailableKB: number | null;
  serviceManager: 'systemd' | 'openrc' | 'sysv' | 'unknown';
  systemd: boolean;
  userSystemd: boolean;
  root: boolean;
  sudo: boolean;
  ports: string;
  warning?: string;
}
export type Result<T = unknown> =
  { ok: true; data: T } | { ok: false; error: string; code?: string };
export interface DesktopApi {
  call<T = unknown>(action: string, payload?: unknown): Promise<Result<T>>;
  onChange(callback: () => void): () => void;
  onCertificateProgress(callback: (progress: CertificateIssueProgress) => void): () => void;
}

export interface CertificateIssueProgress {
  taskId: string;
  status:
    'running' | 'retrying' | 'waiting-user' | 'cancelling' | 'succeeded' | 'failed' | 'cancelled';
  step: string;
  message: string;
  attempt?: number;
  dnsRecords?: Array<{ domain: string; record: string; value: string }>;
  updatedAt: number;
}
