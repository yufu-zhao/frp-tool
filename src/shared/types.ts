import { z } from 'zod';

// 所有来自界面的参数都由主进程再次校验，不信任渲染进程输入。
const id = z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/);
const port = z.number().int().min(1).max(65535);
const text = z.string().max(4096);
export const proxySchema = z.object({
  id,
  name: z.string().min(1).max(100),
  type: z.enum(['tcp', 'udp', 'http', 'https']),
  localIP: z.string().min(1).max(253),
  localPort: port,
  remotePort: port.optional(),
  domain: z.string().max(253).default(''),
  tlsMode: z.enum(['passthrough', 'terminate']).default('passthrough'),
  certPath: text.default(''),
  keyPath: text.default(''),
});
export const deploymentSchema = z.object({
  binary: text,
  config: text,
  log: text,
  pidFile: text,
  mode: z.enum(['system', 'user', 'process']),
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
  arch: string;
  systemd: boolean;
  userSystemd: boolean;
  root: boolean;
  sudo: boolean;
  ports: string;
}
export type Result<T = unknown> =
  { ok: true; data: T } | { ok: false; error: string; code?: string };
export interface DesktopApi {
  call<T = unknown>(action: string, payload?: unknown): Promise<Result<T>>;
  onChange(callback: () => void): () => void;
}
