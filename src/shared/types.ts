import { z } from 'zod';

// 所有来自界面的参数都由主进程再次校验，不信任渲染进程输入。
const id = z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/);
const port = z.number().int().min(1).max(65535);
const text = z.string().max(4096);

// FRP vhost 端口按服务器现状手动填写：80/443 空闲时可直接占用，被占用时改成高端口并反代。
const vhostPort = port;

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
  // 规则内保存的站点反代配置模板：只用于查看/复制，不参与 frpc 配置生成。
  siteConfig: z.string().max(1048576).optional(),
  siteConfigFlavor: z.enum(['nginx', 'apache', 'caddy', 'lighttpd', 'unknown']).optional(),
  siteConfigUpdatedAt: z.number().int().nonnegative().optional(),
  siteConfigPath: z.string().max(1024).optional(),
  // 方案 A（服务器终止 TLS）：站点配置写服务器后，规则回源改为 http；此标记说明公网仍走 HTTPS。
  // 不参与 frpc 配置生成，只用于界面提示与配置模板选择。
  publicHttps: z.boolean().optional(),
  // 证书自动生成的 HTTPS 伴随规则：参与 frpc 配置，但不在规则列表中展示，也不允许单独编辑。
  hidden: z.boolean().optional(),
  // 伴随规则对应的用户 HTTP 规则；移除证书时据此定位并删除。
  sourceRuleId: id.optional(),
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

// 历史数据兼容：旧版本可能保存本机证书记录，运行时不再提供管理入口。
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
  dnsAccountId: id.optional(),
  pendingRestart: z.boolean().default(false),
  pendingRestartInstances: z.array(id).default([]),
  createdAt: z.number().int().nonnegative(),
});

export const serverSiteSchema = z.object({
  id,
  serverId: id,
  instanceId: id,
  ruleId: id,
  name: z.string().min(1).max(100),
  domains: z.array(z.string().min(1).max(253)).min(1).max(100),
  upstreamPort: port,
  configPath: text,
  mainConfig: text.optional(),
  includeCreatedByApp: z.boolean().default(false),
  certificateId: id.optional(),
  outOfSync: z.boolean().default(false),
  createdAt: z.number().int().nonnegative(),
});

export type DeployLevel = 'L0' | 'L1' | 'L2';
export type DeployState = 'pending' | 'awaiting-confirm' | 'deployed' | 'needs-review' | 'manual';
// 新签发只有 api；其余值仅用于读取旧记录（已移除的 CNAME 委派 / 手动 TXT 方案）。
export type DnsAutomation = 'api' | 'cname' | 'reuse' | 'manual';

// DNS 账户：同一服务商可保存多份凭据（不同 SecretID / Token），签发时按账户选择。
export const dnsProviderSchema = z.enum(['dnspod', 'aliyun', 'cloudflare']);
export type DnsProviderId = z.infer<typeof dnsProviderSchema>;
export const dnsAccountSchema = z.object({
  id,
  name: z.string().min(1).max(100),
  provider: dnsProviderSchema,
  createdAt: z.number().int().nonnegative(),
});
export type DnsAccount = z.infer<typeof dnsAccountSchema>;

// 服务端证书：TLS 在服务端 80/443 持有者上终止，本机 frpc 不持有证书。
export const serverCertificateSchema = z.object({
  id,
  serverId: id,
  name: z.string().min(1).max(100),
  provider: z.enum(['manual', 'letsencrypt', 'litessl']),
  domains: z.array(z.string().min(1).max(253)).min(1).max(100),
  email: z.string().email().optional(),
  challenge: z.enum(['http-01', 'dns-01']).optional(),
  // DNS-01 签发时选中的账户；续期沿用同一份凭据。
  dnsAccountId: id.optional(),
  // local：证书落在本机并供 frpc https2http 使用；server：证书落在服务端 TLS 终止层。
  location: z.enum(['local', 'server']).default('server'),
  localCertificateId: id.optional(),
  certPath: text,
  keyPath: text,
  expiresAt: z.string().datetime().optional(),
  autoRenew: z.boolean().default(false),
  renewalManager: z.enum(['systemd', 'cron', 'manual', 'unavailable']).default('manual'),
  // DNS-01 逐级自动化结果；manual 每次续期都需要人工添加 TXT。
  dnsAutomation: z.enum(['api', 'cname', 'reuse', 'manual']).default('manual'),
  // 生命周期与 TLS 终止层解耦：无 80/443 持有者时证书处于 pending。
  deployState: z
    .enum(['pending', 'awaiting-confirm', 'deployed', 'needs-review', 'manual'])
    .default('pending'),
  deployLevel: z.enum(['L0', 'L1', 'L2']).optional(),
  deployTarget: text.optional(),
  environmentSignature: text.optional(),
  lastInspectedAt: z.number().int().nonnegative().optional(),
  lastRenewedAt: z.number().int().nonnegative().optional(),
  notes: text.optional(),
  // 方案 A：证书在服务器上的落点与对应 server 块配置路径。
  serverCertPath: text.optional(),
  serverKeyPath: text.optional(),
  serverConfigPath: text.optional(),
  // 该证书按哪种 TLS 方案签发；旧记录缺省按本机处理。
  tlsPlan: z.enum(['server', 'local']).default('local'),
  // 证书所属的用户规则与实例；用于移除证书时回退到 HTTP。
  ruleId: id.optional(),
  instanceId: id.optional(),
  // 方案 B 自动生成的隐藏 HTTPS 伴随规则 ID。
  hiddenRuleId: id.optional(),
  createdAt: z.number().int().nonnegative(),
});

// 快捷命令仅保存在本机，由用户主动选择并执行。
export const terminalFavoriteSchema = z.object({
  id,
  name: z.string().min(1).max(100),
  command: z.string().min(1).max(8192),
  order: z.number().int().nonnegative(),
  updatedAt: z.number().int().nonnegative(),
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
  httpPort: vhostPort.default(8080),
  httpsPort: vhostPort.default(8443),
  password: text.optional(),
  passphrase: text.optional(),
  token: text.optional(),
  fingerprint: text.optional(),
  deployment: deploymentSchema.optional(),
  // 只读服务器只能用于创建 frpc 实例，不能操作远端 frps 服务。
  accessMode: z.enum(['managed', 'readonly']).default('managed'),
  discoveredService: z
    .object({
      name: z.string().min(1).max(255),
      manager: z.enum(['systemd', 'openrc', 'sysv', 'process']),
      binary: text,
      config: text,
    })
    .optional(),
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

export const settingsSchema = z.object({
  proxyUrl: z.string().max(2048).default(''),
  // 旧版单 DNS 服务商标识；新逻辑以 dnsAccounts 列表为准，保留字段兼容历史 state。
  dnsProvider: z.enum(['dnspod', 'aliyun', 'cloudflare']).default('dnspod'),
  // ACME 联系邮箱：第一次签发时自动写入，之后自动读取且允许修改。
  acmeEmail: z.string().max(254).default(''),
  // LiteSSL EAB 密钥本体只放安全存储，这里只标记是否已配置。
  litesslEabConfigured: z.boolean().default(false),
  // 站点检查后默认选择的部署方式；manual 对应 L0。
  deployDefault: z.enum(['manual', 'auto']).default('manual'),
  catalogCacheHours: z.number().int().min(1).max(720).default(24),
  downloadRetries: z.number().int().min(0).max(10).default(3),
  managedTlsEnabled: z.boolean().default(false),
  confirmDangerous: z.boolean().default(true),
  theme: z.enum(['light', 'dark', 'system']).default('light'),
});
export const installSchema = z.object({
  version: z.string().regex(/^v?\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.-]+)?$/),
  platform: z.enum(['darwin', 'windows', 'linux']),
  arch: z.enum(['amd64', 'arm64']),
  url: z.string().max(4096).optional(),
  localPath: text.optional(),
  digest: text.optional(),
  taskId: id.optional(),
});

export type Server = z.infer<typeof serverSchema>;
export type Deployment = z.infer<typeof deploymentSchema>;
export type Instance = z.infer<typeof instanceSchema>;
export type ProxyRule = z.infer<typeof proxySchema>;
export type CertificateRecord = z.infer<typeof certificateSchema>;
export type ServerSite = z.infer<typeof serverSiteSchema>;
export type ServerCertificate = z.infer<typeof serverCertificateSchema>;
export type TerminalFavorite = z.infer<typeof terminalFavoriteSchema>;
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
  source?: 'api' | 'github-web' | 'cache';
  releases: Release[];
  updatedAt: string;
  cached: boolean;
  stale?: boolean;
  warning?: string;
  page: number;
  hasMore: boolean;
}

// 版本解析结果：只做决策（定版本 / 定架构 / 查本地），不触发任何下载或联网。
// 服务端安装与创建客户端共用它，保证两个使用点的版本规则是同一套。
export interface VersionResolution {
  version: string;
  platform: InstallRequest['platform'];
  arch: InstallRequest['arch'];
  key: string;
  installed: boolean;
  /** 版本号是怎么定出来的，用于界面解释「为什么是这个版本」。 */
  source: 'explicit' | 'server-deployment' | 'latest-cached' | 'unavailable';
  /** 所选服务器已部署的 FRP 版本（客户端用途时才有意义）。 */
  serverVersion?: string;
  /** 客户端版本与服务器部署版本不一致，仅提示、不阻断。 */
  mismatch: boolean;
  /** 缓存的官方列表里是否存在该版本对应平台的安装包。 */
  available: boolean;
  /** 目标架构是否属于工具支持的 amd64 / arm64；不支持时只能手动选择或离线导入。 */
  archSupported: boolean;
  asset?: Asset;
  note: string;
}

// 下载进度：断点续传与失败重试都通过同一条事件通道上报。
// purpose / label 由发起方（自动准备包或手动下载）注入，供任务中心区分任务来源。
export interface DownloadProgress {
  taskId: string;
  key: string;
  version: string;
  purpose?: 'server' | 'client' | 'manual';
  label?: string;
  serverId?: string;
  status:
    | 'starting'
    | 'downloading'
    | 'retrying'
    | 'paused'
    | 'verifying'
    | 'extracting'
    | 'succeeded'
    | 'failed'
    | 'cancelled';
  received: number;
  total: number;
  percent: number;
  speed: number;
  attempt: number;
  resumable: boolean;
  message: string;
  updatedAt: number;
}
/** 渲染层任务中心的单个下载任务视图（由 download:progress 事件累积而成）。 */
export interface DownloadTaskView {
  taskId: string;
  label: string;
  purpose: 'server' | 'client' | 'manual';
  version: string;
  status: DownloadProgress['status'];
  percent: number;
  speed: number;
  received: number;
  total: number;
  message: string;
  attempt: number;
  resumable: boolean;
  updatedAt: number;
  steps?: Array<{ label: string; detail?: string; time?: number; tone?: string }>;
}
export interface DownloadRecord {
  key: string;
  url: string;
  digest?: string;
  partPath: string;
  received: number;
  total: number;
  etag?: string;
  lastModified?: string;
  status: 'downloading' | 'paused' | 'failed' | 'succeeded';
  updatedAt: number;
}

// 只读站点检查：探测本身不修改服务端任何内容。
export interface PortOwner {
  port: number;
  state: 'free' | 'managed-tls' | 'system-nginx' | 'other';
  process?: string;
  pid?: number;
}
export interface DomainSiteInfo {
  domain: string;
  hasSite: boolean;
  siteFile?: string;
  certPath?: string;
  keyPath?: string;
  sharedCert: boolean;
  sharedWith: string[];
  serverNames: string[];
}
export interface SiteInspection {
  serverId: string;
  inspectedAt: number;
  ports: PortOwner[];
  nginx: {
    present: boolean;
    mainConfig: string;
    dumpOk: boolean;
    managedByPanel: boolean;
    includeDir?: string;
  };
  domains: DomainSiteInfo[];
  recommendations: Array<{ domain: string; levels: DeployLevel[]; reason: string }>;
  environmentSignature: string;
  warnings: string[];
}

// 托管 TLS 实例：所有资源都登记在清单里，一键卸载按清单逆序清理。
export interface ManagedResource {
  kind: 'file' | 'directory' | 'unit' | 'timer' | 'cron' | 'capability' | 'process' | 'port';
  path: string;
  marked: boolean;
}
export interface ManagedTlsStatus {
  installed: boolean;
  running: boolean;
  serverId: string;
  root: string;
  unitName: string;
  portsHeld: number[];
  version: string;
  resources: ManagedResource[];
  lastChangedAt: number;
  warning?: string;
}
export interface TlsProxyProgress {
  taskId: string;
  status: 'running' | 'succeeded' | 'failed' | 'cancelled';
  step: string;
  message: string;
  updatedAt: number;
}

// 服务端安装进度：SSH 连接、系统探测、上传、配置、服务安装分阶段上报。
// 渲染层的统一 ProgressPanel 复用它，避免「点了安装没反应、出错也不知道」。
export interface ServerDeployProgress {
  taskId: string;
  serverId: string;
  status: 'starting' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  step: string;
  message: string;
  // 阶段百分比：安装步骤可估序但无法精确计时，null 表示不展示进度条。
  percent: number | null;
  updatedAt: number;
  error?: string;
  // 失败时可操作的下一步建议，直接显示在进度浮层里，避免只给一句错误无从下手。
  hint?: string;
  // 上传阶段的实际字节进度，交给 ProgressPanel 显示「已上传 x / 共 y」。
  received?: number;
  total?: number;
}
export type ServerDeployProgressUpdate = Omit<ServerDeployProgress, 'taskId' | 'updatedAt'>;

/**
 * 安装前预检：端口占用、已有 FRP 服务、安装目录残留一次查清，
 * 让渲染层在安装前就给出「保存只读 / 移除重装 / 覆盖上传」的选择，而不是中途报错终止。
 */
export interface InstallPrecheck {
  serverId: string;
  arch: string;
  supported: boolean;
  distribution: string;
  // 与当前表单配置端口冲突的已占用端口。
  portConflicts: number[];
  // 端口占用原始输出，供用户核对具体进程。
  ports: string;
  // 检索到的已有 FRP 系统服务（systemd / OpenRC / SysV）；不扫描进程列表，避免误报。
  existingServices: FrpsServiceCandidate[];
  // 本工具安装目录是否已有 frps 程序（需要决定是否覆盖上传）。
  installDirExists: boolean;
  // 是否已有本工具管理的部署。
  managedDeployment: boolean;
  warning?: string;
}

export interface State {
  servers: Server[];
  instances: Instance[];
  certificates: CertificateRecord[];
  serverSites: ServerSite[];
  serverCertificates: ServerCertificate[];
  dnsAccounts: DnsAccount[];
  terminalFavorites: TerminalFavorite[];
  versions: InstalledVersion[];
  settings: Settings;
  secureStorage: boolean;
  platform: string;
  arch: string;
  // 新增：版本列表持久化、下载断点、站点检查缓存、托管实例状态。
  catalog: Catalog | null;
  downloads: DownloadRecord[];
  siteInspections: Record<string, SiteInspection>;
  managedTls: ManagedTlsStatus | null;
  // Web 服务 include 注入清单：按服务器保存，便于回显和清除。
  webIncludes: Record<string, WebIncludeRecord>;
}

export type WebIncludeFlavor = 'nginx' | 'apache';

export interface WebIncludeProbe {
  path: string;
  token: string;
  ok: boolean;
  checkedAt: number;
  note?: string;
}

export interface WebIncludeRecord {
  serverId: string;
  flavor: WebIncludeFlavor;
  serviceName: string;
  mainConfig: string;
  managedDir: string;
  includeDirective: string;
  backupPath: string;
  injectedAt: number;
  probe?: WebIncludeProbe;
}

export interface WebIncludeCandidate {
  flavor: WebIncludeFlavor;
  serviceName: string;
  mainConfig: string;
  running: boolean;
  supported: boolean;
  reason?: string;
}

export interface WebIncludeManagedFile {
  name: string;
  size: number;
  modifiedAt: number;
}

export interface WebIncludeStatus {
  serverId: string;
  candidates: WebIncludeCandidate[];
  injected?: WebIncludeRecord;
  probe?: WebIncludeProbe;
  managedFiles: WebIncludeManagedFile[];
  warnings: string[];
  root: boolean;
  sudo: boolean;
}

export interface FrpsServiceCandidate {
  service: string;
  manager: 'systemd' | 'openrc' | 'sysv' | 'process';
  state: string;
  binary: string;
  config: string;
}
export interface Runtime {
  status: 'stopped' | 'starting' | 'running' | 'connected' | 'error';
  message: string;
  proxies: Record<string, string>;
}
export interface HostPortStatus {
  state: 'free' | 'occupied' | 'unknown';
  owner: string;
}
export interface HostWebService {
  name: string;
  installed: boolean;
  running: boolean;
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
  port80: HostPortStatus;
  port443: HostPortStatus;
  webServices: HostWebService[];
  warning?: string;
}
export type Result<T = unknown> =
  { ok: true; data: T } | { ok: false; error: string; code?: string };
export interface DesktopApi {
  call<T = unknown>(action: string, payload?: unknown): Promise<Result<T>>;
  onChange(callback: () => void): () => void;
  onCertificateProgress(callback: (progress: CertificateIssueProgress) => void): () => void;
  onDownloadProgress(callback: (progress: DownloadProgress) => void): () => void;
  onTlsProxyProgress(callback: (progress: TlsProxyProgress) => void): () => void;
  onServerDeployProgress(callback: (progress: ServerDeployProgress) => void): () => void;
  onTerminalEvent(callback: (event: TerminalEvent) => void): () => void;
  terminalInput(terminalId: string, data: string): void;
  terminalResize(terminalId: string, cols: number, rows: number): void;
  terminalClose(terminalId: string): void;
}

export interface TerminalEvent {
  terminalId: string;
  type: 'data' | 'closed' | 'error';
  data?: string;
  message?: string;
}

export interface TerminalHistory {
  shell: string;
  commands: string[];
  available: boolean;
}

export interface CertificateIssueProgress {
  taskId: string;
  status:
    'running' | 'retrying' | 'waiting-user' | 'cancelling' | 'succeeded' | 'failed' | 'cancelled';
  step: string;
  message: string;
  attempt?: number;
  dnsRecords?: Array<{ domain: string; record: string; value: string }>;
  dnsAutomation?: DnsAutomation;
  updatedAt: number;
}
export type CertificateIssueProgressUpdate = Omit<CertificateIssueProgress, 'taskId' | 'updatedAt'>;
