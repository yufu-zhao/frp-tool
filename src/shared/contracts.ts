import type {
  DeployLevel,
  DnsAutomation,
  SiteInspection,
  ServerCertificate,
  ManagedTlsStatus,
  Catalog,
  InstalledVersion,
  VersionResolution,
  DnsProviderId,
  FrpsServiceCandidate,
  WebIncludeFlavor,
} from './types';

// 新增 IPC action 的单一事实源。主进程注册与渲染层调用都从这里取名字。
export const ACTIONS = {
  // 服务端证书
  certificateInspect: 'certificate:inspect',
  certificateIssueServer: 'certificate:issue-server',
  certificateDeploy: 'certificate:deploy',
  certificateRefreshEnv: 'certificate:refresh-env',
  certificateRenewNow: 'certificate:renew-now',
  certificateDnsTest: 'certificate:dns-test',
  certificateChallengeResponse: 'certificate:challenge-response',
  certificateCancel: 'certificate:cancel',
  certificateReadPem: 'certificate:read-pem',
  certificateDetail: 'certificate:detail',
  certificateDelete: 'certificate:delete',
  certificateImportPem: 'certificate:import-pem',
  // 托管 TLS 实例
  tlsProxyStatus: 'tls-proxy:status',
  tlsProxyInstall: 'tls-proxy:install',
  tlsProxyStart: 'tls-proxy:start',
  tlsProxyStop: 'tls-proxy:stop',
  tlsProxyYield: 'tls-proxy:yield',
  tlsProxyUninstall: 'tls-proxy:uninstall',
  // 版本库
  versionCatalog: 'version:catalog',
  versionCatalogCached: 'version:catalog-cached',
  versionInstall: 'version:install',
  versionDownloadCancel: 'version:download-cancel',
  versionDownloadRetry: 'version:download-retry',
  // 使用点自动解析与自动准备包（服务端安装 / 创建客户端）
  versionResolve: 'version:resolve',
  versionEnsure: 'version:ensure',
  // 服务端安装：预检与已有服务的移除（检索结果内置到安装流程，不再单独驻留页面）
  serverInstallPrecheck: 'server:install-precheck',
  serverRemoveExisting: 'server:remove-existing',
  serverAutostart: 'server:autostart',
  // Web 服务 include 注入与站点配置落盘
  webIncludeInspect: 'web-include:inspect',
  webIncludeApply: 'web-include:apply',
  webIncludeRemove: 'web-include:remove',
  siteConfigSave: 'site-config:save',
  siteConfigRead: 'site-config:read',
  certificateRemove: 'certificate:remove',
  tlsPlan: 'tls:plan',
  // 设置
  settingsSave: 'settings:save',
  // DNS 账户管理
  dnsAccountSave: 'dns-account:save',
  dnsAccountDelete: 'dns-account:delete',
  dnsAccountTest: 'dns-account:test',
  dnsAccountMasked: 'dns-account:masked',
  acmeMasked: 'acme:masked',
  // DNS 管理：域名与解析记录
  dnsDomains: 'dns:domains',
  dnsRecords: 'dns:records',
  dnsRecordSave: 'dns:record-save',
  dnsRecordDelete: 'dns:record-delete',
} as const;

export const EVENTS = {
  stateChanged: 'state:changed',
  certificateProgress: 'certificate:progress',
  downloadProgress: 'download:progress',
  tlsProxyProgress: 'tls-proxy:progress',
  serverDeployProgress: 'server:deploy-progress',
  terminalEvent: 'terminal:event',
} as const;

export interface IssueServerInput {
  taskId: string;
  serverId: string;
  name: string;
  domains: string[];
  provider: 'letsencrypt' | 'litessl';
  email: string;
  challenge: 'http-01' | 'dns-01';
  dnsAutomation?: DnsAutomation;
  dnsAccountId?: string;
  /** HTTP-01 时承载 challenge 转发的表单模式客户端实例。 */
  httpInstanceId?: string;
  certTarget?: 'local' | 'server';
  localCertificateId?: string;
  termsAgreed: boolean;
  eabKid?: string;
  eabHmac?: string;
  /** RSA 密钥长度，仅 RSA 签发有效；缺省 2048。 */
  keySize?: 2048 | 3072 | 4096;
  /** 关联的规则 ID：方案 A 下证书要写入该规则对应的 server 块。 */
  ruleId?: string;
}
/** 从服务器托管目录读取到的真实站点配置。 */
export interface SiteConfigReadResult {
  path: string;
  content: string;
  /** false 表示服务器上还没有该规则的配置文件，content 可以是本地生成的模板。 */
  exists: boolean;
  flavor: WebIncludeFlavor;
}

export interface DeployInput {
  certificateId: string;
  level: DeployLevel;
  target?: string;
  confirmed: boolean;
}
/**
 * 安装预检同样通过 taskId 把「检查端口 / 检索已有服务 / 检查目录」上报到安装步骤窗口，
 * 避免 SSH 扫描期间界面静默无反馈。
 */
export interface ServerInstallPrecheckInput {
  id: string;
  taskId?: string;
}
/** 服务端安装：taskId 由渲染层生成，便于点击瞬间就本地 seed 进度窗口。 */
export interface ServerDeployInput {
  id: string;
  key: string;
  taskId?: string;
  confirmed?: boolean;
  // 预检发现安装目录已有程序且用户确认覆盖时置 true，否则部署会拒绝覆盖。
  overwrite?: boolean;
}
/** 移除检索到的已有 FRP 服务：停服务、禁开机、备份程序与配置、删服务单元。 */
export interface RemoveExistingInput {
  id: string;
  service: FrpsServiceCandidate;
  confirmed?: boolean;
}
export interface DnsTestInput {
  provider: string;
  // 兼容旧调用方；凭据测试不再依赖具体域名（Cloudflare 改用 token verify）。
  domain?: string;
  secretId?: string;
  secretKey?: string;
  token?: string;
  endpoint?: string;
}
/** 新建或编辑 DNS 账户；留空的凭据表示沿用已保存值（编辑时）。 */
export interface DnsAccountInput {
  id?: string;
  name: string;
  provider: DnsProviderId;
  secretId?: string;
  secretKey?: string;
  token?: string;
  endpoint?: string;
}
export type DnsAccountTestInput = DnsAccountInput;

/** DNS 管理：域名与解析记录的数据模型（主进程与渲染层共用）。 */
export interface ManagedDnsDomain {
  /** 主域名，如 example.com。 */
  name: string;
}
export interface ManagedDnsRecord {
  id: string;
  /** 完整记录名（含主域），如 www.example.com；@ 开头表示主域名。 */
  name: string;
  type: string;
  value: string;
  ttl: number;
  /** DNSPod / 阿里云的解析线路，Cloudflare 缺省。 */
  line?: string;
  /** MX 优先级，仅 MX 记录有意义。 */
  priority?: number;
  /** Cloudflare 的代理状态。 */
  proxied?: boolean;
}
export interface ManagedDnsRecordInput {
  /** 完整记录名（含主域）。适配器会转换成各家的 sub_domain / RR / name。 */
  name: string;
  type: string;
  value: string;
  ttl: number;
  line?: string;
  priority?: number;
  proxied?: boolean;
}

/** DNS 管理通用入参：账户决定服务商与凭据，域名与记录由界面传入。 */
/** 证书详情：内容 + 实际存放路径；密钥只在明确打开详情时读取。 */
export interface CertificateDetail {
  id: string;
  storage: 'server' | 'local';
  certPath: string;
  keyPath: string;
  configPath?: string;
  certPem: string;
  keyPem: string;
}
/** 已保存凭据的脱敏回显，只用于输入框 placeholder，不含完整值。 */
export interface MaskedCredentials {
  [field: string]: string;
}

export interface DnsDomainQuery {
  accountId: string;
  provider: DnsProviderId;
}
export interface DnsRecordQuery extends DnsDomainQuery {
  domain: string;
}
export interface DnsRecordSaveInput extends DnsRecordQuery {
  recordId?: string;
  name: string;
  type: string;
  value: string;
  ttl: number;
  line?: string;
  priority?: number;
  proxied?: boolean;
}
export interface DnsRecordDeleteInput extends DnsRecordQuery {
  recordId: string;
}
export interface TlsProxyInput {
  taskId: string;
  serverId: string;
  confirmed?: boolean;
}
export interface CatalogInput {
  page?: number;
  force?: boolean;
}
export interface VersionInstallInput {
  taskId: string;
  version: string;
  platform: 'darwin' | 'windows' | 'linux';
  arch: 'amd64' | 'arm64';
  url?: string;
  localPath?: string;
  digest?: string;
}

export type VersionPurpose = 'server' | 'client';
export type VersionPlatform = 'darwin' | 'windows' | 'linux';
export type VersionArch = 'amd64' | 'arm64';

/** 只解析目标版本与架构，不下载、不联网。platform / arch 允许传探测原始值，由主进程归一化校验。 */
export interface ResolveVersionInput {
  purpose: VersionPurpose;
  serverId?: string;
  version?: string;
  platform?: string;
  arch?: string;
}

/**
 * 确保目标版本在本机可用：命中已安装则直接复用，否则自动下载 + 校验 + 解包。
 * 全程通过 download:progress 上报进度，任务中心据此常驻展示。
 */
export interface EnsureVersionInput extends ResolveVersionInput {
  taskId: string;
  /** 缓存列表缺失时允许联网取一次官方列表（由用户主动发起的安装动作触发）。 */
  refreshCatalog?: boolean;
  /** 渲染层已就「未取得官方 SHA256」确认过，主进程不再弹原生框。 */
  confirmed?: boolean;
}
export interface EnsureVersionResult {
  resolution: VersionResolution;
  version: InstalledVersion;
  /** true：本次下载并安装了新包；false：直接复用本机已有包。 */
  prepared: boolean;
}
/** 官方 SHA256 未取得时抛出此 code，由渲染层弹确认后带 confirmed 重试。 */
export const CHECKSUM_UNAVAILABLE = 'CHECKSUM_UNAVAILABLE';
/** 渲染层保存的「重试参数」：不含任务标识与确认标记。 */
export type EnsureVersionArgs = Omit<EnsureVersionInput, 'taskId' | 'confirmed' | 'refreshCatalog'>;
export interface SettingsInput {
  proxyUrl?: string;
  dnsProvider?: 'dnspod' | 'aliyun' | 'cloudflare';
  deployDefault?: 'manual' | 'auto';
  catalogCacheHours?: number;
  downloadRetries?: number;
  managedTlsEnabled?: boolean;
  confirmDangerous?: boolean;
  theme?: 'light' | 'dark' | 'system';
  dnsCredentials?: Record<string, string>;
  acmeEmail?: string;
  eabKid?: string;
  eabHmac?: string;
}

export interface TlsPlanInput {
  serverId: string;
}
export interface ServerCertificateView {
  certificate: ServerCertificate;
  inspection: SiteInspection | null;
  tlsProxy: ManagedTlsStatus | null;
}
export interface VersionCatalogView {
  catalog: Catalog | null;
  refreshed: boolean;
}
