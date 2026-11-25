import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  serverSchema,
  instanceSchema,
  settingsSchema,
  certificateSchema,
  serverSiteSchema,
  serverCertificateSchema,
  dnsAccountSchema,
  terminalFavoriteSchema,
  type Server,
  type Instance,
  type InstalledVersion,
  type Settings,
  type CertificateRecord,
  type ServerSite,
  type ServerCertificate,
  type DnsAccount,
  type TerminalFavorite,
  type Catalog,
  type DownloadRecord,
  type SiteInspection,
  type ManagedTlsStatus,
  type WebIncludeRecord,
} from '../shared/types';
import { AppError } from '../shared/errors';

export interface CryptoProvider {
  available(): boolean;
  encrypt(value: string): Buffer;
  decrypt(value: Buffer): string;
}
interface DiskState {
  schema: 4;
  servers: Server[];
  instances: Instance[];
  versions: InstalledVersion[];
  settings: Settings;
  certificates: CertificateRecord[];
  serverSites: ServerSite[];
  serverCertificates: ServerCertificate[];
  dnsAccounts: DnsAccount[];
  terminalFavorites: TerminalFavorite[];
  secrets: Record<string, string>;
  // 版本列表缓存、断点记录、站点检查与托管实例都随 state 持久化。
  catalog: Catalog | null;
  downloads: DownloadRecord[];
  siteInspections: Record<string, SiteInspection>;
  managedTls: ManagedTlsStatus | null;
  webIncludes: Record<string, WebIncludeRecord>;
}

function emptyDiskState(): DiskState {
  return {
    schema: 4,
    servers: [],
    instances: [],
    versions: [],
    settings: settingsSchema.parse({}),
    certificates: [],
    serverSites: [],
    serverCertificates: [],
    dnsAccounts: [],
    terminalFavorites: [],
    secrets: {},
    catalog: null,
    downloads: [],
    siteInspections: {},
    managedTls: null,
    webIncludes: {},
  };
}

// 明文凭据只在会话内存在；安全存储不可用时绝不落盘。
export class Store {
  data: DiskState = emptyDiskState();
  private writes: Promise<void> = Promise.resolve();
  private sessionSecrets = new Map<string, string>();
  constructor(
    public root: string,
    private crypto: CryptoProvider,
  ) {}
  get secure() {
    return this.crypto.available();
  }
  async load() {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    try {
      const raw = JSON.parse(await readFile(path.join(this.root, 'state.json'), 'utf8'));
      if (
        ![1, 2, 3, 4].includes(raw.schema) ||
        !Array.isArray(raw.servers) ||
        !Array.isArray(raw.instances) ||
        !Array.isArray(raw.versions)
      )
        throw new Error('数据结构不正确');
      const legacySiteServers = raw.servers
        .filter((item: unknown) => !!item && typeof item === 'object' && 'reverseProxies' in item)
        .map((item: { id?: unknown }) => item.id)
        .filter((id: unknown): id is string => typeof id === 'string');
      // vhost 端口按服务器现状手填，80/443 不再强制迁移。
      raw.servers = raw.servers.map((item: unknown) => serverSchema.parse(item));
      raw.instances = raw.instances.map((item: unknown) => instanceSchema.parse(item));
      // schema 4：清除旧证书 / 规则引用 / 站点配置，全新适配双方案。
      // schema 2 及更早来自旧证书体系；schema 3 来自本机 SSL MVP，都要重置。
      const legacyCertReset = raw.schema !== 4;
      if (legacyCertReset) {
        raw.certificates = [];
        raw.serverCertificates = [];
        raw.serverSites = [];
        raw.instances = (raw.instances as Instance[]).map((instance) =>
          instance.mode === 'form'
            ? {
                ...instance,
                proxies: instance.proxies.map((rule) => ({
                  ...rule,
                  type: rule.type === 'https' ? 'http' : rule.type,
                  tlsMode: 'passthrough' as const,
                  certificateId: undefined,
                  certPath: '',
                  keyPath: '',
                  publicHttps: false,
                  siteConfig: undefined,
                  siteConfigFlavor: undefined,
                  siteConfigUpdatedAt: undefined,
                  siteConfigPath: undefined,
                })),
              }
            : instance,
        );
      }
      const rawSettings = raw.settings ?? {};
      // 旧版单服务商标识可能是已移除的选项；归一到默认的 DNSPod，避免老 state 无法加载。
      if (!['dnspod', 'aliyun', 'cloudflare'].includes(rawSettings.dnsProvider))
        rawSettings.dnsProvider = 'dnspod';
      raw.settings = settingsSchema.parse(rawSettings);
      raw.certificates = Array.isArray(raw.certificates)
        ? raw.certificates.map((item: unknown) => certificateSchema.parse(item))
        : [];
      raw.serverSites = Array.isArray(raw.serverSites)
        ? raw.serverSites.map((item: unknown) => serverSiteSchema.parse(item))
        : [];
      raw.serverCertificates = Array.isArray(raw.serverCertificates)
        ? raw.serverCertificates.map((item: unknown) => serverCertificateSchema.parse(item))
        : [];
      const supportedDnsProviders = ['dnspod', 'aliyun', 'cloudflare'];
      const legacyDnsAccounts = Array.isArray(raw.dnsAccounts)
        ? raw.dnsAccounts.filter(
            (item: unknown) =>
              !supportedDnsProviders.includes((item as { provider?: unknown })?.provider as string),
          )
        : [];
      raw.dnsAccounts = Array.isArray(raw.dnsAccounts)
        ? raw.dnsAccounts
            .filter((item: unknown) =>
              supportedDnsProviders.includes((item as { provider?: unknown })?.provider as string),
            )
            .map((item: unknown) => dnsAccountSchema.parse(item))
        : [];
      for (const account of legacyDnsAccounts as Array<{ id?: unknown }>) {
        if (typeof account?.id !== 'string') continue;
        const prefix = `dns:account:${account.id}:`;
        for (const key of Object.keys(raw.secrets ?? {}))
          if (key.startsWith(prefix)) delete raw.secrets[key];
      }
      raw.terminalFavorites = Array.isArray(raw.terminalFavorites)
        ? raw.terminalFavorites.map((item: unknown) => terminalFavoriteSchema.parse(item))
        : [];
      if (
        !raw.secrets ||
        typeof raw.secrets !== 'object' ||
        Array.isArray(raw.secrets) ||
        Object.values(raw.secrets).some((value) => typeof value !== 'string')
      )
        throw new Error('凭据结构不正确');
      const base = emptyDiskState();
      this.data = {
        ...base,
        ...raw,
        schema: 4,
        catalog: raw.catalog && typeof raw.catalog === 'object' ? (raw.catalog as Catalog) : null,
        downloads: Array.isArray(raw.downloads) ? (raw.downloads as DownloadRecord[]) : [],
        siteInspections:
          raw.siteInspections && typeof raw.siteInspections === 'object'
            ? (raw.siteInspections as Record<string, SiteInspection>)
            : {},
        managedTls:
          raw.managedTls && typeof raw.managedTls === 'object'
            ? (raw.managedTls as ManagedTlsStatus)
            : null,
        webIncludes:
          raw.webIncludes && typeof raw.webIncludes === 'object'
            ? (raw.webIncludes as Record<string, WebIncludeRecord>)
            : {},
      };
      // 清理本机旧版站点记录和其 EAB 密钥；服务器上的配置文件不触碰。
      const legacyProxySecrets = Object.keys(this.data.secrets).filter((key) =>
        /^server:[^:]+:proxy:/.test(key),
      );
      for (const key of legacyProxySecrets) delete this.data.secrets[key];
      if (legacyCertReset)
        await rm(path.join(this.root, 'certificates'), { recursive: true, force: true }).catch(
          () => {},
        );
      if (legacySiteServers.length || legacyProxySecrets.length || legacyCertReset)
        await this.persist();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
        throw new AppError(
          '配置文件无法读取，请保留 state.json 并从备份恢复，应用不会覆盖损坏数据。',
        );
    }
  }
  secret(key: string): string {
    if (this.sessionSecrets.has(key)) return this.sessionSecrets.get(key)!;
    if (!this.data.secrets[key]) return '';
    if (!this.secure) throw new AppError('系统安全存储不可用，请重新输入本次会话所需的凭据。');
    try {
      const value = this.crypto.decrypt(Buffer.from(this.data.secrets[key], 'base64'));
      this.sessionSecrets.set(key, value);
      return value;
    } catch {
      throw new AppError('凭据解密失败，请重新输入密码或令牌；原密文已保留。');
    }
  }
  putSecret(key: string, value: string | undefined) {
    if (value === undefined) return;
    this.sessionSecrets.set(key, value);
    if (this.secure) this.data.secrets[key] = this.crypto.encrypt(value).toString('base64');
    else delete this.data.secrets[key];
  }
  dropSecrets(prefix: string) {
    for (const key of Object.keys(this.data.secrets))
      if (key.startsWith(prefix)) delete this.data.secrets[key];
    for (const key of this.sessionSecrets.keys())
      if (key.startsWith(prefix)) this.sessionSecrets.delete(key);
  }
  server(id: string) {
    const item = this.data.servers.find((s) => s.id === id);
    if (!item) throw new AppError('服务器不存在。');
    return item;
  }
  instance(id: string) {
    const item = this.data.instances.find((s) => s.id === id);
    if (!item) throw new AppError('客户端实例不存在。');
    return item;
  }
  version(key: string) {
    const item = this.data.versions.find((v) => v.key === key);
    if (!item) throw new AppError('请先安装所选 FRP 版本。');
    return item;
  }
  async saveServer(input: Server) {
    const previous = this.data.servers.find((s) => s.id === input.id);
    for (const name of ['password', 'passphrase', 'token', 'rawConfig'] as const)
      this.putSecret(`server:${input.id}:${name}`, input[name]);
    // 主机指纹和部署记录仅由主进程维护，界面不能伪造信任记录。
    const item: Server = {
      ...input,
      password: undefined,
      passphrase: undefined,
      token: undefined,
      rawConfig: '',
      fingerprint: previous?.fingerprint,
      deployment: previous?.deployment,
      accessMode: previous?.accessMode ?? input.accessMode,
      discoveredService: previous?.discoveredService ?? input.discoveredService,
    };
    this.data.servers = [...this.data.servers.filter((s) => s.id !== item.id), item];
    await this.persist();
  }
  // 检索到的服务只导入客户端连接字段；密钥链不可用时令牌仅保留在当前会话。
  async saveDiscoveredServerConfig(
    id: string,
    config: { frpPort: number; httpPort: number; httpsPort: number; token: string },
    service: NonNullable<Server['discoveredService']>,
  ) {
    const server = this.server(id);
    if (server.deployment) throw new AppError('此服务器已有本机管理的部署，不能转为只读检索记录。');
    this.putSecret(`server:${id}:token`, config.token);
    server.frpPort = config.frpPort;
    // vhost 端口按探测到的现状保留：80/443 空闲时可直接占用，不再强制迁移到高端口。
    server.httpPort = config.httpPort;
    server.httpsPort = config.httpsPort;
    server.accessMode = 'readonly';
    server.discoveredService = service;
    await this.persist();
    return this.secure;
  }
  async saveInstance(item: Instance) {
    this.server(item.serverId);
    this.version(item.versionKey);
    const previous = this.data.instances.find((s) => s.id === item.id);
    this.putSecret(`instance:${item.id}:rawConfig`, item.rawConfig);
    this.data.instances = [
      ...this.data.instances.filter((s) => s.id !== item.id),
      { ...item, rawConfig: '' },
    ];
    if (previous) {
      const domainsByRule = (instance: Instance) =>
        new Map(
          instance.proxies.map((rule) => [
            rule.id,
            rule.domains.map((domain) => domain.toLowerCase()),
          ]),
        );
      const before = domainsByRule(previous);
      const after = domainsByRule(item);
      this.data.serverSites = this.data.serverSites.map((site) => {
        if (site.instanceId !== item.id) return site;
        const oldDomains = before.get(site.ruleId) ?? [];
        const newDomains = after.get(site.ruleId) ?? [];
        return oldDomains.join('\0') === newDomains.join('\0')
          ? site
          : { ...site, outOfSync: true };
      });
    }
    await this.persist();
  }
  async saveCertificate(item: CertificateRecord) {
    const parsed = certificateSchema.parse(item);
    this.data.certificates = [
      ...this.data.certificates.filter((certificate) => certificate.id !== parsed.id),
      parsed,
    ];
    await this.persist();
  }
  async saveServerSite(item: ServerSite) {
    const parsed = serverSiteSchema.parse(item);
    this.server(parsed.serverId);
    this.data.serverSites = [
      ...this.data.serverSites.filter((site) => site.id !== parsed.id),
      parsed,
    ];
    await this.persist();
  }
  async saveServerCertificate(item: ServerCertificate) {
    const parsed = serverCertificateSchema.parse(item);
    this.server(parsed.serverId);
    this.data.serverCertificates = [
      ...this.data.serverCertificates.filter((certificate) => certificate.id !== parsed.id),
      parsed,
    ];
    await this.persist();
  }
  async saveCatalog(catalog: Catalog) {
    this.data.catalog = catalog;
    await this.persist();
  }
  async saveDownload(record: DownloadRecord) {
    this.data.downloads = [
      ...this.data.downloads.filter((item) => item.key !== record.key),
      record,
    ];
    await this.persist();
  }
  async dropDownload(key: string) {
    this.data.downloads = this.data.downloads.filter((item) => item.key !== key);
    await this.persist();
  }
  async saveInspection(serverId: string, inspection: SiteInspection) {
    this.data.siteInspections = { ...this.data.siteInspections, [serverId]: inspection };
    await this.persist();
  }
  async saveManagedTls(status: ManagedTlsStatus | null) {
    this.data.managedTls = status;
    await this.persist();
  }
  async saveWebInclude(serverId: string, record: WebIncludeRecord | null) {
    const next = { ...this.data.webIncludes };
    if (record) next[serverId] = record;
    else delete next[serverId];
    this.data.webIncludes = next;
    await this.persist();
  }
  async saveTerminalFavorite(item: TerminalFavorite) {
    const parsed = terminalFavoriteSchema.parse(item);
    this.data.terminalFavorites = [
      ...this.data.terminalFavorites.filter((favorite) => favorite.id !== parsed.id),
      parsed,
    ]
      .sort((a, b) => a.order - b.order)
      .map((favorite, order) => ({ ...favorite, order }));
    await this.persist();
  }
  async deleteTerminalFavorite(id: string) {
    this.data.terminalFavorites = this.data.terminalFavorites
      .filter((favorite) => favorite.id !== id)
      .sort((a, b) => a.order - b.order)
      .map((favorite, order) => ({ ...favorite, order }));
    await this.persist();
  }
  async reorderTerminalFavorites(ids: string[]) {
    if (
      new Set(ids).size !== this.data.terminalFavorites.length ||
      ids.some((id) => !this.data.terminalFavorites.some((favorite) => favorite.id === id))
    )
      throw new AppError('快捷命令排序列表与当前记录不匹配，请刷新后重试。');
    const byId = new Map(this.data.terminalFavorites.map((favorite) => [favorite.id, favorite]));
    this.data.terminalFavorites = ids.map((id, order) => ({ ...byId.get(id)!, order }));
    await this.persist();
  }
  snapshot() {
    // 原始配置需要在编辑器内可读，磁盘上仍使用加密存储。
    return {
      servers: this.data.servers.map((s) => ({
        ...s,
        rawConfig: this.readConfig(`server:${s.id}:rawConfig`),
      })),
      instances: this.data.instances.map((s) => ({
        ...s,
        rawConfig: this.readConfig(`instance:${s.id}:rawConfig`),
      })),
      versions: this.data.versions,
      certificates: this.data.certificates,
      serverSites: this.data.serverSites,
      serverCertificates: this.data.serverCertificates,
      dnsAccounts: this.data.dnsAccounts,
      terminalFavorites: this.data.terminalFavorites,
      settings: this.data.settings,
      secureStorage: this.secure,
      platform: process.platform === 'win32' ? 'windows' : process.platform,
      arch: process.arch === 'x64' ? 'amd64' : process.arch,
      catalog: this.data.catalog,
      downloads: this.data.downloads,
      siteInspections: this.data.siteInspections,
      managedTls: this.data.managedTls,
      webIncludes: this.data.webIncludes,
    };
  }
  private readConfig(key: string) {
    try {
      return this.secret(key);
    } catch {
      return '';
    }
  }
  allSecrets() {
    return [
      ...this.sessionSecrets.values(),
      ...Object.keys(this.data.secrets).flatMap((key) => {
        try {
          return [this.secret(key)];
        } catch {
          return [];
        }
      }),
    ].filter(Boolean);
  }
  async persist() {
    // 原子替换避免退出或磁盘写入中断留下半份 JSON。
    const temporary = path.join(this.root, 'state.json.tmp');
    const content = JSON.stringify(this.data, null, 2);
    const write = this.writes.then(async () => {
      await writeFile(temporary, content, { mode: 0o600 });
      await rename(temporary, path.join(this.root, 'state.json'));
    });
    this.writes = write.catch(() => {});
    await write;
  }
}
