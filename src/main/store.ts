import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  serverSchema,
  instanceSchema,
  settingsSchema,
  certificateSchema,
  type Server,
  type Instance,
  type InstalledVersion,
  type Settings,
  type CertificateRecord,
} from '../shared/types';
import { AppError } from '../shared/errors';

export interface CryptoProvider {
  available(): boolean;
  encrypt(value: string): Buffer;
  decrypt(value: Buffer): string;
}
interface DiskState {
  schema: 1;
  servers: Server[];
  instances: Instance[];
  versions: InstalledVersion[];
  settings: Settings;
  certificates: CertificateRecord[];
  secrets: Record<string, string>;
}

// 明文凭据只在会话内存在；安全存储不可用时绝不落盘。
export class Store {
  data: DiskState = {
    schema: 1,
    servers: [],
    instances: [],
    versions: [],
    settings: { proxyUrl: '' },
    certificates: [],
    secrets: {},
  };
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
        raw.schema !== 1 ||
        !Array.isArray(raw.servers) ||
        !Array.isArray(raw.instances) ||
        !Array.isArray(raw.versions)
      )
        throw new Error('数据结构不正确');
      const legacySiteServers = raw.servers
        .filter((item: unknown) => !!item && typeof item === 'object' && 'reverseProxies' in item)
        .map((item: { id?: unknown }) => item.id)
        .filter((id: unknown): id is string => typeof id === 'string');
      raw.servers = raw.servers.map((item: unknown) => serverSchema.parse(item));
      raw.instances = raw.instances.map((item: unknown) => instanceSchema.parse(item));
      raw.settings = settingsSchema.parse(raw.settings);
      raw.certificates = Array.isArray(raw.certificates)
        ? raw.certificates.map((item: unknown) => certificateSchema.parse(item))
        : [];
      if (
        !raw.secrets ||
        typeof raw.secrets !== 'object' ||
        Array.isArray(raw.secrets) ||
        Object.values(raw.secrets).some((value) => typeof value !== 'string')
      )
        throw new Error('凭据结构不正确');
      this.data = raw;
      // 清理本机旧版站点记录和其 EAB 密钥；服务器上的配置文件不触碰。
      const legacyProxySecrets = Object.keys(this.data.secrets).filter((key) =>
        /^server:[^:]+:proxy:/.test(key),
      );
      for (const key of legacyProxySecrets) delete this.data.secrets[key];
      if (legacySiteServers.length || legacyProxySecrets.length) await this.persist();
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
    };
    this.data.servers = [...this.data.servers.filter((s) => s.id !== item.id), item];
    await this.persist();
  }
  async saveInstance(item: Instance) {
    this.server(item.serverId);
    this.version(item.versionKey);
    this.putSecret(`instance:${item.id}:rawConfig`, item.rawConfig);
    this.data.instances = [
      ...this.data.instances.filter((s) => s.id !== item.id),
      { ...item, rawConfig: '' },
    ];
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
      settings: this.data.settings,
      secureStorage: this.secure,
      platform: process.platform === 'win32' ? 'windows' : process.platform,
      arch: process.arch === 'x64' ? 'amd64' : process.arch,
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
