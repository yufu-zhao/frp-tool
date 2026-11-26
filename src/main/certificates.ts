import { mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  X509Certificate,
} from 'node:crypto';
import acme from 'acme-client';
import { AppError, redact } from '../shared/errors';
import type { CertificateIssueProgress, CertificateRecord, DnsAutomation } from '../shared/types';
import { certificateSchema } from '../shared/types';
import { Store } from './store';

export interface DnsChallengeRecord {
  domain: string;
  record: string;
  value: string;
}

export interface HttpChallengeResponder {
  port: number;
  set(token: string, value: string): void;
  remove(token: string): void;
}

// 引擎内部的响应器：远程临时响应器需要把 token 写到服务端，set/remove 允许异步。
// 同步响应器（本机 frpc 机制）天然可赋值给此类型，故旧路径无需改动。
export interface AcmeHttpResponder {
  port: number;
  set(token: string, value: string): void | Promise<void>;
  remove(token: string): void | Promise<void>;
}

export interface HttpChallengeAssignment {
  instanceId: string;
  domains: string[];
}

export interface IssueCertificateInput {
  name: string;
  domains: string[];
  provider: 'letsencrypt' | 'litessl';
  email: string;
  challenge: 'http-01' | 'dns-01';
  termsAgreed: boolean;
  eabKid?: string;
  eabHmac?: string;
  keySize?: 2048 | 3072 | 4096;
}

export type CertificateIssueProgressUpdate = Omit<CertificateIssueProgress, 'taskId' | 'updatedAt'>;

export interface CertificateIssueHooks {
  taskId: string;
  signal: AbortSignal;
  onProgress(progress: CertificateIssueProgressUpdate): void;
  promptDnsChallenge?(records: DnsChallengeRecord[]): Promise<boolean>;
}

export type HttpChallengeRunner = <T>(
  assignments: HttpChallengeAssignment[],
  operation: (responder: HttpChallengeResponder) => Promise<T>,
  signal?: AbortSignal,
) => Promise<T>;

// ─────────────────────────── 通用工具 ───────────────────────────

export function throwIfCancelled(signal?: AbortSignal) {
  if (signal?.aborted) throw new AppError('用户已取消证书签发。', 'CANCELLED');
}

export function abortable<T>(operation: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return operation;
  throwIfCancelled(signal);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new AppError('用户已取消证书签发。', 'CANCELLED'));
    signal.addEventListener('abort', onAbort, { once: true });
    operation.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

function waitForRetry(delay: number, signal?: AbortSignal) {
  return abortable(new Promise<void>((resolve) => setTimeout(resolve, delay)), signal);
}

/** 用 EAB 凭据生成账户绑定指纹；凭据变化即代表 CA 侧需要重新注册账户。 */
function eabHash(kid: string, hmacKey: string): string {
  return createHash('sha256').update(kid.trim()).update('\0').update(hmacKey.trim()).digest('hex');
}

export function normalizeDomains(values: string[]): string[] {
  const result: string[] = [];
  for (const value of values) {
    const domain = value.trim().toLowerCase().replace(/\.$/, '');
    if (!domain || domain.length > 253 || /[\s/:*]/.test(domain) || !domain.includes('.'))
      throw new AppError(`域名格式无效：${value}`);
    if (
      !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
        domain,
      )
    )
      throw new AppError(`域名格式无效：${value}`);
    if (!result.includes(domain)) result.push(domain);
  }
  if (!result.length) throw new AppError('请至少填写一个域名。');
  if (result.length > 100) throw new AppError('一次最多处理 100 个域名。');
  return result;
}

export function validateCertificateMaterial(certPem: string, keyPem: string, domains: string[]) {
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(certPem);
    const privateKey = createPrivateKey(keyPem);
    const certificatePublicKey = certificate.publicKey.export({ type: 'spki', format: 'der' });
    const privatePublicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
    if (!Buffer.from(certificatePublicKey).equals(Buffer.from(privatePublicKey)))
      throw new AppError('证书与私钥不匹配。');
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(
      `无法读取证书或私钥 PEM：${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (Date.parse(certificate.validTo) <= Date.now()) throw new AppError('证书已经过期。');
  for (const domain of domains)
    if (!certificate.checkHost(domain)) throw new AppError(`证书不包含域名 ${domain}。`);
  return certificate;
}

// ───────────────────── 签发引擎（与存储位置解耦） ─────────────────────
// 只负责「向 CA 申请并校验证书材料」，返回 PEM，不落盘、不写 store。
// 签发引擎由服务端证书库（ServerCertificates）使用；本机证书库仅保留为历史数据兼容，
// 差别只在把材料写到哪里、写哪张记录。

export interface AcmeMaterial {
  certPem: string;
  keyPem: string;
  certificate: X509Certificate;
}

export interface AcmeChallengeHooks {
  // dns-01：自动放置 TXT（A1/A2/A3）。不提供时引擎回退到手动弹窗（A4）。
  createDnsRecord?(record: DnsChallengeRecord): Promise<void>;
  // dns-01：验证结束后清理 TXT（A1/A2/A3）。
  removeDnsRecord?(record: DnsChallengeRecord): Promise<void>;
  // dns-01：手动兜底弹窗（A4）。优先用 hooks.promptDnsChallenge。
  promptDnsChallenge?(records: DnsChallengeRecord[]): Promise<boolean>;
  // http-01：用临时响应器包裹整个 ACME auto 调用；实现方须在 finally 立即释放。
  withHttpResponder?<T>(
    operation: (responder: AcmeHttpResponder) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T>;
  // 覆盖 acme-client 的本地预校验（远程响应器 / DNS 解析未就绪时置 true）。
  skipChallengeVerification?: boolean;
  // 当前 DNS-01 自动化级别，仅用于进度回显。
  dnsAutomation?: DnsAutomation;
}

interface AcmeErrorContext {
  url?: string;
  status?: number;
  type?: string;
}

function installCancelableTransport(
  acmeClient: typeof acme,
  hooks: CertificateIssueHooks | undefined,
  currentStep: () => string,
  errorContext?: AcmeErrorContext,
): () => void {
  const library = acmeClient as any;
  const axios = library.axios;
  const signal = hooks?.signal;
  if (!axios || !signal) return () => {};
  const originalRequest = axios.request;
  const retrySettings = axios.defaults?.acmeSettings;
  const originalRetryCount = retrySettings?.retryMaxAttempts;
  if (retrySettings) retrySettings.retryMaxAttempts = 0;
  axios.request = async function (this: unknown, config: Record<string, unknown>) {
    let attempt = 0;
    while (true) {
      throwIfCancelled(signal);
      try {
        const response = await originalRequest.call(this, { ...config, signal });
        // acme-client 把 4xx 当普通响应处理，这里记录失败的 ACME 端点，便于区分
        // 账户注册（EAB）失败与订单/验证失败，两者错误文案可能完全相同。
        const data = (response as { data?: { type?: unknown } } | undefined)?.data;
        const status = (response as { status?: number } | undefined)?.status;
        if (errorContext && status && status >= 400 && typeof data?.type === 'string') {
          errorContext.url = String(config.url ?? '');
          errorContext.status = status;
          errorContext.type = data.type;
        }
        return response;
      } catch (error) {
        throwIfCancelled(signal);
        const response = (error as { response?: { status?: number } }).response;
        const code = (error as { code?: string }).code;
        const retryable =
          code !== 'ECONNABORTED' &&
          code !== 'ERR_NOCK_NO_MATCH' &&
          (!response || response.status === 429 || (response.status ?? 0) >= 500);
        if (!retryable || attempt >= 4) throw error;
        attempt += 1;
        const detail = error instanceof Error ? error.message : String(error);
        hooks?.onProgress({
          status: 'retrying',
          step: currentStep(),
          attempt,
          message: `请求失败，${Math.min(attempt * 2, 8)} 秒后重试（${attempt}/4）：${detail.slice(0, 240)}`,
        });
        await waitForRetry(Math.min(attempt * 2000, 8000), signal);
      }
    }
  };
  return () => {
    axios.request = originalRequest;
    if (retrySettings) retrySettings.retryMaxAttempts = originalRetryCount;
  };
}

export async function issueAcmeMaterial(
  store: Store,
  input: IssueCertificateInput,
  hooks: CertificateIssueHooks | undefined,
  challenge: AcmeChallengeHooks,
  acmeClient: typeof acme = acme,
): Promise<AcmeMaterial> {
  const domains = normalizeDomains(input.domains);
  if (!input.termsAgreed) throw new AppError('请先确认已阅读并同意所选证书机构的服务条款。');
  if (input.eabKid && !input.eabHmac)
    throw new AppError('填写 EAB KID 后还需要填写 EAB HMAC 密钥。');
  const signal = hooks?.signal;
  const progress = (value: CertificateIssueProgressUpdate) => hooks?.onProgress(value);
  let currentStep = '准备签发';
  const acmeError: AcmeErrorContext = {};
  try {
    throwIfCancelled(signal);
    currentStep = '准备 ACME 账户';
    progress({ status: 'running', step: currentStep, message: '正在准备 ACME 账户密钥。' });
    if (input.eabKid) store.putSecret(`acme:${input.provider}:eabKid`, input.eabKid);
    if (input.eabHmac) store.putSecret(`acme:${input.provider}:eabHmac`, input.eabHmac);
    const kid = input.eabKid || store.secret(`acme:${input.provider}:eabKid`);
    const hmacKey = input.eabHmac || store.secret(`acme:${input.provider}:eabHmac`);
    if (input.provider === 'litessl' && !(kid && hmacKey))
      throw new AppError('LiteSSL 要求 EAB，请先在设置中填写 EAB KID 与 HMAC。');
    // ACME 账户必须与 EAB 绑定：EAB 变更后旧账户在 CA 侧仍未授权，必须换密钥重新注册，
    // 否则 CA 会在下单/验证阶段报 "The client lacks sufficient authorization"。
    const eabFingerprint = kid && hmacKey ? eabHash(kid, hmacKey) : '';
    const accountKeyId = `acme:${input.provider}:accountKey`;
    const accountEabId = `acme:${input.provider}:accountKeyEab`;
    let accountKey = store.secret(accountKeyId);
    if (accountKey && store.secret(accountEabId) !== eabFingerprint) accountKey = '';
    if (!accountKey) {
      accountKey = (await acmeClient.crypto.createPrivateEcdsaKey()).toString();
      progress({
        status: 'running',
        step: currentStep,
        message: 'EAB 已变更，正在注册新的 ACME 账户。',
      });
    }
    store.putSecret(accountKeyId, accountKey);
    store.putSecret(accountEabId, eabFingerprint);
    await store.persist();
    const directoryUrl =
      input.provider === 'letsencrypt'
        ? acmeClient.directory.letsencrypt.production
        : 'https://acme.litessl.com/acme/v2/directory';
    currentStep = '生成私钥与 CSR';
    progress({
      status: 'running',
      step: currentStep,
      message: `正在为 ${domains.length} 个域名生成 SAN 申请。`,
    });
    // acme-client 的 createCsr 内部按 keySize 生成 RSA 私钥；默认保持 2048。
    const [certificateKey, csr] = await acmeClient.crypto.createCsr({
      altNames: domains,
      keySize: input.keySize ?? 2048,
    });
    throwIfCancelled(signal);
    const client = new acmeClient.Client({
      directoryUrl,
      accountKey,
      ...(kid && hmacKey ? { externalAccountBinding: { kid, hmacKey } } : {}),
    });
    const cleanupTransport = installCancelableTransport(
      acmeClient,
      hooks,
      () => currentStep,
      acmeError,
    );
    let dnsPrompt = Promise.resolve();
    const dnsRecords = new Map<string, DnsChallengeRecord>();
    const originalLogger = (acmeClient as any).setLogger;
    if (typeof originalLogger === 'function')
      originalLogger((line: string) => {
        const detail = String(line).slice(0, 400);
        const retry = /retry(?:ing)?|backoff|attempt\s*#/i.test(detail);
        if (retry) {
          progress({ status: 'retrying', step: currentStep, message: detail });
        } else if (/placing new certificate order/i.test(detail)) {
          currentStep = '提交证书订单';
          progress({
            status: 'running',
            step: currentStep,
            message: '正在向证书机构提交域名订单。',
          });
        } else if (/checking account|registering account/i.test(detail)) {
          currentStep = '注册 ACME 账户';
          progress({
            status: 'running',
            step: currentStep,
            message: '正在验证或注册 ACME 账户。',
          });
        }
      });
    const operation = async (responder?: AcmeHttpResponder): Promise<string> => {
      throwIfCancelled(signal);
      currentStep = '连接证书机构';
      progress({
        status: 'running',
        step: currentStep,
        message: `正在连接 ${input.provider === 'letsencrypt' ? 'Let’s Encrypt' : 'LiteSSL'}。`,
      });
      return client.auto({
        csr,
        email: input.email,
        termsOfServiceAgreed: input.termsAgreed,
        challengePriority: [input.challenge],
        skipChallengeVerification:
          challenge.skipChallengeVerification ?? input.challenge === 'dns-01',
        challengeCreateFn: async (authorization, acmeChallenge, keyAuthorization) => {
          if (acmeChallenge.type === 'http-01') {
            throwIfCancelled(signal);
            if (!responder) throw new AppError('HTTP-01 验证代理未启动。');
            currentStep = `配置 HTTP-01：${authorization.identifier.value}`;
            progress({
              status: 'running',
              step: currentStep,
              message: '正在通过临时验证通道提供域名验证响应。',
              dnsAutomation: challenge.dnsAutomation,
            });
            await Promise.resolve(responder.set(acmeChallenge.token, keyAuthorization));
          } else if (acmeChallenge.type === 'dns-01') {
            const record: DnsChallengeRecord = {
              domain: authorization.identifier.value,
              record: `_acme-challenge.${authorization.identifier.value}`,
              value: keyAuthorization,
            };
            dnsRecords.set(acmeChallenge.token, record);
            dnsPrompt = dnsPrompt.then(async () => {
              if (challenge.createDnsRecord) {
                currentStep = `写入 DNS-01：${record.domain}`;
                progress({
                  status: 'running',
                  step: currentStep,
                  message: '正在自动写入 TXT 记录。',
                  dnsAutomation: challenge.dnsAutomation,
                });
                await abortable(challenge.createDnsRecord!(record), signal);
              } else {
                currentStep = `等待 DNS-01：${record.domain}`;
                progress({
                  status: 'waiting-user',
                  step: currentStep,
                  message: '请添加 TXT 记录；添加完成后点击“已添加，继续验证”。',
                  dnsRecords: [record],
                  dnsAutomation: challenge.dnsAutomation,
                });
                const prompt = hooks?.promptDnsChallenge ?? challenge.promptDnsChallenge;
                if (!prompt) throw new AppError('DNS-01 缺少 TXT 记录处理逻辑。');
                if (!(await abortable(prompt([record]), signal)))
                  throw new AppError('用户取消了 DNS-01 验证。');
              }
            });
            await dnsPrompt;
            throwIfCancelled(signal);
            currentStep = `等待 CA 验证：${record.domain}`;
            progress({
              status: 'running',
              step: currentStep,
              message: 'TXT 已就绪，正在等待证书机构查询 DNS 并验证。',
              dnsAutomation: challenge.dnsAutomation,
            });
          } else throw new AppError('ACME 服务返回了未支持的验证方式。');
        },
        challengeRemoveFn: async (_authorization, acmeChallenge) => {
          if (acmeChallenge.type === 'http-01') {
            await Promise.resolve(responder?.remove(acmeChallenge.token));
          } else if (acmeChallenge.type === 'dns-01') {
            const record = dnsRecords.get(acmeChallenge.token);
            if (record && challenge.removeDnsRecord)
              await challenge.removeDnsRecord(record).catch(() => {});
            dnsRecords.delete(acmeChallenge.token);
          }
        },
      });
    };
    let certPem: string;
    try {
      if (input.challenge === 'http-01') {
        if (!challenge.withHttpResponder)
          throw new AppError('HTTP-01 需要临时验证通道（响应器或现有反代链路）。');
        currentStep = '准备 HTTP-01 临时通道';
        progress({
          status: 'running',
          step: currentStep,
          message: '正在启动临时验证通道并等待其就绪。',
        });
        certPem = await challenge.withHttpResponder((responder) => operation(responder), signal);
      } else {
        certPem = await operation();
      }
    } finally {
      cleanupTransport();
      if (typeof originalLogger === 'function') originalLogger(() => {});
    }
    throwIfCancelled(signal);
    currentStep = '校验证书与域名';
    progress({
      status: 'running',
      step: currentStep,
      message: '正在校验证书有效期、SAN 域名和私钥匹配。',
    });
    const certificate = validateCertificateMaterial(certPem, certificateKey.toString(), domains);
    if (certPem.length > 1024 * 1024) throw new AppError('签发机构返回的证书文件超过 1 MB。');
    return { certPem, keyPem: certificateKey.toString(), certificate };
  } catch (error) {
    if (signal?.aborted) throw new AppError('用户已取消证书签发。', 'CANCELLED');
    const detail = redact(
      error instanceof Error ? error.message : String(error),
      store.allSecrets(),
    ).slice(0, 1200);
    let endpoint = '';
    try {
      endpoint = acmeError.url ? new URL(acmeError.url).pathname : '';
    } catch {
      endpoint = '';
    }
    const context = [
      endpoint && `ACME 端点 ${endpoint}`,
      acmeError.type && `错误类型 ${acmeError.type}`,
    ]
      .filter(Boolean)
      .join('，');
    const hint =
      input.provider === 'litessl' && endpoint.includes('new-account')
        ? '；请确认 EAB KID/HMAC 与 LiteSSL 控制台一致，若已更换 EAB 程序会自动重建账户'
        : '';
    throw new AppError(`${detail}${context ? `（${context}）` : ''}${hint}`);
  }
}

// ───── 本机证书库：仅为历史数据兼容与签发引擎回归测试保留，运行时不再实例化 ─────
export class Certificates {
  private readonly directory: string;
  private issuing = new Set<string>();
  private activeTask?: string;

  constructor(
    private readonly store: Store,
    private readonly changed: () => void,
    private readonly promptDnsChallenge: (records: DnsChallengeRecord[]) => Promise<boolean>,
    private readonly runHttpChallenge: HttpChallengeRunner,
    private readonly isInstanceRunning: (id: string) => boolean,
    private readonly acmeClient = acme,
  ) {
    this.directory = path.join(store.root, 'certificates');
  }

  /** 本机证书库的证书与私钥落点，供证书详情展示。 */
  pathFor(id: string) {
    const directory = path.join(this.directory, id);
    return {
      directory,
      certPath: path.join(directory, 'fullchain.pem'),
      keyPath: path.join(directory, 'private-key.pem'),
    };
  }

  private async saveMaterial(
    id: string,
    certPem: string,
    keyPem: string,
    existing?: CertificateRecord,
    metadata?: Partial<CertificateRecord>,
  ) {
    const paths = this.pathFor(id);
    const certTmp = `${paths.certPath}.tmp`;
    const keyTmp = `${paths.keyPath}.tmp`;
    const certificate = new X509Certificate(certPem);
    const runningReferences = this.store.data.instances
      .filter(
        (instance) =>
          this.isInstanceRunning(instance.id) &&
          instance.proxies.some((rule) => rule.certificateId === id),
      )
      .map((instance) => instance.id);
    const record = certificateSchema.parse({
      id,
      name: existing?.name ?? '证书',
      provider: existing?.provider ?? 'manual',
      domains: metadata?.domains ?? existing?.domains,
      email: metadata?.email ?? existing?.email,
      certPath: paths.certPath,
      keyPath: paths.keyPath,
      expiresAt: new Date(certificate.validTo).toISOString(),
      autoRenew: existing?.autoRenew ?? false,
      challenge: existing?.challenge,
      createdAt: existing?.createdAt ?? Date.now(),
      ...metadata,
      pendingRestartInstances: [
        ...new Set([...(existing?.pendingRestartInstances ?? []), ...runningReferences]),
      ],
      pendingRestart:
        Boolean(existing?.pendingRestart) ||
        (existing?.pendingRestartInstances ?? []).length > 0 ||
        runningReferences.length > 0,
    });
    validateCertificateMaterial(certPem, keyPem, record.domains);
    await mkdir(paths.directory, { recursive: true, mode: 0o700 });
    const oldCert = await readFile(paths.certPath).catch(() => undefined);
    const oldKey = await readFile(paths.keyPath).catch(() => undefined);
    try {
      await writeFile(certTmp, certPem, { mode: 0o600 });
      await writeFile(keyTmp, keyPem, { mode: 0o600 });
      await rename(certTmp, paths.certPath);
      await rename(keyTmp, paths.keyPath);
    } catch (error) {
      await Promise.all([
        oldCert
          ? writeFile(paths.certPath, oldCert, { mode: 0o600 })
          : rm(paths.certPath, { force: true }),
        oldKey
          ? writeFile(paths.keyPath, oldKey, { mode: 0o600 })
          : rm(paths.keyPath, { force: true }),
      ]).catch(() => {});
      throw error;
    } finally {
      await Promise.all([rm(certTmp, { force: true }), rm(keyTmp, { force: true })]);
    }
    return record;
  }

  async importManual(input: {
    name: string;
    domains: string[];
    certificatePath: string;
    privateKeyPath: string;
  }) {
    const domains = normalizeDomains(input.domains);
    const [certStats, keyStats] = await Promise.all([
      stat(input.certificatePath),
      stat(input.privateKeyPath),
    ]);
    if (certStats.size > 1024 * 1024 || keyStats.size > 1024 * 1024)
      throw new AppError('证书或私钥文件超过 1 MB。');
    const [certPem, keyPem] = await Promise.all([
      readFile(input.certificatePath, 'utf8'),
      readFile(input.privateKeyPath, 'utf8'),
    ]);
    const certificate = validateCertificateMaterial(certPem, keyPem, domains);
    const id = randomUUID();
    const record = await this.saveMaterial(id, certPem, keyPem, undefined, {
      name: input.name.trim() || domains[0],
      domains,
      provider: 'manual',
      expiresAt: new Date(certificate.validTo).toISOString(),
    });
    await this.store.saveCertificate(record);
    this.changed();
    return record;
  }

  /** 直接粘贴 KEY / PEM 文本导入本机证书库；域名与材料一致性由 validateCertificateMaterial 校验。 */
  async importPemText(input: { name: string; domains: string[]; certPem: string; keyPem: string }) {
    const domains = normalizeDomains(input.domains);
    const certPem = input.certPem.trim();
    const keyPem = input.keyPem.trim();
    if (certPem.length > 1024 * 1024 || keyPem.length > 1024 * 1024)
      throw new AppError('证书或私钥内容超过 1 MB。');
    const certificate = validateCertificateMaterial(certPem, keyPem, domains);
    const id = randomUUID();
    const record = await this.saveMaterial(id, certPem, keyPem, undefined, {
      name: input.name.trim() || domains[0],
      domains,
      provider: 'manual',
      expiresAt: new Date(certificate.validTo).toISOString(),
    });
    await this.store.saveCertificate(record);
    this.changed();
    return record;
  }

  /** 读取本机证书 PEM 内容，供规则 SSL 面板回填文本框。 */
  async readPem(id: string): Promise<{ certPem: string; keyPem: string }> {
    const record = this.store.data.certificates.find((item) => item.id === id);
    if (!record) throw new AppError('证书不存在或已被删除。');
    const [certPem, keyPem] = await Promise.all([
      readFile(record.certPath, 'utf8'),
      readFile(record.keyPath, 'utf8'),
    ]);
    return { certPem, keyPem };
  }

  /** 供服务端证书签发流程复用：把 ACME 材料落到本机证书库，供 frpc https2http 引用。 */
  async saveIssued(
    input: {
      id?: string;
      name: string;
      domains: string[];
      provider: 'letsencrypt' | 'litessl';
      email?: string;
      challenge?: 'http-01' | 'dns-01';
      dnsAccountId?: string;
    },
    material: AcmeMaterial,
    existing?: CertificateRecord,
  ) {
    const id = input.id ?? existing?.id ?? randomUUID();
    const record = await this.saveMaterial(id, material.certPem, material.keyPem, existing, {
      name: input.name,
      domains: input.domains,
      provider: input.provider,
      email: input.email,
      challenge: input.challenge,
      dnsAccountId: input.dnsAccountId,
    });
    await this.store.saveCertificate(record);
    this.changed();
    return record;
  }

  async issue(
    input: IssueCertificateInput,
    assignments: HttpChallengeAssignment[] = [],
    existing?: CertificateRecord,
    hooks?: CertificateIssueHooks,
  ) {
    const domains = normalizeDomains(input.domains);
    const signature = `${input.provider}:${domains.join(',')}`;
    if (this.activeTask && this.activeTask !== hooks?.taskId)
      throw new AppError('已有证书签发任务正在运行，请等待当前任务完成。');
    if (this.issuing.has(signature)) throw new AppError('相同域名的证书正在签发。');
    if (input.challenge === 'http-01' && !assignments.length)
      throw new AppError('HTTP-01 需要每个域名都能通过现有 FRP HTTP 规则映射到客户端实例。');
    this.issuing.add(signature);
    this.activeTask = hooks?.taskId ?? signature;
    const progress = (value: CertificateIssueProgressUpdate) => hooks?.onProgress(value);
    const id = existing?.id ?? randomUUID();
    try {
      const material = await issueAcmeMaterial(
        this.store,
        { ...input, domains },
        hooks,
        {
          withHttpResponder: <T>(
            operation: (responder: AcmeHttpResponder) => Promise<T>,
            signal?: AbortSignal,
          ): Promise<T> => {
            progress({
              status: 'running',
              step: '准备 HTTP-01 临时通道',
              message: '正在启动临时验证通道并等待客户端连接。',
            });
            return this.runHttpChallenge(assignments, operation, signal);
          },
          promptDnsChallenge: hooks?.promptDnsChallenge ?? this.promptDnsChallenge,
        },
        this.acmeClient,
      );
      progress({
        status: 'running',
        step: '保存证书',
        message: '验证通过，正在安全保存证书与私钥。',
      });
      const record = await this.saveMaterial(id, material.certPem, material.keyPem, existing, {
        name: input.name.trim() || existing?.name || domains[0],
        provider: input.provider,
        email: input.email,
        domains,
        challenge: input.challenge,
        expiresAt: new Date(material.certificate.validTo).toISOString(),
      });
      await this.store.saveCertificate(record);
      this.changed();
      progress({
        status: 'succeeded',
        step: '签发完成',
        message: `证书已保存，覆盖 ${domains.length} 个域名。`,
      });
      return record;
    } catch (error) {
      if (hooks?.signal.aborted) throw new AppError('用户已取消证书签发。', 'CANCELLED');
      throw new AppError(
        redact(
          error instanceof Error ? error.message : String(error),
          this.store.allSecrets(),
        ).slice(0, 1200),
      );
    } finally {
      this.issuing.delete(signature);
      if (this.activeTask === (hooks?.taskId ?? signature)) this.activeTask = undefined;
    }
  }

  async renewDue(
    resolveAssignments: (certificate: CertificateRecord) => HttpChallengeAssignment[],
  ) {
    const now = Date.now();
    const failures: string[] = [];
    for (const certificate of this.store.data.certificates) {
      if (
        !certificate.autoRenew ||
        !certificate.challenge ||
        Date.parse(certificate.expiresAt ?? '') - now > 30 * 24 * 60 * 60 * 1000 ||
        this.issuing.has(`${certificate.provider}:${certificate.domains.join(',')}`)
      )
        continue;
      try {
        await this.issue(
          {
            name: certificate.name,
            domains: certificate.domains,
            provider: certificate.provider as 'letsencrypt' | 'litessl',
            email: certificate.email ?? '',
            challenge: certificate.challenge,
            termsAgreed: true,
          },
          certificate.challenge === 'http-01' ? resolveAssignments(certificate) : [],
          certificate,
        );
      } catch (error) {
        failures.push(
          `${certificate.name}：${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    if (failures.length) throw new AppError(`部分证书续期失败：\n${failures.join('\n')}`);
  }

  async setAutoRenew(id: string, enabled: boolean) {
    const certificate = this.store.data.certificates.find((item) => item.id === id);
    if (!certificate) throw new AppError('证书不存在。');
    if (enabled && certificate.provider === 'manual')
      throw new AppError('手动导入的证书不能自动续期。');
    if (enabled && !this.store.secure)
      throw new AppError('系统安全存储不可用，无法安全保存自动续期凭据。');
    certificate.autoRenew = enabled;
    await this.store.persist();
    this.changed();
    return enabled ? '已开启自动续期；应用运行或驻留托盘时检查。' : '已关闭自动续期。';
  }

  async associate(certificateId: string, targets: Array<{ instanceId: string; ruleId: string }>) {
    const certificate = this.store.data.certificates.find((item) => item.id === certificateId);
    if (!certificate) throw new AppError('证书不存在。');
    const covered = new Set(certificate.domains.map((domain) => domain.toLowerCase()));
    const affected = new Set<string>();
    const selected: Array<{ instanceId: string; ruleId: string }> = [];
    for (const target of targets) {
      const instance = this.store.instance(target.instanceId);
      const rule = instance.proxies.find((item) => item.id === target.ruleId);
      if (!rule || rule.type !== 'https' || rule.tlsMode !== 'terminate')
        throw new AppError('证书只能关联到 HTTPS 证书终止规则。');
      if (!rule.domains.every((domain) => covered.has(domain.toLowerCase())))
        throw new AppError(`证书 SAN 未覆盖规则「${rule.name}」的全部域名。`);
      selected.push(target);
    }
    for (const target of selected) {
      const instance = this.store.instance(target.instanceId);
      const rule = instance.proxies.find((item) => item.id === target.ruleId)!;
      rule.certificateId = certificateId;
      rule.certPath = '';
      rule.keyPath = '';
      affected.add(instance.id);
    }
    certificate.pendingRestartInstances = [
      ...new Set([
        ...certificate.pendingRestartInstances,
        ...[...affected].filter((id) => this.isInstanceRunning(id)),
      ]),
    ];
    certificate.pendingRestart = certificate.pendingRestartInstances.length > 0;
    await this.store.persist();
    this.changed();
    return `证书已关联到 ${targets.length} 条规则；运行中的实例需重启后加载。`;
  }

  async instanceStarted(id: string) {
    let changed = false;
    for (const certificate of this.store.data.certificates) {
      const referenced = this.store.data.instances.some(
        (instance) =>
          instance.id === id &&
          instance.proxies.some((rule) => rule.certificateId === certificate.id),
      );
      if (
        !certificate.pendingRestartInstances.includes(id) &&
        !(certificate.pendingRestart && referenced)
      )
        continue;
      certificate.pendingRestartInstances = certificate.pendingRestartInstances.filter(
        (instanceId) => instanceId !== id,
      );
      certificate.pendingRestart = certificate.pendingRestartInstances.length > 0;
      changed = true;
    }
    if (changed) await this.store.persist();
    return changed;
  }

  async remove(id: string) {
    if (
      this.store.data.instances.some((instance) =>
        instance.proxies.some((rule) => rule.certificateId === id),
      )
    )
      throw new AppError('证书仍被 HTTPS 规则引用，请先解除关联。');
    const index = this.store.data.certificates.findIndex((certificate) => certificate.id === id);
    if (index < 0) throw new AppError('证书不存在。');
    await rm(this.pathFor(id).directory, { recursive: true, force: true });
    this.store.data.certificates.splice(index, 1);
    await this.store.persist();
    this.changed();
  }
}
