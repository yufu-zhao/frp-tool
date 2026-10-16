import { mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createPrivateKey, createPublicKey, randomUUID, X509Certificate } from 'node:crypto';
import acme from 'acme-client';
import { AppError, redact } from '../shared/errors';
import type { CertificateIssueProgress, CertificateRecord } from '../shared/types';
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

function throwIfCancelled(signal?: AbortSignal) {
  if (signal?.aborted) throw new AppError('用户已取消证书签发。', 'CANCELLED');
}

function abortable<T>(operation: Promise<T>, signal?: AbortSignal): Promise<T> {
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

  private pathFor(id: string) {
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

  async issue(
    input: IssueCertificateInput,
    assignments: HttpChallengeAssignment[] = [],
    existing?: CertificateRecord,
    hooks?: CertificateIssueHooks,
  ) {
    const domains = normalizeDomains(input.domains);
    if (!input.termsAgreed) throw new AppError('请先确认已阅读并同意所选证书机构的服务条款。');
    const signature = `${input.provider}:${domains.join(',')}`;
    if (this.activeTask && this.activeTask !== hooks?.taskId)
      throw new AppError('已有证书签发任务正在运行，请等待当前任务完成。');
    if (this.issuing.has(signature)) throw new AppError('相同域名的证书正在签发。');
    if (input.challenge === 'http-01' && !assignments.length)
      throw new AppError('HTTP-01 需要每个域名都能通过现有 FRP HTTP 规则映射到客户端实例。');
    if (input.challenge === 'dns-01' && input.eabKid && !input.eabHmac)
      throw new AppError('填写 EAB KID 后还需要填写 EAB HMAC 密钥。');
    this.issuing.add(signature);
    this.activeTask = hooks?.taskId ?? signature;
    const progress = (value: CertificateIssueProgressUpdate) => hooks?.onProgress(value);
    let currentStep = '准备签发';
    try {
      throwIfCancelled(hooks?.signal);
      currentStep = '准备 ACME 账户';
      progress({ status: 'running', step: currentStep, message: '正在准备本机 ACME 账户密钥。' });
      const accountKeyId = `acme:${input.provider}:accountKey`;
      let accountKey = this.store.secret(accountKeyId);
      if (!accountKey) {
        accountKey = (await this.acmeClient.crypto.createPrivateEcdsaKey()).toString();
        this.store.putSecret(accountKeyId, accountKey);
        await this.store.persist();
      }
      if (input.eabKid) this.store.putSecret(`acme:${input.provider}:eabKid`, input.eabKid);
      if (input.eabHmac) this.store.putSecret(`acme:${input.provider}:eabHmac`, input.eabHmac);
      const kid = input.eabKid || this.store.secret(`acme:${input.provider}:eabKid`);
      const hmacKey = input.eabHmac || this.store.secret(`acme:${input.provider}:eabHmac`);
      const directoryUrl =
        input.provider === 'letsencrypt'
          ? this.acmeClient.directory.letsencrypt.production
          : 'https://acme.litessl.com/acme/v2/directory';
      currentStep = '生成私钥与 CSR';
      progress({
        status: 'running',
        step: currentStep,
        message: `正在为 ${domains.length} 个域名生成 SAN 申请。`,
      });
      const [certificateKey, csr] = await this.acmeClient.crypto.createCsr({ altNames: domains });
      throwIfCancelled(hooks?.signal);
      const client = new this.acmeClient.Client({
        directoryUrl,
        accountKey,
        ...(kid && hmacKey ? { externalAccountBinding: { kid, hmacKey } } : {}),
      });
      const cleanupTransport = this.installCancelableTransport(client, hooks, () => currentStep);
      const id = existing?.id ?? randomUUID();
      let dnsPrompt = Promise.resolve();
      const originalLogger = (this.acmeClient as any).setLogger;
      if (typeof originalLogger === 'function')
        originalLogger((line: string) => {
          const detail = String(line).slice(0, 400);
          const retry = /retry(?:ing)?|backoff|attempt\s*#/i.test(detail);
          if (retry) {
            progress({
              status: 'retrying',
              step: currentStep,
              message: detail,
            });
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
      const operation = async (responder?: HttpChallengeResponder) => {
        throwIfCancelled(hooks?.signal);
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
          skipChallengeVerification: input.challenge === 'dns-01',
          challengeCreateFn: async (authorization, challenge, keyAuthorization) => {
            if (challenge.type === 'http-01') {
              throwIfCancelled(hooks?.signal);
              if (!responder) throw new AppError('HTTP-01 验证代理未启动。');
              currentStep = `配置 HTTP-01：${authorization.identifier.value}`;
              progress({
                status: 'running',
                step: currentStep,
                message: '正在通过临时 FRP 规则提供域名验证响应。',
              });
              responder.set(challenge.token, keyAuthorization);
            } else if (challenge.type === 'dns-01') {
              const record = {
                domain: authorization.identifier.value,
                record: `_acme-challenge.${authorization.identifier.value}`,
                value: keyAuthorization,
              };
              dnsPrompt = dnsPrompt.then(async () => {
                currentStep = `等待 DNS-01：${record.domain}`;
                progress({
                  status: 'waiting-user',
                  step: currentStep,
                  message: '请添加 TXT 记录；添加完成后点击“已添加，继续验证”。',
                  dnsRecords: [record],
                });
                const prompt = hooks?.promptDnsChallenge ?? this.promptDnsChallenge;
                if (!(await abortable(prompt([record]), hooks?.signal)))
                  throw new AppError('用户取消了 DNS-01 验证。');
              });
              await dnsPrompt;
              throwIfCancelled(hooks?.signal);
              currentStep = `等待 CA 验证：${record.domain}`;
              progress({
                status: 'running',
                step: currentStep,
                message: 'TXT 已确认，正在等待证书机构查询 DNS 并验证。',
              });
            } else throw new AppError('ACME 服务返回了未支持的验证方式。');
          },
          challengeRemoveFn: async (_authorization, challenge) => {
            if (challenge.type === 'http-01') responder?.remove(challenge.token);
          },
        });
      };
      let certPem: string;
      try {
        if (input.challenge === 'http-01') {
          currentStep = '准备 HTTP-01 临时通道';
          progress({
            status: 'running',
            step: currentStep,
            message: '正在启动临时验证通道并等待客户端连接。',
          });
        }
        certPem =
          input.challenge === 'http-01'
            ? await this.runHttpChallenge(
                assignments,
                async (responder) => operation(responder),
                hooks?.signal,
              )
            : await operation();
      } finally {
        cleanupTransport();
        if (typeof originalLogger === 'function') originalLogger(() => {});
      }
      throwIfCancelled(hooks?.signal);
      currentStep = '校验证书与域名';
      progress({
        status: 'running',
        step: currentStep,
        message: '正在校验证书有效期、SAN 域名和私钥匹配。',
      });
      const certificate = validateCertificateMaterial(certPem, certificateKey.toString(), domains);
      if (certPem.length > 1024 * 1024) throw new AppError('签发机构返回的证书文件超过 1 MB。');
      throwIfCancelled(hooks?.signal);
      currentStep = '保存证书';
      progress({
        status: 'running',
        step: currentStep,
        message: '验证通过，正在安全保存证书与私钥。',
      });
      const record = await this.saveMaterial(id, certPem, certificateKey.toString(), existing, {
        name: input.name.trim() || existing?.name || domains[0],
        provider: input.provider,
        email: input.email,
        domains,
        challenge: input.challenge,
        expiresAt: new Date(certificate.validTo).toISOString(),
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

  private installCancelableTransport(
    client: any,
    hooks: CertificateIssueHooks | undefined,
    currentStep: () => string,
  ) {
    const library = this.acmeClient as any;
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
          return await originalRequest.call(this, { ...config, signal });
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
