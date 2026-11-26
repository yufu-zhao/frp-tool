import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { decideTlsPlan, type TlsPlan } from '../shared/tls-plan';
import { generateSiteConfig } from '../shared/site-config';
import { AppError, redact } from '../shared/errors';
import {
  serverCertificateSchema,
  type CertificateIssueProgressUpdate,
  type Instance,
  type ProxyRule,
  type ServerCertificate,
  type SiteInspection,
} from '../shared/types';
import type {
  DnsAccountTestInput,
  DnsTestInput,
  IssueServerInput,
  ServerCertificateView,
} from '../shared/contracts';
import type { Store } from './store';
import {
  Certificates,
  issueAcmeMaterial,
  normalizeDomains,
  throwIfCancelled,
  type AcmeChallengeHooks,
  type CertificateIssueHooks,
  type DnsChallengeRecord,
  type HttpChallengeRunner,
} from './certificates';
import {
  createDnsHook,
  removeDnsHook,
  resolveAutomation,
  testDnsAccount,
  testDnsProvider,
  type DnsAutomationResolution,
  type DnsTestResult,
} from './dns-automation';

export type ServerIssueHooks = CertificateIssueHooks;

interface RuleSnapshot {
  instanceId: string;
  ruleId: string;
  type: 'tcp' | 'udp' | 'http' | 'https';
  certificateId?: string;
  certPath: string;
  keyPath: string;
  tlsMode: 'passthrough' | 'terminate';
  publicHttps: boolean;
  siteConfigPath?: string;
}

/** 隐藏 HTTPS 伴随规则的回滚信息：新建的直接删除，已存在的恢复原引用。 */
export interface HiddenRuleRef {
  instanceId: string;
  ruleId: string;
  created: boolean;
  before?: ProxyRule;
}

function uniqueProxyName(instance: Instance, base: string): string {
  const names = new Set(instance.proxies.map((rule) => rule.name));
  if (!names.has(base)) return base;
  let index = 2;
  while (names.has(`${base}-${index}`)) index += 1;
  return `${base}-${index}`;
}

/**
 * 为 HTTP 规则创建（或更新）隐藏的 HTTPS 伴随规则。
 * 用户规则仍保持 http，伴随规则参与 frpc 配置，但不出现在规则列表里。
 */
export function ensureHiddenHttpsRules(
  instance: Instance,
  sourceRules: ProxyRule[],
  certificateId: string,
): HiddenRuleRef[] {
  const refs: HiddenRuleRef[] = [];
  for (const source of sourceRules) {
    const existing = instance.proxies.find(
      (rule) => rule.hidden && rule.sourceRuleId === source.id,
    );
    if (existing) {
      refs.push({
        instanceId: instance.id,
        ruleId: existing.id,
        created: false,
        before: JSON.parse(JSON.stringify(existing)) as ProxyRule,
      });
      existing.type = 'https';
      existing.tlsMode = 'terminate';
      existing.certificateId = certificateId;
      existing.certPath = '';
      existing.keyPath = '';
      existing.domains = [...source.domains];
      existing.localIP = source.localIP;
      existing.localPort = source.localPort;
      continue;
    }
    const hidden: ProxyRule = {
      id: randomUUID(),
      name: uniqueProxyName(instance, `${source.name}-https`),
      type: 'https',
      localIP: source.localIP,
      localPort: source.localPort,
      domains: [...source.domains],
      tlsMode: 'terminate',
      certificateId,
      certPath: '',
      keyPath: '',
      hidden: true,
      sourceRuleId: source.id,
    };
    instance.proxies.push(hidden);
    refs.push({ instanceId: instance.id, ruleId: hidden.id, created: true });
  }
  return refs;
}

export function restoreHiddenRules(instances: Instance[], refs: HiddenRuleRef[]) {
  for (const ref of refs) {
    const instance = instances.find((item) => item.id === ref.instanceId);
    if (!instance) continue;
    if (ref.created) {
      instance.proxies = instance.proxies.filter((rule) => rule.id !== ref.ruleId);
      continue;
    }
    const index = instance.proxies.findIndex((rule) => rule.id === ref.ruleId);
    if (index >= 0 && ref.before) instance.proxies[index] = ref.before;
  }
}

/**
 * 最小 MVP：本机申请 SSL + 本机部署。
 *
 * 只做一件事：用已保存的 DNS 账户走 DNS-01 签发证书，材料落到本机证书库，
 * 并把同服务器上域名匹配的 HTTPS 规则切到该证书（frpc https2http 终止 TLS）。
 * 签发与部署共用一个 taskId；任何一步失败都会撤销本次写入，不留半成品。
 */
export class ServerCertificates {
  private issuing = new Set<string>();

  constructor(
    private readonly store: Store,
    private readonly changed: () => void,
    private readonly localCertificates: Certificates,
    private readonly runHttpChallenge: HttpChallengeRunner,
    private readonly webInclude: import('./web-include').WebIncludeManager,
    private readonly detectHost: (serverId: string) => Promise<import('../shared/types').HostInfo>,
  ) {}

  private async resolveDns(
    input: IssueServerInput,
    domains: string[],
    progress: (value: CertificateIssueProgressUpdate) => void,
  ): Promise<{ resolution: DnsAutomationResolution; notes: string[] }> {
    progress({
      status: 'running',
      step: '检查 DNS 账户',
      message: '正在读取已保存账户的凭据并验证可用性。',
    });
    const account = input.dnsAccountId
      ? this.store.data.dnsAccounts.find((item) => item.id === input.dnsAccountId)
      : undefined;
    if (!account) throw new AppError('请选择已保存的 DNS 账户。');
    const resolution = await resolveAutomation(
      account.provider,
      this.store,
      domains,
      progress,
      account.id,
    );
    return { resolution, notes: [resolution.summary] };
  }

  /** 方案只由服务端 vhostHTTPPort 决定；探测结果作为方案 A 的申请门槛。 */
  async plan(serverId: string): Promise<TlsPlan> {
    const server = this.store.server(serverId);
    let hostInfo: import('../shared/types').HostInfo | undefined;
    try {
      hostInfo = await this.detectHost(serverId);
    } catch {
      // 探测失败只影响方案 A 的申请条件，不改变端口决定的方案。
    }
    return decideTlsPlan({
      httpPort: server.httpPort,
      hostInfo,
      webInclude: this.store.data.webIncludes[serverId],
      probe: this.store.data.webIncludes[serverId]?.probe,
    });
  }

  /**
   * HTTP-01 双通道：
   * - 方案 A：把 token 写到服务器 nginx 的 challenge 目录，由服务器直接应答 CA；
   * - 方案 B：沿用 frpc 临时 http 规则 + 本机响应器。
   */
  private async resolveHttpForPlan(
    input: IssueServerInput,
    serverId: string,
    domains: string[],
    plan: TlsPlan,
    progress: (value: CertificateIssueProgressUpdate) => void,
  ): Promise<{ hooks: AcmeChallengeHooks; notes: string[]; cleanup: () => Promise<void> }> {
    if (plan.mode === 'server') {
      progress({
        status: 'running',
        step: '准备 HTTP-01 验证',
        message: '正在服务器 nginx 上部署域名 challenge 站点。',
      });
      const { root } = await this.webInclude.installHttp01Challenge(serverId, domains);
      const tokens = new Set<string>();
      return {
        notes: ['HTTP-01 文件验证 · 服务器 nginx 直接应答'],
        cleanup: () => this.webInclude.removeHttp01Challenge(serverId),
        hooks: {
          skipChallengeVerification: true,
          withHttpResponder: async (operation) => {
            const responder = {
              port: 80,
              set: async (token: string, value: string) => {
                tokens.add(token);
                await this.webInclude.setHttp01Token(serverId, root, token, value);
              },
              remove: async (token: string) => {
                tokens.delete(token);
                await this.webInclude.removeHttp01Token(serverId, root, token);
              },
            };
            try {
              return await operation(responder);
            } finally {
              for (const token of tokens) await responder.remove(token).catch(() => {});
            }
          },
        },
      };
    }
    const resolved = this.resolveHttp(input, serverId, domains, progress);
    return { ...resolved, cleanup: async () => {} };
  }

  /** HTTP-01：校验承载验证的客户端实例，返回一个把 ACME 验证挂到临时 FRP 通道的 hooks。 */
  private resolveHttp(
    input: IssueServerInput,
    serverId: string,
    domains: string[],
    progress: (value: CertificateIssueProgressUpdate) => void,
  ): { hooks: AcmeChallengeHooks; notes: string[] } {
    progress({
      status: 'running',
      step: '检查验证实例',
      message: '正在确定用于 HTTP-01 文件验证的客户端实例。',
    });
    // 文件验证的目标服务器已由规则固定：优先用申请规则所属实例，否则取该服务器唯一的实例。
    const candidates = this.store.data.instances.filter(
      (item) => item.serverId === serverId && item.mode === 'form',
    );
    let instance = input.httpInstanceId ? this.store.instance(input.httpInstanceId) : undefined;
    if (!instance && input.ruleId)
      instance = candidates.find((item) =>
        item.proxies.some((rule) => rule.id === input.ruleId && !rule.hidden),
      );
    if (!instance && candidates.length === 1) instance = candidates[0];
    if (!instance)
      throw new AppError(
        candidates.length
          ? '目标服务器下有多个客户端实例，请从对应的 Web 规则发起文件验证。'
          : '目标服务器下没有表单模式的客户端实例，无法完成文件验证。',
      );
    if (instance.serverId !== serverId)
      throw new AppError('验证实例不属于目标服务器，请从对应 Web 规则发起申请。');
    if (instance.mode !== 'form')
      throw new AppError('HTTP-01 验证实例必须是表单模式；高级原始配置无法临时添加验证规则。');
    const instanceId = instance.id;
    return {
      notes: [`HTTP-01 文件验证 · 实例「${instance.name}」`],
      hooks: {
        // CA 从公网回连，本机无法预校验 challenge 路径，跳过 acme-client 的本地自检。
        skipChallengeVerification: true,
        withHttpResponder: (operation, signal) => {
          progress({
            status: 'running',
            step: '准备 HTTP-01 临时通道',
            message: '正在临时重启客户端实例，通过 FRP 提供文件验证响应。',
          });
          return this.runHttpChallenge([{ instanceId, domains }], operation, signal);
        },
      },
    };
  }

  /** 为本机证书创建隐藏 HTTPS 伴随规则；原 HTTP 规则保持不变。 */
  attachHiddenRules(serverId: string, certificateId: string, domains: string[]): HiddenRuleRef[] {
    const refs: HiddenRuleRef[] = [];
    const wanted = new Set(domains.map((domain) => domain.toLowerCase()));
    for (const instance of this.store.data.instances) {
      if (instance.serverId !== serverId || instance.mode !== 'form') continue;
      const sources = instance.proxies.filter(
        (rule) =>
          rule.type === 'http' &&
          !rule.publicHttps &&
          rule.domains.some((domain) => wanted.has(domain.toLowerCase())),
      );
      refs.push(...ensureHiddenHttpsRules(instance, sources, certificateId));
    }
    return refs;
  }

  private restoreRules(snapshots: RuleSnapshot[]) {
    for (const snapshot of snapshots) {
      const instance = this.store.data.instances.find((item) => item.id === snapshot.instanceId);
      const rule = instance?.proxies.find((item) => item.id === snapshot.ruleId);
      if (!rule) continue;
      rule.type = snapshot.type;
      rule.tlsMode = snapshot.tlsMode;
      rule.certificateId = snapshot.certificateId;
      rule.certPath = snapshot.certPath;
      rule.keyPath = snapshot.keyPath;
      rule.publicHttps = snapshot.publicHttps;
      rule.siteConfigPath = snapshot.siteConfigPath;
    }
  }

  /**
   * 方案 A：把目标规则切成 http 回源 + publicHttps 标记（TLS 由服务器 nginx 终止）。
   * 只处理域名匹配的规则；返回快照供回滚。
   */
  private convertRulesToServerTls(
    serverId: string,
    ruleId: string | undefined,
    domains: string[],
    configPath: string,
  ): RuleSnapshot[] {
    const snapshots: RuleSnapshot[] = [];
    const wanted = new Set(domains.map((domain) => domain.toLowerCase()));
    for (const instance of this.store.data.instances) {
      if (instance.serverId !== serverId || instance.mode !== 'form') continue;
      for (const rule of instance.proxies) {
        const isTarget = ruleId
          ? rule.id === ruleId
          : rule.domains.some((domain) => wanted.has(domain.toLowerCase()));
        if (!isTarget || (rule.type !== 'http' && rule.type !== 'https')) continue;
        snapshots.push({
          instanceId: instance.id,
          ruleId: rule.id,
          type: rule.type,
          certificateId: rule.certificateId,
          certPath: rule.certPath,
          keyPath: rule.keyPath,
          tlsMode: rule.tlsMode,
          publicHttps: rule.publicHttps ?? false,
          siteConfigPath: rule.siteConfigPath,
        });
        rule.type = 'http';
        rule.tlsMode = 'passthrough';
        rule.certificateId = undefined;
        rule.certPath = '';
        rule.keyPath = '';
        rule.publicHttps = true;
        rule.siteConfigPath = configPath;
      }
    }
    return snapshots;
  }

  /** 定位证书关联的用户 Web 规则；未指定 ruleId 时按域名找第一条 HTTP 规则。 */
  private locateRule(serverId: string, ruleId: string | undefined, domains: string[]) {
    const wanted = new Set(domains.map((domain) => domain.toLowerCase()));
    for (const instance of this.store.data.instances) {
      if (instance.serverId !== serverId || instance.mode !== 'form') continue;
      if (ruleId) {
        const rule = instance.proxies.find((item) => item.id === ruleId && !item.hidden);
        if (rule) return { instance, rule };
        continue;
      }
      const rule = instance.proxies.find(
        (item) =>
          item.type === 'http' &&
          !item.publicHttps &&
          item.domains.some((domain) => wanted.has(domain.toLowerCase())),
      );
      if (rule) return { instance, rule };
    }
    return undefined;
  }

  /** 失败回滚：TXT、本机证书文件、store 记录、HTTPS 规则引用全部还原。 */
  private async rollback(args: {
    dnsResolution?: DnsAutomationResolution;
    dnsRecords: DnsChallengeRecord[];
    snapshots: RuleSnapshot[];
    hiddenRefs?: HiddenRuleRef[];
    localCertificateId?: string;
    localCertPath?: string;
    serverCertificateId?: string;
    challengeCleanup?: () => Promise<void>;
    serverCleanup?: () => Promise<void>;
  }) {
    if (args.challengeCleanup) await args.challengeCleanup().catch(() => {});
    if (args.serverCleanup) await args.serverCleanup().catch(() => {});
    if (args.dnsResolution) {
      const remove = removeDnsHook(args.dnsResolution);
      for (const record of args.dnsRecords) await remove(record).catch(() => {});
    }
    this.restoreRules(args.snapshots);
    if (args.hiddenRefs?.length) restoreHiddenRules(this.store.data.instances, args.hiddenRefs);
    this.store.data.serverCertificates = this.store.data.serverCertificates.filter(
      (item) => item.id !== args.serverCertificateId,
    );
    if (args.localCertificateId) {
      this.store.data.certificates = this.store.data.certificates.filter(
        (item) => item.id !== args.localCertificateId,
      );
      await rm(path.join(this.store.root, 'certificates', args.localCertificateId), {
        recursive: true,
        force: true,
      }).catch(() => {});
    }
    await this.store.persist().catch(() => {});
    this.changed();
  }

  async issue(input: IssueServerInput, hooks: ServerIssueHooks): Promise<ServerCertificate> {
    const domains = normalizeDomains(input.domains);
    const server = this.store.server(input.serverId);
    const signature = `${server.id}:${domains.join(',')}`;
    if (this.issuing.has(signature)) throw new AppError('相同域名的证书任务正在运行。');
    this.issuing.add(signature);

    const progress = (value: CertificateIssueProgressUpdate) => hooks.onProgress(value);
    const dnsRecords: DnsChallengeRecord[] = [];
    let dnsResolution: DnsAutomationResolution | undefined;
    let snapshots: RuleSnapshot[] = [];
    let hiddenRefs: HiddenRuleRef[] = [];
    let localCertificateId: string | undefined;
    let localCertPath: string | undefined;
    let serverCertificateId: string | undefined;
    let challengeCleanup: (() => Promise<void>) | undefined;
    let serverCleanup: (() => Promise<void>) | undefined;

    const challenge = input.challenge ?? 'dns-01';

    try {
      progress({
        status: 'running',
        step: '判定 TLS 方案',
        message: '正在按服务端 vhostHTTPPort 判定证书终止位置并检查申请条件。',
      });
      const plan = await this.plan(server.id);
      if (!plan.canIssue)
        throw new AppError(`当前服务器不满足方案 A 的申请条件：${plan.blockers.join('；')}`);
      let notes: string[];
      let challengeHooks: AcmeChallengeHooks;
      if (challenge === 'http-01') {
        const resolved = await this.resolveHttpForPlan(input, server.id, domains, plan, progress);
        notes = resolved.notes;
        challengeHooks = resolved.hooks;
        challengeCleanup = resolved.cleanup;
      } else {
        const resolved = await this.resolveDns(input, domains, progress);
        dnsResolution = resolved.resolution;
        notes = resolved.notes;
        const createDns = createDnsHook(resolved.resolution, progress);
        challengeHooks = {
          dnsAutomation: 'api',
          skipChallengeVerification: true,
          createDnsRecord: async (record) => {
            dnsRecords.push(record);
            await createDns(record);
          },
          removeDnsRecord: removeDnsHook(resolved.resolution),
        };
      }

      progress({
        status: 'running',
        step: '申请证书',
        message: `正在向 CA 提交订单并完成 ${challenge === 'http-01' ? 'HTTP-01 文件' : 'DNS-01'} 验证。`,
      });
      const material = await issueAcmeMaterial(
        this.store,
        {
          name: input.name,
          domains,
          provider: input.provider,
          email: input.email,
          challenge,
          termsAgreed: input.termsAgreed,
          eabKid: input.eabKid,
          eabHmac: input.eabHmac,
          keySize: input.keySize ?? 2048,
        },
        hooks,
        challengeHooks,
      );
      throwIfCancelled(hooks.signal);

      const id = randomUUID();
      serverCertificateId = id;
      const baseRecord = {
        id,
        serverId: server.id,
        name: input.name.trim() || domains[0],
        provider: input.provider,
        domains,
        ...(input.email ? { email: input.email } : {}),
        challenge,
        ...(challenge === 'dns-01' && input.dnsAccountId
          ? { dnsAccountId: input.dnsAccountId }
          : {}),
        expiresAt: new Date(material.certificate.validTo).toISOString(),
        renewalManager: 'manual',
        dnsAutomation: challenge === 'dns-01' ? 'api' : 'manual',
        lastRenewedAt: Date.now(),
        notes: notes.join('；') || undefined,
        createdAt: Date.now(),
      };

      let record: import('../shared/types').ServerCertificate;
      const target = this.locateRule(server.id, input.ruleId, domains);
      if (plan.mode === 'server') {
        progress({
          status: 'running',
          step: '部署到服务器',
          message: '正在检查服务器站点配置，缺少时自动生成并同步，然后写入证书。',
        });
        // 方案 A 的目标规则此时仍是普通 http：publicHttps 要等 convertRulesToServerTls() 在部署成功后才置位。
        // 必须显式标记，generateSiteConfig 才会生成 listen 443 ssl 的 server 块，而不是 listen 80。
        const generated = target
          ? generateSiteConfig({
              rule: { ...target.rule, publicHttps: true },
              server,
              tlsMode: 'server',
              certificateId: id,
            }).content
          : undefined;
        const deployed = await this.webInclude.installServerCertificate({
          serverId: server.id,
          ruleId: target?.rule.id ?? input.ruleId ?? '',
          certificateId: id,
          domains,
          httpPort: server.httpPort,
          certPem: material.certPem,
          keyPem: material.keyPem,
          siteConfig: generated,
        });
        serverCleanup = () =>
          this.webInclude.removeServerCertificate(server.id, [
            deployed.certPath,
            deployed.keyPath,
            deployed.configPath,
          ]);
        snapshots = this.convertRulesToServerTls(
          server.id,
          input.ruleId,
          domains,
          deployed.configPath,
        );
        record = serverCertificateSchema.parse({
          ...baseRecord,
          location: 'server',
          certPath: deployed.certPath,
          keyPath: deployed.keyPath,
          serverCertPath: deployed.certPath,
          serverKeyPath: deployed.keyPath,
          serverConfigPath: deployed.configPath,
          tlsPlan: 'server',
          deployState: 'deployed',
          deployTarget: 'server-nginx',
          ruleId: target?.rule.id,
          instanceId: target?.instance.id,
        });
      } else {
        progress({
          status: 'running',
          step: '部署到本机',
          message: '正在把证书写入本机并创建 HTTPS 伴随规则（原 HTTP 规则保持不变）。',
        });
        const local = await this.localCertificates.saveIssued(
          {
            id,
            name: input.name.trim() || domains[0],
            domains,
            provider: input.provider,
            email: input.email,
            challenge,
            dnsAccountId: challenge === 'dns-01' ? input.dnsAccountId : undefined,
          },
          material,
        );
        localCertificateId = local.id;
        localCertPath = local.certPath;
        hiddenRefs = this.attachHiddenRules(server.id, local.id, domains);
        record = serverCertificateSchema.parse({
          ...baseRecord,
          location: 'local',
          localCertificateId: local.id,
          certPath: local.certPath,
          keyPath: local.keyPath,
          tlsPlan: 'local',
          deployState: 'deployed',
          deployTarget: 'local-frpc',
          ruleId: target?.rule.id,
          instanceId: target?.instance.id,
          hiddenRuleId: hiddenRefs[0]?.ruleId,
        });
      }
      await this.store.saveServerCertificate(record);
      // HTTP-01 验证完成，移除临时 challenge server 块，避免长期占用域名 80 路径。
      if (challengeCleanup) await challengeCleanup().catch(() => {});
      challengeCleanup = undefined;
      this.changed();

      progress({
        status: 'succeeded',
        step: '完成',
        message:
          plan.mode === 'server'
            ? `证书已部署到服务器，${snapshots.length} 条规则已启用公网 HTTPS。`
            : `证书已保存本机，${hiddenRefs.length} 条 HTTP 规则已获得隐藏 HTTPS 伴随规则。`,
      });
      return record;
    } catch (error) {
      progress({
        status: 'failed',
        step: '清理失败现场',
        message: '本次签发失败，正在撤销已写入的证书、规则引用与 DNS 记录。',
      });
      await this.rollback({
        dnsResolution,
        dnsRecords,
        snapshots,
        hiddenRefs,
        localCertificateId,
        localCertPath,
        serverCertificateId,
        challengeCleanup,
        serverCleanup,
      });
      if (hooks.signal.aborted) throw new AppError('用户已取消证书签发。', 'CANCELLED');
      throw new AppError(
        redact(
          error instanceof Error ? error.message : String(error),
          this.store.allSecrets(),
        ).slice(0, 1200),
      );
    } finally {
      this.issuing.delete(signature);
    }
  }

  /** 手动导入 PEM 时同样创建隐藏 HTTPS 伴随规则，不修改用户的 HTTP 规则。 */
  async enableLocalCertificate(instanceId: string, domains: string[], certificateId: string) {
    const instance = this.store.instance(instanceId);
    const wanted = new Set(domains.map((domain) => domain.toLowerCase()));
    const sources = instance.proxies.filter(
      (rule) =>
        rule.type === 'http' &&
        !rule.publicHttps &&
        rule.domains.some((domain) => wanted.has(domain.toLowerCase())),
    );
    const refs = ensureHiddenHttpsRules(instance, sources, certificateId);
    await this.store.saveInstance(instance);
    this.changed();
    return refs;
  }

  /**
   * 移除规则关联的证书并回退 HTTP：
   * - 方案 A 删除服务器证书与 443 server 块，把托管配置改回 HTTP；
   * - 方案 B 删除隐藏 HTTPS 伴随规则与本机证书，原 HTTP 规则不变。
   */
  async removeForRule(instanceId: string, ruleId: string) {
    const instance = this.store.instance(instanceId);
    const rule = instance.proxies.find((item) => item.id === ruleId && !item.hidden);
    if (!rule) throw new AppError('未找到要移除证书的用户规则。');
    const server = this.store.server(instance.serverId);
    const serverCert = this.store.data.serverCertificates.find(
      (item) => item.ruleId === rule.id && item.serverId === server.id,
    );
    const hidden = instance.proxies.find((item) => item.hidden && item.sourceRuleId === rule.id);
    let plan: 'server' | 'local' = 'local';
    let certificateId = hidden?.certificateId ?? serverCert?.localCertificateId;

    if (serverCert?.tlsPlan === 'server') {
      plan = 'server';
      certificateId = serverCert.id;
      const httpRule: ProxyRule = { ...rule, publicHttps: false };
      const content = generateSiteConfig({
        rule: httpRule,
        server,
        tlsMode: 'server',
      }).content;
      const configPath = serverCert.serverConfigPath;
      await this.webInclude.removeServerCertificate(
        server.id,
        [serverCert.serverCertPath, serverCert.serverKeyPath, configPath].filter(
          (value): value is string => !!value,
        ),
        configPath ? { path: configPath, content } : undefined,
      );
      rule.publicHttps = false;
      rule.siteConfig = content;
      rule.siteConfigFlavor = 'nginx';
      rule.siteConfigPath = configPath;
      rule.siteConfigUpdatedAt = Date.now();
      this.store.data.serverCertificates = this.store.data.serverCertificates.filter(
        (item) => item.id !== serverCert.id,
      );
    } else {
      if (hidden) instance.proxies = instance.proxies.filter((item) => item.id !== hidden.id);
      // 兼容旧数据里直接挂在用户规则上的证书引用，先解除再删本机证书。
      if (certificateId && rule.certificateId === certificateId) {
        rule.certificateId = undefined;
        rule.certPath = '';
        rule.keyPath = '';
      }
      if (serverCert)
        this.store.data.serverCertificates = this.store.data.serverCertificates.filter(
          (item) => item.id !== serverCert.id,
        );
      if (certificateId) await this.localCertificates.remove(certificateId).catch(() => {});
    }

    await this.store.saveInstance(instance);
    await this.store.persist();
    this.changed();
    return { instanceId, ruleId, plan, certificateId };
  }

  /** 从证书管理页按证书 ID 删除：解析关联实例/规则后走统一的回退 HTTP 流程。 */
  async removeById(id: string) {
    const certificate = this.store.data.serverCertificates.find((item) => item.id === id);
    if (!certificate) throw new AppError('证书不存在或已被删除。');
    let instanceId = certificate.instanceId;
    let ruleId = certificate.ruleId;
    if (!instanceId || !ruleId) {
      const companionId = certificate.hiddenRuleId;
      for (const instance of this.store.data.instances) {
        if (instance.serverId !== certificate.serverId) continue;
        const hidden = companionId
          ? instance.proxies.find((item) => item.id === companionId && item.hidden)
          : instance.proxies.find(
              (item) =>
                item.hidden &&
                (item.certificateId === id ||
                  item.certificateId === certificate.localCertificateId),
            );
        const source = hidden?.sourceRuleId
          ? instance.proxies.find((item) => item.id === hidden.sourceRuleId && !item.hidden)
          : instance.proxies.find(
              (item) =>
                !item.hidden &&
                item.domains.some((domain) =>
                  certificate.domains.some((name) => name.toLowerCase() === domain.toLowerCase()),
                ),
            );
        if (hidden && source) {
          instanceId = instance.id;
          ruleId = source.id;
          break;
        }
      }
    }
    if (!instanceId || !ruleId)
      throw new AppError('该证书没有可定位的关联规则，无法自动回退 HTTP；请在规则中移除证书。');
    return this.removeForRule(instanceId, ruleId);
  }

  async testDns(input: DnsTestInput): Promise<DnsTestResult> {
    return testDnsProvider(input, this.store);
  }

  async testAccount(input: DnsAccountTestInput): Promise<DnsTestResult> {
    return testDnsAccount(input, this.store);
  }

  status(serverId: string): ServerCertificateView[] {
    this.store.server(serverId);
    return this.store.data.serverCertificates
      .filter((certificate) => certificate.serverId === serverId)
      .map((certificate) => ({ certificate, inspection: null, tlsProxy: null }));
  }

  /** 以下入口在 MVP 阶段保留 IPC 兼容性，但不再提供旧逻辑。 */
  async inspect(): Promise<SiteInspection> {
    throw new AppError('当前最小版本不提供站点检查。');
  }
  async deploy(..._args: unknown[]): Promise<never> {
    throw new AppError('当前最小版本只支持本机证书，不提供服务端部署。');
  }
  async refreshEnvironment(..._args: unknown[]): Promise<never> {
    throw new AppError('当前最小版本不提供环境复核。');
  }
  async renewNow(_certificateId?: string, _hooks?: ServerIssueHooks): Promise<never> {
    throw new AppError('当前最小版本不提供续期入口；请重新申请证书。');
  }
}
