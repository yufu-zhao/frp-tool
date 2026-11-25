import { createHmac, randomBytes } from 'node:crypto';
import { AppError, redact } from '../shared/errors';
import type { DnsAutomation, CertificateIssueProgressUpdate } from '../shared/types';
import type {
  DnsAccountTestInput,
  DnsTestInput,
  ManagedDnsDomain,
  ManagedDnsRecord,
  ManagedDnsRecordInput,
} from '../shared/contracts';
import type { Store } from './store';
import type { DnsChallengeRecord } from './certificates';

// DNS-01 自动化只走 DNS 服务商 API（dnspod / aliyun / cloudflare）：
// 选中账户的凭据探测通过即全自动增删 TXT；否则签发失败并明确提示重新测试账户。
// 已移除 acme-dns / 既有 CNAME 委派 / 手动 TXT 等非 API 分支。
export type DnsProvider = 'dnspod' | 'aliyun' | 'cloudflare';

export interface DnsCredentials {
  secretId?: string;
  secretKey?: string;
  token?: string;
  endpoint?: string;
}

export interface DnsAdapter {
  // 只读探测：验证凭据/委派是否真正可用（网络调用需幂等、无副作用）。
  // 签发阶段会传入域名；账户测试不依赖具体域名，实际调用可忽略该参数。
  probe(domain?: string): Promise<boolean>;
  // 放置 / 删除 _acme-challenge TXT。
  set(record: DnsChallengeRecord): Promise<void>;
  unset(record: DnsChallengeRecord): Promise<void>;
}

// ─────────────────────────── 域名解析管理（通用记录 CRUD） ───────────────────────────
// 与 ACME 专用的 set/unset 共用同一套适配器与凭据，避免重复造 HTTP 签名轮子。
// 记录数据模型定义于 shared/contracts，主进程与渲染层共用。

/** 域名解析管理扩展接口：只有支持通用记录 CRUD 的服务商才实现。 */
export interface DnsManageAdapter {
  listDomains(): Promise<ManagedDnsDomain[]>;
  listRecords(domain: string): Promise<ManagedDnsRecord[]>;
  createRecord(domain: string, input: ManagedDnsRecordInput): Promise<void>;
  updateRecord(domain: string, recordId: string, input: ManagedDnsRecordInput): Promise<void>;
  deleteRecord(domain: string, recordId: string): Promise<void>;
}

/** 完整适配器：ACME 签发与域名解析管理共用同一实例与凭据。 */
export interface DnsFullAdapter extends DnsAdapter, DnsManageAdapter {}

/** 把完整记录名转换成相对于所选主域的子域名：@ / www.example.com → www。 */
function subNameFor(fullName: string, domain: string): string {
  const value = fullName.trim();
  if (!value || value === '@') return '@';
  const lower = value.toLowerCase();
  const base = domain.toLowerCase();
  if (lower === base) return '@';
  if (lower.endsWith(`.${base}`)) return value.slice(0, -(base.length + 1));
  return value;
}

/** 把子域名（DNSPod sub_domain / 阿里云 RR）还原成记录名：@ 代表主域名，其余带主域后缀。 */
function fullNameFor(sub: string, domain: string): string {
  return !sub || sub === '@' ? '@' : `${sub}.${domain}`;
}

export interface DnsAutomationResolution {
  level: DnsAutomation;
  provider: DnsProvider;
  // 可读摘要，写入证书 notes。
  summary: string;
  // 服务商 API 适配器。
  adapter: DnsAdapter;
}

export type DnsCreateHook = (record: DnsChallengeRecord) => Promise<void>;
export type DnsRemoveHook = (record: DnsChallengeRecord) => Promise<void>;

export type AutomationProgress = (value: CertificateIssueProgressUpdate) => void;

// ─────────────────────────── 凭据（只走 store.putSecret） ───────────────────────────

function credentialKeys(namespace: string) {
  const prefix = `dns:${namespace}`;
  return {
    secretId: `${prefix}:secretId`,
    secretKey: `${prefix}:secretKey`,
    token: `${prefix}:token`,
    endpoint: `${prefix}:endpoint`,
  };
}

// 凭据读取绝不抛错：安全存储暂时不可用时按「无凭据」处理，让逐级探测自然降级。
function safeSecret(store: Store, key: string): string {
  try {
    return store.secret(key);
  } catch {
    return '';
  }
}

export function readDnsCredentials(store: Store, namespace: string): DnsCredentials {
  const keys = credentialKeys(namespace);
  return {
    secretId: safeSecret(store, keys.secretId) || undefined,
    secretKey: safeSecret(store, keys.secretKey) || undefined,
    token: safeSecret(store, keys.token) || undefined,
    endpoint: safeSecret(store, keys.endpoint) || undefined,
  };
}

/** 读取已保存 DNS 账户的凭据；命名空间与账户 id 绑定，互不影响。 */
export function readDnsAccountCredentials(store: Store, accountId: string): DnsCredentials {
  return readDnsCredentials(store, `account:${accountId}`);
}

function persistCredentials(store: Store, namespace: string, creds: DnsCredentials) {
  const keys = credentialKeys(namespace);
  store.putSecret(keys.secretId, creds.secretId);
  store.putSecret(keys.secretKey, creds.secretKey);
  store.putSecret(keys.token, creds.token);
  store.putSecret(keys.endpoint, creds.endpoint);
}

// ─────────────────────────── HTTP 帮助 ───────────────────────────

async function httpRequest(
  url: string,
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
  timeoutMs = 15000,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    const text = await response.text();
    if (!response.ok)
      throw new AppError(`DNS 接口返回 HTTP ${response.status}：${text.slice(0, 200)}`);
    return text;
  } finally {
    clearTimeout(timer);
  }
}

async function httpJson(
  url: string,
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<any> {
  const text = await httpRequest(url, init);
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

const MULTI_PART_TLD = new Set([
  'co.uk',
  'com.cn',
  'net.cn',
  'org.cn',
  'gov.cn',
  'ac.cn',
  'com.hk',
  'co.jp',
  'com.tw',
  'com.au',
  'co.nz',
  'com.br',
  'com.sg',
  'com.mx',
]);

// 无公共后缀表时的保守估算：取注册域（eTLD+1）。
function registrableDomain(domain: string): string {
  const parts = domain.toLowerCase().split('.');
  if (parts.length <= 2) return parts.join('.');
  const last2 = parts.slice(-2).join('.');
  return MULTI_PART_TLD.has(last2) ? parts.slice(-3).join('.') : last2;
}

function relativeSubDomain(record: string, domain: string): string {
  const base = registrableDomain(domain);
  return record.toLowerCase().endsWith(`.${base}`) ? record.slice(0, -(base.length + 1)) : record;
}

// ─────────────────────────── 适配器 ───────────────────────────

function cloudflareAdapter(creds: DnsCredentials): DnsFullAdapter {
  if (!creds.token) throw new AppError('缺少 Cloudflare API Token。');
  const base = 'https://api.cloudflare.com/client/v4';
  const headers = { Authorization: `Bearer ${creds.token}`, 'Content-Type': 'application/json' };
  const recordIds = new Map<string, string>();
  async function findZone(domain: string): Promise<{ id: string } | undefined> {
    const parts = domain.toLowerCase().split('.');
    for (let index = 0; index < parts.length - 1; index += 1) {
      const candidate = parts.slice(index).join('.');
      const data = await httpJson(
        `${base}/zones?name=${encodeURIComponent(candidate)}&per_page=1`,
        { headers },
      );
      if (data?.success && Array.isArray(data.result) && data.result.length)
        return data.result[0] as { id: string };
    }
    return undefined;
  }
  return {
    async probe() {
      // 凭据测试只需验证 Token 本身，不再依赖用户填写「测试域名」。
      const verified = await httpJson(`${base}/user/tokens/verify`, { headers });
      return verified?.success === true && verified?.result?.status === 'active';
    },
    async set(record: DnsChallengeRecord) {
      const zone = await findZone(record.domain);
      if (!zone) throw new AppError('Cloudflare 账号下未找到该域名所属 zone。');
      const listed = await httpJson(
        `${base}/zones/${zone.id}/dns_records?type=TXT&name=${encodeURIComponent(record.record)}`,
        { headers },
      );
      if (listed?.success)
        for (const item of listed.result ?? [])
          await httpJson(`${base}/zones/${zone.id}/dns_records/${item.id}`, {
            method: 'DELETE',
            headers,
          }).catch(() => {});
      const created = await httpJson(`${base}/zones/${zone.id}/dns_records`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ type: 'TXT', name: record.record, content: record.value, ttl: 60 }),
      });
      if (!created?.success) throw new AppError('Cloudflare 写入 TXT 失败。');
      recordIds.set(record.record, created.result?.id ?? '');
    },
    async unset(record: DnsChallengeRecord) {
      const id = recordIds.get(record.record);
      const zone = await findZone(record.domain);
      if (id && zone)
        await httpJson(`${base}/zones/${zone.id}/dns_records/${id}`, {
          method: 'DELETE',
          headers,
        }).catch(() => {});
    },
    async listDomains() {
      const data = await httpJson(`${base}/zones?per_page=100&page=1`, { headers });
      if (data?.success !== true) throw new AppError('读取 Cloudflare 域名列表失败。');
      return (data.result ?? [])
        .map((zone: any) => ({ name: String(zone.name ?? '') }))
        .filter((item: ManagedDnsDomain) => item.name);
    },
    async listRecords(domain: string) {
      const zone = await findZone(domain);
      if (!zone) return [];
      const data = await httpJson(`${base}/zones/${zone.id}/dns_records?per_page=100&page=1`, {
        headers,
      });
      if (data?.success !== true) throw new AppError('读取 Cloudflare 解析记录失败。');
      return (data.result ?? []).map((item: any) => ({
        id: String(item.id ?? ''),
        name: String(item.name ?? ''),
        type: String(item.type ?? ''),
        value: String(item.content ?? ''),
        ttl: Number(item.ttl ?? 1),
        proxied: Boolean(item.proxied),
        priority: item.priority === undefined ? undefined : Number(item.priority),
      }));
    },
    async createRecord(domain: string, input: ManagedDnsRecordInput) {
      const zone = await findZone(domain);
      if (!zone) throw new AppError('Cloudflare 账号下未找到该域名所属 zone。');
      const body: Record<string, unknown> = {
        type: input.type,
        name: input.name,
        content: input.value,
        ttl: input.ttl || 1,
      };
      if (input.priority !== undefined) body.priority = input.priority;
      if (input.proxied !== undefined) body.proxied = input.proxied;
      const created = await httpJson(`${base}/zones/${zone.id}/dns_records`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      });
      if (created?.success !== true) throw new AppError('Cloudflare 新增解析记录失败。');
    },
    async updateRecord(domain: string, recordId: string, input: ManagedDnsRecordInput) {
      const zone = await findZone(domain);
      if (!zone) throw new AppError('Cloudflare 账号下未找到该域名所属 zone。');
      const body: Record<string, unknown> = {
        type: input.type,
        name: input.name,
        content: input.value,
        ttl: input.ttl || 1,
      };
      if (input.priority !== undefined) body.priority = input.priority;
      if (input.proxied !== undefined) body.proxied = input.proxied;
      const updated = await httpJson(`${base}/zones/${zone.id}/dns_records/${recordId}`, {
        method: 'PUT',
        headers,
        body: JSON.stringify(body),
      });
      if (updated?.success !== true) throw new AppError('Cloudflare 更新解析记录失败。');
    },
    async deleteRecord(domain: string, recordId: string) {
      const zone = await findZone(domain);
      if (!zone) throw new AppError('Cloudflare 账号下未找到该域名所属 zone。');
      await httpJson(`${base}/zones/${zone.id}/dns_records/${recordId}`, {
        method: 'DELETE',
        headers,
      });
    },
  };
}

function dnspodAdapter(creds: DnsCredentials): DnsFullAdapter {
  if (!creds.secretId || !creds.secretKey) throw new AppError('缺少 DNSPod ID/Token。');
  const base = 'https://dnsapi.cn';
  const loginToken = `${creds.secretId},${creds.secretKey}`;
  const post = (path: string, params: Record<string, string>) =>
    httpJson(`${base}/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        login_token: loginToken,
        format: 'json',
        error_on_empty: 'no',
        ...params,
      }).toString(),
    });
  const recordIds = new Map<string, string>();
  return {
    async probe() {
      const data = await post('Domain.List', {});
      return data?.status?.code === '1';
    },
    async set(record: DnsChallengeRecord) {
      const baseDomain = registrableDomain(record.domain);
      const sub = relativeSubDomain(record.record, record.domain);
      const listed = await post('Record.List', { domain: baseDomain, sub_domain: sub });
      if (listed?.status?.code === '1')
        for (const item of listed.records ?? [])
          await post('Record.Remove', { domain: baseDomain, record_id: String(item.id) }).catch(
            () => {},
          );
      const created = await post('Record.Create', {
        domain: baseDomain,
        sub_domain: sub,
        record_type: 'TXT',
        record_line: '默认',
        value: record.value,
        ttl: '60',
      });
      if (created?.status?.code !== '1') throw new AppError('DNSPod 写入 TXT 失败。');
      recordIds.set(record.record, String(created.record?.id ?? ''));
    },
    async unset(record: DnsChallengeRecord) {
      const id = recordIds.get(record.record);
      if (id)
        await post('Record.Remove', {
          domain: registrableDomain(record.domain),
          record_id: id,
        }).catch(() => {});
    },
    async listDomains() {
      const data = await post('Domain.List', {});
      if (data?.status?.code !== '1') throw new AppError('读取 DNSPod 域名列表失败。');
      return (data.domains ?? [])
        .map((item: any) => ({ name: String(item.name ?? '') }))
        .filter((item: ManagedDnsDomain) => item.name);
    },
    async listRecords(domain: string) {
      const data = await post('Record.List', { domain });
      if (data?.status?.code !== '1') throw new AppError('读取 DNSPod 解析记录失败。');
      return (data.records ?? []).map((item: any) => ({
        id: String(item.id ?? ''),
        name: fullNameFor(String(item.name ?? ''), domain),
        type: String(item.type ?? ''),
        value: String(item.value ?? ''),
        ttl: Number(item.ttl ?? 600),
        line: item.line ? String(item.line) : undefined,
        priority: item.mx === undefined ? undefined : Number(item.mx),
      }));
    },
    async createRecord(domain: string, input: ManagedDnsRecordInput) {
      const params: Record<string, string> = {
        domain,
        sub_domain: subNameFor(input.name, domain),
        record_type: input.type,
        record_line: input.line || '默认',
        value: input.value,
        ttl: String(input.ttl || 600),
      };
      if (input.priority !== undefined) params.mx = String(input.priority);
      const data = await post('Record.Create', params);
      if (data?.status?.code !== '1') throw new AppError('DNSPod 新增解析记录失败。');
    },
    async updateRecord(domain: string, recordId: string, input: ManagedDnsRecordInput) {
      const params: Record<string, string> = {
        domain,
        record_id: recordId,
        sub_domain: subNameFor(input.name, domain),
        record_type: input.type,
        record_line: input.line || '默认',
        value: input.value,
        ttl: String(input.ttl || 600),
      };
      if (input.priority !== undefined) params.mx = String(input.priority);
      const data = await post('Record.Modify', params);
      if (data?.status?.code !== '1') throw new AppError('DNSPod 更新解析记录失败。');
    },
    async deleteRecord(domain: string, recordId: string) {
      const data = await post('Record.Remove', { domain, record_id: recordId });
      if (data?.status?.code !== '1') throw new AppError('DNSPod 删除解析记录失败。');
    },
  };
}

function aliyunAdapter(creds: DnsCredentials): DnsFullAdapter {
  if (!creds.secretId || !creds.secretKey) throw new AppError('缺少阿里云 AccessKey。');
  const endpoint = 'https://alidns.aliyuncs.com/';
  const percentEncode = (value: string) =>
    encodeURIComponent(value).replace(
      /[!'()*]/g,
      (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
    );
  const recordIds = new Map<string, string>();
  async function rpc(action: string, params: Record<string, string>): Promise<any> {
    const common: Record<string, string> = {
      Format: 'JSON',
      Version: '2015-01-09',
      AccessKeyId: creds.secretId!,
      SignatureMethod: 'HMAC-SHA1',
      Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      SignatureVersion: '1.0',
      SignatureNonce: randomBytes(8).toString('hex'),
      Action: action,
      ...params,
    };
    const canonical = Object.keys(common)
      .sort()
      .map((key) => `${percentEncode(key)}=${percentEncode(common[key])}`)
      .join('&');
    const stringToSign = `GET&${percentEncode('/')}&${percentEncode(canonical)}`;
    const signature = createHmac('sha1', `${creds.secretKey}&`)
      .update(stringToSign)
      .digest('base64');
    const url = `${endpoint}?Signature=${percentEncode(signature)}&${canonical}`;
    return httpJson(url);
  }
  return {
    async probe() {
      const data = await rpc('DescribeDomains', { PageNumber: '1', PageSize: '1' });
      // 正常响应带 DomainRecords，错误响应带 Code。
      return Boolean(data && !data.Code);
    },
    async set(record: DnsChallengeRecord) {
      const baseDomain = registrableDomain(record.domain);
      const rr = relativeSubDomain(record.record, record.domain);
      const listed = await rpc('DescribeDomainRecords', {
        DomainName: baseDomain,
        RRKeyWord: rr,
        TypeKeyWord: 'TXT',
      });
      if (listed?.DomainRecords?.Record)
        for (const item of listed.DomainRecords.Record)
          await rpc('DeleteDomainRecord', { RecordId: String(item.RecordId) }).catch(() => {});
      const created = await rpc('AddDomainRecord', {
        DomainName: baseDomain,
        RR: rr,
        Type: 'TXT',
        Value: record.value,
        // 阿里云 DNS 要求 TTL 在 600~86400 秒之间，60 会被拒（QuotaExceeded.TTL）。
        TTL: '600',
      });
      if (!created?.RecordId) throw new AppError('阿里云 DNS 写入 TXT 失败。');
      recordIds.set(record.record, String(created.RecordId));
    },
    async unset(record: DnsChallengeRecord) {
      const id = recordIds.get(record.record);
      if (id) await rpc('DeleteDomainRecord', { RecordId: id }).catch(() => {});
    },
    async listDomains() {
      const data = await rpc('DescribeDomains', { PageNumber: '1', PageSize: '100' });
      if (data?.Code) throw new AppError('读取阿里云域名列表失败。');
      return ((data?.Domains?.Domain ?? []) as any[])
        .map((item) => ({ name: String(item.DomainName ?? '') }))
        .filter((item: ManagedDnsDomain) => item.name);
    },
    async listRecords(domain: string) {
      const data = await rpc('DescribeDomainRecords', {
        DomainName: domain,
        PageNumber: '1',
        PageSize: '100',
      });
      if (data?.Code) throw new AppError('读取阿里云解析记录失败。');
      return ((data?.DomainRecords?.Record ?? []) as any[]).map((item) => ({
        id: String(item.RecordId ?? ''),
        name: fullNameFor(String(item.RR ?? ''), domain),
        type: String(item.Type ?? ''),
        value: String(item.Value ?? ''),
        ttl: Number(item.TTL ?? 600),
        line: item.Line ? String(item.Line) : undefined,
        priority: item.Priority === undefined ? undefined : Number(item.Priority),
      }));
    },
    async createRecord(domain: string, input: ManagedDnsRecordInput) {
      const params: Record<string, string> = {
        DomainName: domain,
        RR: subNameFor(input.name, domain),
        Type: input.type,
        Value: input.value,
        // 阿里云 DNS 要求 TTL 在 600~86400 秒之间。
        TTL: String(Math.max(600, input.ttl || 600)),
      };
      if (input.line) params.Line = input.line;
      if (input.priority !== undefined) params.Priority = String(input.priority);
      const data = await rpc('AddDomainRecord', params);
      if (!data?.RecordId) throw new AppError('阿里云新增解析记录失败。');
    },
    async updateRecord(domain: string, recordId: string, input: ManagedDnsRecordInput) {
      const params: Record<string, string> = {
        RecordId: recordId,
        RR: subNameFor(input.name, domain),
        Type: input.type,
        Value: input.value,
        TTL: String(Math.max(600, input.ttl || 600)),
      };
      if (input.line) params.Line = input.line;
      if (input.priority !== undefined) params.Priority = String(input.priority);
      const data = await rpc('UpdateDomainRecord', params);
      if (!data?.RecordId) throw new AppError('阿里云更新解析记录失败。');
    },
    async deleteRecord(_domain: string, recordId: string) {
      await rpc('DeleteDomainRecord', { RecordId: recordId });
    },
  };
}

function adapterForProvider(provider: DnsProvider, creds: DnsCredentials): DnsFullAdapter {
  switch (provider) {
    case 'cloudflare':
      return cloudflareAdapter(creds);
    case 'dnspod':
      return dnspodAdapter(creds);
    case 'aliyun':
      return aliyunAdapter(creds);
    default:
      throw new AppError(`服务商 ${provider} 不提供 API 自动化。`);
  }
}

/** 按已保存账户构造完整适配器：provider 与凭据都来自账户，界面无需接触明文。 */
export function manageAdapterForAccount(
  provider: string,
  store: Store,
  accountId: string,
): DnsManageAdapter {
  const creds = readDnsAccountCredentials(store, accountId);
  if (!creds.secretId && !creds.token)
    throw new AppError('该 DNS 账户尚未保存有效凭据，请先在账户管理中重新测试并保存。');
  return adapterForProvider(normalizeProvider(provider), creds);
}

// ─────────────────────────── 凭据探测 ───────────────────────────

function normalizeProvider(value: string): DnsProvider {
  const allowed: DnsProvider[] = ['dnspod', 'aliyun', 'cloudflare'];
  if (!allowed.includes(value as DnsProvider))
    throw new AppError('不支持的 DNS 服务商，请选择 DNSPod、阿里云 DNS 或 Cloudflare。');
  return value as DnsProvider;
}

async function safeProbe(adapter: DnsAdapter, domain: string): Promise<boolean> {
  try {
    return await adapter.probe(domain);
  } catch {
    return false;
  }
}

/**
 * 探测选中 DNS 账户的服务商 API；失败直接抛错，不再降级到 CNAME 委派 / 手动 TXT。
 * 旧版全局单服务商配置仍可作为账户缺失时的兼容回退。
 */
export async function resolveAutomation(
  provider: string,
  store: Store,
  domains: string[],
  onProgress?: AutomationProgress,
  accountId?: string,
): Promise<DnsAutomationResolution> {
  const dnsProvider = normalizeProvider(provider);
  const primary = domains[0] ?? '';
  const report = (message: string) =>
    onProgress?.({ status: 'running', step: 'DNS-01 自动化探测', message });

  const creds = accountId
    ? readDnsAccountCredentials(store, accountId)
    : readDnsCredentials(store, dnsProvider);
  let adapter: DnsAdapter;
  try {
    adapter = adapterForProvider(dnsProvider, creds);
    if (await safeProbe(adapter, primary)) {
      report(`DNS 服务商 API 可用（${dnsProvider}），采用全自动 DNS-01。`);
      return {
        level: 'api',
        provider: dnsProvider,
        adapter,
        summary: `全自动：${dnsProvider} API 自动增删 _acme-challenge TXT。`,
      };
    }
  } catch (error) {
    const detail = redact(
      error instanceof Error ? error.message : String(error),
      store.allSecrets(),
    ).slice(0, 300);
    throw new AppError(`${detail}；请在设置中重新测试并保存 DNS 账户凭据后重试。`);
  }
  throw new AppError('DNS 账户凭据不可用或接口探测失败，请在设置中重新测试并保存凭据后重试。');
}

// ─────────────────────────── acme-client hooks ───────────────────────────
// 返回值供 certificates.ts 引擎的 challengeCreateFn / challengeRemoveFn 使用：
// 引擎把 (authorization, challenge, keyAuthorization) 映射成 DnsChallengeRecord 后调用。

export function createDnsHook(
  resolution: DnsAutomationResolution,
  onProgress?: AutomationProgress,
): DnsCreateHook {
  return async (record: DnsChallengeRecord) => {
    onProgress?.({
      status: 'running',
      step: `写入 DNS-01：${record.domain}`,
      message: '正在通过服务商 API 自动写入 TXT。',
      dnsAutomation: resolution.level,
    });
    await resolution.adapter.set(record);
  };
}

export function removeDnsHook(resolution: DnsAutomationResolution): DnsRemoveHook {
  return async (record: DnsChallengeRecord) => {
    await resolution.adapter.unset(record).catch(() => {});
  };
}

// ─────────────────────────── 凭据测试 ───────────────────────────

export interface DnsTestResult {
  ok: boolean;
  provider: DnsProvider;
  message: string;
}

/** 校验凭据并（仅在成功时）经 store.putSecret 持久化；失败不保存任何明文。 */
export async function testDnsAccount(
  input: DnsAccountTestInput,
  store: Store,
): Promise<DnsTestResult> {
  const provider = normalizeProvider(input.provider);
  const accountId = input.id;
  if (!accountId) return { ok: false, provider, message: '账户标识缺失，请先保存账户。' };
  const existing = readDnsAccountCredentials(store, accountId);
  const keep = (value: string | undefined, old: string | undefined) => value || old || undefined;
  const creds: DnsCredentials = {
    secretId: keep(input.secretId, existing.secretId),
    secretKey: keep(input.secretKey, existing.secretKey),
    token: keep(input.token, existing.token),
    endpoint: keep(input.endpoint, existing.endpoint),
  };
  try {
    const adapter = adapterForProvider(provider, creds);
    const ok = await adapter.probe();
    if (!ok) return { ok: false, provider, message: '凭据或接口探测失败，请检查后重试。' };
    persistCredentials(store, `account:${accountId}`, creds);
    await store.persist();
    return { ok: true, provider, message: `${input.name || provider} 凭据校验通过并已安全保存。` };
  } catch (error) {
    return {
      ok: false,
      provider,
      message: redact(
        error instanceof Error ? error.message : String(error),
        store.allSecrets(),
      ).slice(0, 400),
    };
  }
}

export async function testDnsProvider(input: DnsTestInput, store: Store): Promise<DnsTestResult> {
  const provider = normalizeProvider(input.provider);
  const creds: DnsCredentials = {
    secretId: input.secretId,
    secretKey: input.secretKey,
    token: input.token,
    endpoint: input.endpoint,
  };
  try {
    const adapter = adapterForProvider(provider, creds);
    const ok = await adapter.probe();
    if (!ok) return { ok: false, provider, message: '凭据或接口探测失败，请检查后重试。' };
    persistCredentials(store, provider, creds);
    await store.persist();
    return { ok: true, provider, message: `${provider} 凭据校验通过并已安全保存。` };
  } catch (error) {
    return {
      ok: false,
      provider,
      message: redact(
        error instanceof Error ? error.message : String(error),
        store.allSecrets(),
      ).slice(0, 400),
    };
  }
}
