<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import type {
  State,
  Server,
  Instance,
  ProxyRule,
  Catalog,
  InstalledVersion,
  HostInfo,
  HostPortStatus,
  Runtime,
  Deployment,
  FrpsServiceCandidate,
  InstallRequest,
  CertificateIssueProgress,
  TerminalFavorite,
  TerminalHistory,
  ServerCertificate,
  Settings,
  DnsAccount,
  DnsAutomation,
  DnsProviderId,
  DownloadProgress,
  DownloadTaskView,
  ServerDeployProgress,
  VersionResolution,
  InstallPrecheck,
  WebIncludeStatus,
  WebIncludeFlavor,
} from '../shared/types';
import logoUrl from '../../assets/brand/logo.svg';
import { accessAddress } from '../shared/address';
import {
  detectSiteFlavor,
  generateSiteConfig,
  siteFlavorLabel,
  type SiteConfigFlavor,
} from '../shared/site-config';
import { decideTlsPlan, type TlsPlan } from '../shared/tls-plan';
import {
  ACTIONS,
  CHECKSUM_UNAVAILABLE,
  type EnsureVersionArgs,
  type EnsureVersionResult,
  type SiteConfigReadResult,
  type ManagedDnsDomain,
  type ManagedDnsRecord,
  type CertificateDetail,
  type MaskedCredentials,
} from '../shared/contracts';
import ToastHost from './components/ToastHost.vue';
import ConfirmDialog from './components/ConfirmDialog.vue';
import AppModal from './components/AppModal.vue';
import AppDrawer from './components/AppDrawer.vue';
import ProgressPanel from './components/ProgressPanel.vue';
import EmptyState from './components/EmptyState.vue';
import StatusBadge from './components/StatusBadge.vue';
import FormField from './components/FormField.vue';
import SectionCard from './components/SectionCard.vue';
import AppSidebar from './components/AppSidebar.vue';
import HelpPage from './components/HelpPage.vue';
import DownloadCenter from './components/DownloadCenter.vue';
import AppSelect from './components/AppSelect.vue';
import CodeEditor from './components/CodeEditor.vue';

const api = window.desktop;
const uid = () => crypto.randomUUID();

type PageKey =
  'servers' | 'versions' | 'clients' | 'serverCerts' | 'dns' | 'terminal' | 'settings' | 'help';
type ToastType = 'success' | 'info' | 'warning' | 'error';
interface ToastOpts {
  title?: string;
  actionLabel?: string;
  action?: () => void;
  duration?: number;
}
interface ToastItem extends ToastOpts {
  id: string;
  type: ToastType;
  message: string;
}
interface ConfirmSpec {
  title: string;
  message?: string;
  level?: string;
  impacts?: string[];
  confirmWord?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  // 三选确认的可选动作（如安装预检里的「保存为只读」）。
  altLabel?: string;
  altTone?: 'primary' | 'danger' | 'soft';
  onConfirm: () => void | Promise<void>;
  onAlt?: () => void | Promise<void>;
  onCancel?: () => void;
}

/* ---------------- 应用状态 ---------------- */
const state = ref<State>({
  servers: [],
  instances: [],
  certificates: [],
  serverSites: [],
  serverCertificates: [],
  dnsAccounts: [],
  terminalFavorites: [],
  versions: [],
  settings: {
    proxyUrl: '',
    dnsProvider: 'dnspod',
    acmeEmail: '',
    litesslEabConfigured: false,
    deployDefault: 'manual',
    catalogCacheHours: 24,
    downloadRetries: 3,
    managedTlsEnabled: false,
    confirmDangerous: true,
    theme: 'light',
  },
  secureStorage: true,
  platform: '',
  arch: '',
  catalog: null,
  downloads: [],
  siteInspections: {},
  managedTls: null,
  webIncludes: {},
});
const runtime = ref<{
  clients: Record<string, Runtime>;
  ssh: Record<string, string>;
  services: Record<string, string>;
  serviceErrors: Record<string, string>;
}>({ clients: {}, ssh: {}, services: {}, serviceErrors: {} });
const page = ref<PageKey>('servers');
const busy = ref(false);
const selectedServer = ref('');
const selectedInstance = ref('');
const activeModal = ref('');
const sidebarCollapsed = ref(false);
const logText = ref('');
const logKind = ref<'server' | 'instance'>('instance');
const logTarget = ref('');
const catalog = ref<Catalog>();
const targetPlatform = ref<InstallRequest['platform']>('darwin');
const targetArch = ref<InstallRequest['arch']>('arm64');
const serverDraft = ref<Server>();
const instanceDraft = ref<Instance>();
/* 规则独立 CRUD：草稿、所属实例、编辑态、Web 规则左侧标签。 */
type RuleDraft = ProxyRule & { certPem?: string; keyPem?: string };
const ruleDraft = ref<RuleDraft>();
const ruleInstanceId = ref('');
const ruleIsEdit = ref(false);
const ruleTab = ref<'basic' | 'config' | 'ssl'>('basic');
const ruleKind = ref<'tcp' | 'udp' | 'web'>('tcp');
// 规则弹窗单独缓存所属服务器的 Web 软件探测结果，避免误用服务器页当前选中的机器。
const ruleHostInfo = ref<HostInfo>();
const ruleHostInfoServerId = ref('');
const ruleConfigDetecting = ref(false);
const ruleConfigSaving = ref(false);
const ruleConfigCopying = ref(false);
const ruleConfigRegenerating = ref(false);
const ruleConfigLoading = ref(false);
// 配置编辑器被用户改动后，不再用服务器内容覆盖；可点「读取服务器」强制刷新。
const ruleConfigDirty = ref(false);
const ruleConfigProgrammatic = ref(false);
const ruleCertRemoving = ref(false);
const ruleCertDetail = ref<CertificateDetail>();
const ruleCertDetailLoading = ref(false);
const ruleCertDetailError = ref('');
const ruleListTab = ref<'site' | 'service'>('site');
// 当前规则所属服务器的 TLS 方案；由服务器探测 + include 探针判定，供配置模板与证书弹窗共用。
const ruleTlsPlan = ref<TlsPlan>();
const certApplyPlan = ref<TlsPlan>();
const certApplyPlanLoading = ref(false);
// 快速切换实例/重开弹窗时，丢弃过期的探测响应，避免旧服务器结果覆盖新弹窗。
let certApplyPlanSeq = 0;
const certApplyDraft = reactive({
  provider: 'letsencrypt' as 'letsencrypt' | 'litessl',
  keySize: 2048 as 2048 | 3072 | 4096,
  challenge: 'dns-01' as 'http-01' | 'dns-01',
  domainIds: [] as string[],
  allDomains: true,
  email: '',
  dnsAccountId: '',
  termsAgreed: false,
});
const versionChoice = ref('');
const hostInfo = ref<HostInfo>();
const systemInfoExpanded = ref(true);
const webIncludeStatus = ref<WebIncludeStatus>();
const webIncludeLoading = ref(false);
const webIncludeApplying = ref<'' | WebIncludeFlavor>('');
const webIncludeRemoving = ref(false);
const autostartEnabled = ref<boolean | null>(null);
const backups = ref<Array<{ kind: 'binary' | 'config'; path: string; time: number }>>([]);
const abandonRaw = ref(false);
const manual = reactive({ version: '', url: '', localPath: '', digest: '' });
const certificateProgress = ref<CertificateIssueProgress>();
const certificateProgressHistory = ref<CertificateIssueProgress[]>([]);
const activeCertificateTask = ref('');
const terminalTabs = ref<
  Array<{ id: string; serverId: string; title: string; history: TerminalHistory }>
>([]);
const activeTerminalId = ref('');
const terminalPaneCollapsed = ref(false);
const terminalFavoritesCollapsed = ref(false);
const terminalHistoryCollapsed = ref(false);
const terminalHistoryLoading = ref(false);
const terminalHistoryNotice = ref('');
const terminalFavoriteDraft = reactive({ id: '', name: '', command: '' });
const terminalContextMenu = ref<{ x: number; y: number; command: string; favoriteId?: string }>();
const terminalInstances = new Map<string, { terminal: Terminal; fit: FitAddon }>();

/* 下载任务中心：跨页面常驻，一个 taskId 一条进度 */
const downloadTasks = ref<DownloadTaskView[]>([]);
const downloadLaunchers = new Map<string, () => void>();
// 服务端安装进度：点击后本地即刻 seed，主进程事件逐步覆盖，失败时保留具体错误。
const serverDeployProgress = ref<ServerDeployProgress | null>(null);
const serverDeploySteps = ref<
  Array<{ label: string; detail?: string; time?: number; tone?: string }>
>([]);

/* 证书管理：申请入口统一收敛到客户端实例的 Web 规则；本页只读 + 下载/删除。 */
const certSearch = ref('');
const certPage = ref(1);
const certPageSize = 8;
const certDetailOpen = ref(false);
const certDetail = ref<CertificateDetail>();
const certDetailLoading = ref(false);
const certDownloading = ref(false);
const certDeleting = ref(false);
const selectedCertServer = ref('');
const dnsAutomation = ref<DnsAutomation>('api');
const deployMode = ref<'manual' | 'auto'>('manual');
const deployLevel = ref<'L0' | 'L1' | 'L2'>('L0');
const acmeMasked = ref({ eabKid: '', eabHmac: '' });
const settingsDraft = reactive({
  proxyUrl: '',
  acmeEmail: '',
  eabKid: '',
  eabHmac: '',
  deployDefault: 'manual' as Settings['deployDefault'],
  catalogCacheHours: 24 as number,
  downloadRetries: 3 as number,
  confirmDangerous: true,
  theme: 'light' as Settings['theme'],
});
const dnsAccountDraft = reactive({
  id: '',
  name: '',
  provider: 'dnspod' as DnsProviderId,
  secretId: '',
  secretKey: '',
  token: '',
  endpoint: '',
});
const dnsAccountResult = ref('');
const dnsAccountResultTone = ref<'success' | 'error'>('success');
const dnsAccountMasked = ref<MaskedCredentials>({});

// DNS 管理：域名解析在前、账户管理在后
const dnsTab = ref<'records' | 'accounts'>('records');
const dnsManage = reactive({
  accountId: '',
  domain: '',
  domains: [] as ManagedDnsDomain[],
  records: [] as ManagedDnsRecord[],
  loadingDomains: false,
  loadingRecords: false,
});
const dnsRecordDraft = reactive({
  recordId: '',
  name: '',
  type: 'A',
  value: '',
  ttl: 600,
  line: '',
  priority: '' as number | '',
  proxied: false,
});
const dnsRecordOptions = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SRV', 'CAA'];
// 账户被删除后清掉失效选择，避免继续用旧 id 查询。
watch(
  () => state.value.dnsAccounts.map((item) => item.id).join(','),
  () => {
    if (
      dnsManage.accountId &&
      !state.value.dnsAccounts.some((item) => item.id === dnsManage.accountId)
    ) {
      dnsManage.accountId = '';
      dnsManage.domains = [];
      dnsManage.records = [];
      dnsManage.domain = '';
    }
  },
);

let unsubscribeTerminal: (() => void) | undefined;
let unsubscribeCertificateProgress: (() => void) | undefined;
let unsubscribeDownloadProgress: (() => void) | undefined;
let unsubscribeServerDeployProgress: (() => void) | undefined;
let unsubscribe: () => void;
let timer: ReturnType<typeof setInterval>;

/* ---------------- 导航与页面元信息 ---------------- */
const titles: Record<PageKey, string> = {
  servers: '服务器',
  versions: '版本库',
  clients: '客户端实例',
  serverCerts: '证书管理',
  dns: 'DNS 管理',
  terminal: '终端',
  settings: '设置',
  help: '帮助',
};
const descriptions: Record<PageKey, string> = {
  servers: '连接服务器、预检并安装 FRP 服务端，或管理已有部署。',
  versions: '管理已安装包与官方列表，支持离线导入；下载进度在任务中心显示。',
  clients: '将本机服务分享出去，多套配置与代理规则可同时运行。',
  serverCerts: '查看已签发的证书与部署位置；申请证书请从客户端实例的 Web 规则发起。',
  dns: '维护 DNS 服务商账户，并直接查询与增删改域名解析记录。',
  terminal: '通过 SSH 连接已添加的服务器，管理多个独立终端会话。',
  settings: 'ACME 邮箱与 EAB、部署默认值、下载策略与安全确认。',
  help: '端口约束、证书终止位置、托管实例隔离与常见问题。',
};
// 扁平导航：菜单项少，直接平铺，不再分组折叠。
const navItems = computed(() => [
  { key: 'servers', label: '服务器', icon: 'servers', badge: state.value.servers.length },
  { key: 'versions', label: '版本库', icon: 'versions' },
  { key: 'clients', label: '客户端实例', icon: 'clients', badge: state.value.instances.length },
  { key: 'dns', label: 'DNS 管理', icon: 'dns', badge: state.value.dnsAccounts.length },
  { key: 'serverCerts', label: '证书管理', icon: 'serverCerts' },
  { key: 'terminal', label: '终端', icon: 'terminal' },
  { key: 'settings', label: '设置', icon: 'settings' },
  { key: 'help', label: '帮助', icon: 'help' },
]);
const runtimeLabel = computed(() => {
  const running = Object.values(runtime.value.clients).filter((c) =>
    ['running', 'connected', 'starting'].includes(c.status),
  ).length;
  const ssh = Object.values(runtime.value.ssh).filter((s) => s === 'connected').length;
  if (running) return `${running} 个实例运行中`;
  if (ssh) return `${ssh} 台 SSH 已连接`;
  return '空闲';
});
const runtimeTone = computed(() => (runtimeLabel.value === '空闲' ? 'neutral' : 'success'));

/* ---------------- 统一反馈：Toast / Confirm / Modal ---------------- */
const toasts = ref<ToastItem[]>([]);
function dismissToast(id: string) {
  toasts.value = toasts.value.filter((t) => t.id !== id);
}
function pushToast(type: ToastType, message: string, opts: ToastOpts = {}) {
  const id = uid();
  toasts.value.push({ id, type, message, ...opts });
  const duration = opts.duration ?? (type === 'error' ? 7000 : 4500);
  if (duration > 0 && !opts.action) setTimeout(() => dismissToast(id), duration);
}
const toastSuccess = (m: string, o?: ToastOpts) => pushToast('success', m, o);
const toastInfo = (m: string, o?: ToastOpts) => pushToast('info', m, o);
const toastWarning = (m: string, o?: ToastOpts) => pushToast('warning', m, o);
const toastError = (m: string, o?: ToastOpts) => pushToast('error', m, o);
function onToastAction(id: string) {
  const item = toasts.value.find((t) => t.id === id);
  item?.action?.();
  dismissToast(id);
}

const confirmState = ref<ConfirmSpec | null>(null);
function askConfirm(spec: ConfirmSpec) {
  confirmState.value = spec;
}
async function acceptConfirm() {
  const spec = confirmState.value;
  if (!spec) return;
  confirmState.value = null;
  await spec.onConfirm();
}
async function acceptAltConfirm() {
  const spec = confirmState.value;
  if (!spec?.onAlt) return;
  confirmState.value = null;
  await spec.onAlt();
}
function cancelConfirm() {
  const spec = confirmState.value;
  confirmState.value = null;
  spec?.onCancel?.();
}
// 危险 action 统一走渲染层确认；confirmDangerous 关闭时直接执行。
function confirmedPayload(payload: unknown): unknown {
  if (typeof payload === 'string') return { id: payload, confirmed: true };
  if (payload && typeof payload === 'object')
    return { ...(payload as Record<string, unknown>), confirmed: true };
  return { confirmed: true };
}
function runDangerous(
  spec: Omit<ConfirmSpec, 'onConfirm'>,
  action: string,
  payload?: unknown,
  success = '操作已完成。',
) {
  const wrapped = confirmedPayload(payload);
  const execute = () => {
    void act(action, wrapped, success);
  };
  if (state.value.settings.confirmDangerous === false) {
    execute();
    return;
  }
  askConfirm({ ...spec, onConfirm: execute });
}
function openModal(key: string) {
  activeModal.value = key;
}
function closeModal() {
  if (!busy.value) activeModal.value = '';
}

/* ---------------- RPC 基础 ---------------- */
async function rpc<T>(action: string, payload?: unknown): Promise<T> {
  if (!api) throw new Error('此页面需在 Electron 桌面应用中使用，请运行 npm run dev。');
  const result = await api.call<T>(
    action,
    payload === undefined ? undefined : JSON.parse(JSON.stringify(payload)),
  );
  if (!result.ok) {
    const error = new Error(result.error) as Error & { code?: string };
    error.code = result.code;
    throw error;
  }
  return result.data;
}
async function refresh() {
  state.value = await rpc<State>('state');
  if (!selectedServer.value || !state.value.servers.some((s) => s.id === selectedServer.value))
    selectedServer.value = state.value.servers[0]?.id ?? '';
  if (
    !selectedInstance.value ||
    !state.value.instances.some((s) => s.id === selectedInstance.value)
  )
    selectedInstance.value = state.value.instances[0]?.id ?? '';
  await refreshRuntime();
  await refreshAcmeMasked().catch(() => {});
}
async function refreshAcmeMasked() {
  acmeMasked.value = await rpc<{ eabKid: string; eabHmac: string }>(ACTIONS.acmeMasked);
}
async function refreshRuntime() {
  runtime.value = await rpc('runtime');
  const current = server.value;
  if (current?.deployment && runtime.value.ssh[current.id] === 'connected') {
    try {
      autostartEnabled.value = await rpc<boolean | null>(ACTIONS.serverAutostart, current.id);
    } catch {
      autostartEnabled.value = null;
    }
  } else {
    autostartEnabled.value = null;
  }
}
// 所有 action 都经此函数：结果 → Toast，错误 → Toast，成功后刷新状态。
async function act(
  action: string,
  payload?: unknown,
  success = '',
): Promise<{ ok: boolean; data?: any }> {
  if (busy.value) return { ok: false };
  busy.value = true;
  try {
    const data = await rpc<any>(action, payload);
    const text = typeof data === 'string' ? data : (data?.note ?? success);
    if (text) toastSuccess(text);
    await refresh();
    return { ok: true, data };
  } catch (e) {
    toastError((e as Error).message);
    return { ok: false };
  } finally {
    busy.value = false;
  }
}

/* ---------------- 派生数据 ---------------- */
const server = computed(() => state.value.servers.find((s) => s.id === selectedServer.value));
const instance = computed(() => state.value.instances.find((s) => s.id === selectedInstance.value));
const localVersions = computed(() =>
  state.value.versions.filter(
    (v) => v.platform === state.value.platform && v.arch === state.value.arch,
  ),
);
const activeTerminal = computed(() =>
  terminalTabs.value.find((tab) => tab.id === activeTerminalId.value),
);
const terminalServer = (id: string) => state.value.servers.find((item) => item.id === id);
const inspection = computed(() => state.value.siteInspections[selectedCertServer.value] ?? null);

/* ---------------- 长任务：统一 ProgressPanel 数据 ---------------- */
const downloadStatusLabels: Record<string, string> = {
  starting: '准备下载',
  downloading: '下载中',
  retrying: '重试中',
  paused: '已暂停',
  verifying: '校验中',
  extracting: '解压中',
  succeeded: '下载完成',
  failed: '下载失败',
  cancelled: '已取消',
};
const dnsAutomationLabels: Record<string, string> = {
  manual: '手动 TXT',
  api: '服务商 API',
  cname: 'CNAME 委派',
  reuse: '复用已有记录',
};
const deployStateMeta: Record<string, { label: string; tone: string }> = {
  pending: { label: '待部署', tone: 'warning' },
  'awaiting-confirm': { label: '待确认', tone: 'info' },
  deployed: { label: '已生效', tone: 'success' },
  'needs-review': { label: '需复核', tone: 'danger' },
  manual: { label: '手动部署', tone: 'neutral' },
};
const portOwnerMeta: Record<string, { label: string; tone: string }> = {
  free: { label: '空闲', tone: 'success' },
  'managed-tls': { label: '托管 TLS 实例', tone: 'info' },
  'system-nginx': { label: '系统 nginx', tone: 'warning' },
  other: { label: '其他进程', tone: 'danger' },
};
/* ---------------- 下载任务中心 ---------------- */
// 点击即刻插入本地 starting 任务：不等 IPC 往返，消除「点了没反应」的静默期。
function seedDownloadTask(input: {
  taskId: string;
  label: string;
  purpose: DownloadTaskView['purpose'];
  version: string;
}) {
  const now = Date.now();
  const task: DownloadTaskView = {
    ...input,
    status: 'starting',
    percent: 0,
    speed: 0,
    received: 0,
    total: 0,
    message: '正在准备安装包…',
    attempt: 1,
    resumable: false,
    updatedAt: now,
    steps: [
      { label: '准备中', detail: '已提交任务，等待主进程响应。', time: now, tone: 'running' },
    ],
  };
  const index = downloadTasks.value.findIndex((item) => item.taskId === input.taskId);
  const next = [...downloadTasks.value];
  if (index >= 0) next[index] = task;
  else next.push(task);
  downloadTasks.value = next;
}

// 把 download:progress 累积成任务视图；同一 taskId 覆盖，不同 taskId 并存。
function upsertDownloadTask(progress: DownloadProgress) {
  const previous = downloadTasks.value.find((item) => item.taskId === progress.taskId);
  const steps = [...(previous?.steps ?? [])];
  const label = downloadStatusLabels[progress.status] ?? progress.status;
  const last = steps.at(-1);
  if (!last || last.label !== label || last.detail !== progress.message)
    steps.push({
      label,
      detail: progress.message,
      time: progress.updatedAt,
      tone:
        progress.status === 'failed' || progress.status === 'cancelled'
          ? 'danger'
          : progress.status === 'succeeded'
            ? 'success'
            : 'running',
    });
  const task: DownloadTaskView = {
    taskId: progress.taskId,
    label: progress.label ?? previous?.label ?? `下载 FRP ${progress.version}`,
    purpose: progress.purpose ?? previous?.purpose ?? 'manual',
    version: progress.version || previous?.version || '',
    status: progress.status,
    percent: progress.percent,
    speed: progress.speed,
    received: progress.received,
    total: progress.total,
    message: progress.message,
    attempt: progress.attempt,
    resumable: progress.resumable,
    updatedAt: progress.updatedAt,
    steps,
  };
  const index = downloadTasks.value.findIndex((item) => item.taskId === progress.taskId);
  const next = [...downloadTasks.value];
  if (index >= 0) next[index] = task;
  else next.push(task);
  downloadTasks.value = next;
}

// 服务端安装：确认后立刻本地 seed，不等 IPC 往返，避免「点了没反应」的静默期。
function seedServerDeploy(taskId: string, serverId: string, version = '') {
  const now = Date.now();
  serverDeploySteps.value = [
    {
      label: '准备中',
      detail: '正在检查服务器现状与安装条件。',
      time: now,
      tone: 'running',
    },
  ];
  serverDeployProgress.value = {
    taskId,
    serverId,
    status: 'starting',
    step: '准备中',
    message: version ? `正在准备 FRP ${version} 服务端安装包` : '正在检查服务器现状与安装条件',
    percent: 0,
    updatedAt: now,
  };
}
function updateServerDeploy(progress: ServerDeployProgress) {
  // 失败事件正文可能为空，时间线上改用 error，否则最后一步看着像什么都没发生。
  const detail =
    progress.status === 'failed' ? (progress.error ?? progress.message) : progress.message;
  const last = serverDeploySteps.value.at(-1);
  if (!last || last.label !== progress.step || last.detail !== detail)
    serverDeploySteps.value.push({
      label: progress.step,
      detail,
      time: progress.updatedAt,
      tone:
        progress.status === 'failed'
          ? 'danger'
          : progress.status === 'succeeded'
            ? 'success'
            : 'running',
    });
  // 终态事件不带字节统计时继承上一步，避免「已上传 3 MB / 共 12 MB」在完成瞬间消失。
  serverDeployProgress.value = {
    ...serverDeployProgress.value,
    ...progress,
    received: progress.received ?? serverDeployProgress.value?.received,
    total: progress.total ?? serverDeployProgress.value?.total,
  };
}

function dismissDownloadTask(taskId: string) {
  downloadTasks.value = downloadTasks.value.filter((item) => item.taskId !== taskId);
  downloadLaunchers.delete(taskId);
}
function clearFinishedDownloadTasks() {
  const done = new Set(['succeeded', 'failed', 'cancelled']);
  for (const item of downloadTasks.value)
    if (done.has(item.status)) downloadLaunchers.delete(item.taskId);
  downloadTasks.value = downloadTasks.value.filter((item) => !done.has(item.status));
}

// 官方 SHA256 取不到时统一走渲染层确认，彻底去掉会卡住界面的 Electron 原生框。
async function callWithChecksumConfirm<T>(
  call: (confirmed: boolean) => Promise<T>,
  label: string,
): Promise<T | null> {
  try {
    return await call(false);
  } catch (error) {
    if ((error as Error & { code?: string }).code !== CHECKSUM_UNAVAILABLE) throw error;
    const agreed = await new Promise<boolean>((resolve) => {
      askConfirm({
        title: '安装包无法核对官方校验值',
        level: 'warning',
        message: `${label}：未能取得 FRP 官方发布的 SHA256 清单，本次无法与官方摘要核对。`,
        impacts: ['仅在你确认下载来源可信时继续', '安装后仍会执行程序检查实际版本'],
        confirmLabel: '确认来源并继续',
        onConfirm: () => resolve(true),
        onCancel: () => resolve(false),
      });
    });
    return agreed ? call(true) : null;
  }
}

/**
 * 使用点通用「确保安装包可用」：命中已装直接复用，否则自动下载，
 * 全程由任务中心显示进度。返回 null 表示用户取消或失败（已 Toast）。
 */
async function prepareVersion(
  args: EnsureVersionArgs,
  label: string,
  taskId = uid(),
): Promise<EnsureVersionResult | null> {
  seedDownloadTask({ taskId, label, purpose: args.purpose, version: args.version ?? '' });
  downloadLaunchers.set(taskId, () => void prepareVersion(args, label, taskId));
  try {
    const result = await callWithChecksumConfirm(
      (confirmed) =>
        rpc<EnsureVersionResult>(ACTIONS.versionEnsure, { ...args, taskId, confirmed }),
      label,
    );
    if (!result) {
      dismissDownloadTask(taskId);
      return null;
    }
    // 命中已安装时主进程不产生下载事件，避免任务中心留下永远 starting 的占位。
    if (!result.prepared) dismissDownloadTask(taskId);
    await refresh();
    return result;
  } catch (error) {
    toastError((error as Error).message);
    return null;
  }
}

// 版本库手动下载 / 离线导入也进同一个任务中心。
async function runManualInstall(
  payload: Record<string, unknown>,
  label: string,
  taskId = uid(),
): Promise<InstalledVersion | null> {
  seedDownloadTask({ taskId, label, purpose: 'manual', version: String(payload.version ?? '') });
  downloadLaunchers.set(taskId, () => void runManualInstall(payload, label, taskId));
  try {
    const result = await callWithChecksumConfirm(
      (confirmed) =>
        rpc<InstalledVersion>(ACTIONS.versionInstall, {
          ...payload,
          taskId,
          purpose: 'manual',
          confirmed,
        }),
      label,
    );
    if (!result) {
      dismissDownloadTask(taskId);
      return null;
    }
    await refresh();
    toastSuccess('版本已安装。');
    return result;
  } catch (error) {
    toastError((error as Error).message);
    return null;
  }
}

async function onDownloadTaskCancel(taskId: string) {
  try {
    await rpc(ACTIONS.versionDownloadCancel, { taskId });
    toastWarning('下载已暂停，断点已保留，可在任务中心重试。');
  } catch (error) {
    toastError((error as Error).message);
  }
}
function onDownloadTaskRetry(taskId: string) {
  const launch = downloadLaunchers.get(taskId);
  if (launch) launch();
  else
    void rpc(ACTIONS.versionDownloadRetry, { taskId }).catch((error) =>
      toastError((error as Error).message),
    );
}

// 全局浮层：服务端安装与证书签发共用同一个 ProgressPanel（下载走右下角任务中心）。
const floatTask = computed(() => {
  const dp = serverDeployProgress.value;
  if (dp)
    return {
      kind: 'server-deploy',
      view: {
        title: '安装 FRP 服务端',
        status: dp.status,
        percent: dp.percent,
        speed: null,
        received: dp.received,
        total: dp.total,
        message: dp.error ?? dp.message,
        detail: '',
        cancellable: false,
        retryable: dp.status === 'failed',
        closable: ['succeeded', 'failed', 'cancelled'].includes(dp.status),
        steps: serverDeploySteps.value,
      },
    };
  const cp = certificateProgress.value;
  if (cp)
    return {
      kind: 'certificate',
      view: {
        title: '服务端证书签发',
        status: cp.status,
        percent: null,
        speed: null,
        message: cp.message,
        detail: cp.dnsAutomation
          ? `DNS 自动化级别：${dnsAutomationLabels[cp.dnsAutomation] ?? cp.dnsAutomation}`
          : '',
        cancellable: ['running', 'retrying', 'waiting-user'].includes(cp.status),
        retryable: cp.status === 'failed',
        closable: ['succeeded', 'failed', 'cancelled'].includes(cp.status),
        steps: certificateProgressHistory.value.map((h) => ({
          label: h.step,
          detail: h.message,
          time: h.updatedAt,
          tone: h.status === 'failed' ? 'danger' : h.status === 'succeeded' ? 'success' : 'running',
        })),
      },
    };
  return null;
});
function onTaskCancel() {
  if (floatTask.value?.kind === 'certificate') void cancelCertificateIssue();
}
function onTaskRetry() {
  if (floatTask.value?.kind === 'server-deploy') {
    serverDeployProgress.value = null;
    void deployServerWithPrepare();
  } else if (floatTask.value?.kind === 'certificate') {
    certificateProgress.value = undefined;
    if (ruleDraft.value) {
      ruleTab.value = 'ssl';
      openModal('rule');
    } else toastWarning('请从客户端实例的 Web 规则中重新申请证书。');
  }
}
function onTaskClose() {
  const kind = floatTask.value?.kind;
  if (kind === 'server-deploy') {
    serverDeployProgress.value = null;
  } else if (kind === 'certificate') {
    certificateProgress.value = undefined;
    activeCertificateTask.value = '';
  }
}
/* ---------------- 服务器 ---------------- */
// 预检发现已有 FRP 服务时，用户选择「保存为只读连接」：复用原有只读导入链路。
async function importFrpsService(
  candidate: FrpsServiceCandidate,
  taskId: string,
  serverId: string,
): Promise<boolean> {
  updateServerDeploy({
    taskId,
    serverId,
    status: 'running',
    step: '读取服务端配置',
    message: `正在读取 ${candidate.config} 的 frps 连接参数`,
    percent: 70,
    updatedAt: Date.now(),
  });
  const r = await act(
    'server:import-service',
    { id: serverId, ...candidate },
    '已读取服务端 frps 配置并回填连接参数，保存为只读服务器。',
  );
  if (!r.ok) {
    updateServerDeploy({
      taskId,
      serverId,
      status: 'failed',
      step: '只读保存失败',
      message: '未能读取服务端 frps 配置，未保存只读连接，也未安装新服务。',
      percent: null,
      updatedAt: Date.now(),
      hint: '可重新发起安装并选择「移除并重新安装」，或先核对服务端配置路径与读取权限。',
    });
    return false;
  }
  updateServerDeploy({
    taskId,
    serverId,
    status: 'succeeded',
    step: '已保存只读连接',
    message: '已回填端口与令牌并保存为只读服务器；本次未安装新服务。',
    percent: 100,
    updatedAt: Date.now(),
  });
  return true;
}
function newServer() {
  hostInfo.value = undefined;
  serverDraft.value = {
    id: uid(),
    name: '',
    host: '',
    sshPort: 22,
    username: 'root',
    auth: 'key',
    keyPath: '',
    publicHost: '',
    frpPort: 7000,
    httpPort: 8080,
    httpsPort: 8443,
    accessMode: 'managed',
    configMode: 'form',
    rawConfig: '',
    rawFormat: 'toml',
  };
  openModal('server');
}
function editServer() {
  if (server.value) {
    serverDraft.value = JSON.parse(JSON.stringify(server.value));
    openModal('server');
  }
}
async function saveServer() {
  const s = serverDraft.value!;
  if (!s.publicHost) s.publicHost = s.host;
  const input = {
    ...s,
    password: s.password || undefined,
    passphrase: s.passphrase || undefined,
    token: s.token || undefined,
  };
  const r = await act('server:save', input, '服务器配置已保存。');
  if (!r.ok) return;
  selectedServer.value = s.id;
  closeModal();
  // 已部署且 SSH 在线时，保存即应用并重启；未连接时只落本机配置。
  if (server.value?.deployment && runtime.value.ssh[s.id] === 'connected') {
    await act('server:apply', { id: s.id, confirmed: true }, '配置已应用并重启服务。');
  } else {
    toastInfo('已保存本机配置；连接 SSH 后再次保存即可应用并重启。');
  }
}
function newInstance() {
  const s = server.value ?? state.value.servers[0];
  if (!s) {
    toastWarning('请先添加服务器。');
    page.value = 'servers';
    return;
  }
  const preferred =
    localVersions.value.find((v) => v.version === s.deployment?.version) ?? localVersions.value[0];
  instanceVersionOverride.value = '';
  instanceDraft.value = {
    id: uid(),
    name: '',
    serverId: s.id,
    versionKey: preferred?.key ?? '',
    mode: 'form',
    rawConfig: '',
    rawFormat: 'toml',
    proxies: [],
  };
  abandonRaw.value = false;
  openModal('instance');
}
function editInstance() {
  if (instance.value) {
    instanceDraft.value = JSON.parse(JSON.stringify(instance.value));
    instanceVersionOverride.value = instance.value.versionKey.split('_')[0] || '';
    abandonRaw.value = false;
    openModal('instance');
  }
}
function addProxy() {
  instanceDraft.value?.proxies.push({
    id: uid(),
    name: `service-${(instanceDraft.value?.proxies.length ?? 0) + 1}`,
    type: 'tcp',
    localIP: '127.0.0.1',
    localPort: 3000,
    remotePort: 18080,
    domains: [],
    tlsMode: 'passthrough',
    certPath: '',
    keyPath: '',
  });
}
/* ---------------- 规则独立 CRUD ---------------- */
function kindOf(rule: ProxyRule): 'tcp' | 'udp' | 'web' {
  return rule.type === 'tcp' ? 'tcp' : rule.type === 'udp' ? 'udp' : 'web';
}
function typeLabel(rule: ProxyRule, instance?: Instance) {
  if (rule.type === 'http' && rule.publicHttps) return 'Web · HTTPS';
  // 方案 B 的 HTTPS 是隐藏伴随规则，原 HTTP 规则仍一条；列表也应显示已启用 HTTPS。
  if (
    rule.type === 'http' &&
    instance?.proxies.some(
      (item) =>
        item.hidden && item.sourceRuleId === rule.id && item.type === 'https' && item.certificateId,
    )
  )
    return 'Web · HTTPS';
  return { tcp: 'TCP', udp: 'UDP', http: 'Web', https: 'Web · HTTPS' }[rule.type];
}
function openRuleCreate(kind: 'web' | 'service') {
  const target = instance.value;
  if (!target) return;
  if (target.mode === 'raw') {
    toastWarning('高级原始配置实例请在「编辑实例」中修改完整配置。');
    return;
  }
  const isWeb = kind === 'web';
  ruleDraft.value = {
    id: uid(),
    name: `${isWeb ? 'web' : 'service'}-${target.proxies.length + 1}`,
    type: isWeb ? 'http' : 'tcp',
    localIP: '127.0.0.1',
    localPort: isWeb ? 8080 : 3000,
    ...(isWeb ? { domains: [], remotePort: undefined } : { remotePort: 18080, domains: [] }),
    tlsMode: 'passthrough',
    certPath: '',
    keyPath: '',
  } as ProxyRule;
  ruleInstanceId.value = target.id;
  ruleIsEdit.value = false;
  ruleKind.value = isWeb ? 'web' : 'tcp';
  ruleTab.value = 'basic';
  ruleConfigDirty.value = false;
  ruleConfigLoading.value = false;
  if (ruleHostInfoServerId.value !== target.serverId) ruleHostInfo.value = undefined;
  refreshRuleTlsPlan(target.serverId);
  openModal('rule');
}
async function openRuleEdit(rule: ProxyRule) {
  const target = instance.value;
  if (!target) return;
  const draft = JSON.parse(JSON.stringify(rule)) as RuleDraft;
  draft.certPem = '';
  draft.keyPem = '';
  ruleDraft.value = draft;
  ruleInstanceId.value = target.id;
  ruleIsEdit.value = true;
  ruleKind.value = kindOf(rule);
  ruleTab.value = 'basic';
  ruleConfigDirty.value = false;
  ruleConfigLoading.value = false;
  if (ruleHostInfoServerId.value !== target.serverId) ruleHostInfo.value = undefined;
  refreshRuleTlsPlan(target.serverId);
  openModal('rule');
  if (rule.certificateId) {
    try {
      const pem = await rpc<{ certPem: string; keyPem: string }>(ACTIONS.certificateReadPem, {
        id: rule.certificateId,
      });
      if (ruleDraft.value?.id === rule.id) {
        ruleDraft.value.certPem = pem.certPem;
        ruleDraft.value.keyPem = pem.keyPem;
      }
    } catch {
      // 证书文件已不存在时留空，用户可重新粘贴或申请。
    }
  }
}
function onRuleKindChange(value: string | number | null) {
  if (value === 'tcp' || value === 'udp' || value === 'web') setRuleKind(value);
}
function setRuleKind(kind: 'tcp' | 'udp' | 'web') {
  ruleKind.value = kind;
  const rule = ruleDraft.value;
  if (!rule) return;
  if (kind === 'tcp' || kind === 'udp') {
    rule.type = kind;
    rule.remotePort = rule.remotePort ?? 18080;
    rule.domains = [];
    rule.tlsMode = 'passthrough';
  } else {
    rule.type = 'http';
    rule.domains = rule.domains?.length ? rule.domains : [];
    rule.remotePort = undefined;
    rule.tlsMode = 'passthrough';
  }
}
async function saveRule() {
  const rule = ruleDraft.value;
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  if (!rule || !target || !rule.name.trim()) {
    toastWarning('请填写规则名称。');
    return;
  }
  if (ruleKind.value === 'web' && !rule.domains?.length) {
    toastWarning('Web 规则请至少填写一个域名。');
    return;
  }
  const proxies = target.proxies.filter((item) => item.id !== rule.id);
  if (proxies.some((item) => item.name === rule.name.trim())) {
    toastWarning('规则名称重复，请换一个名称。');
    return;
  }
  proxies.push(rule);
  instanceDraft.value = JSON.parse(JSON.stringify(target)) as Instance;
  instanceDraft.value.proxies = proxies;
  await saveInstance('规则已保存。', true);
  closeModal();
}
function deleteRule(rule: ProxyRule, targetInstance?: Instance) {
  const target =
    targetInstance ?? state.value.instances.find((item) => item.id === ruleInstanceId.value);
  if (!target) return;
  askConfirm({
    title: '删除代理规则？',
    level: 'warning',
    message: `将删除规则「${rule.name}」，其访问地址随即失效。`,
    impacts: ['实例将在保存后自动重启以应用新规则'],
    confirmLabel: '删除',
    onConfirm: async () => {
      instanceDraft.value = JSON.parse(JSON.stringify(target)) as Instance;
      instanceDraft.value.proxies = target.proxies.filter(
        (item) => item.id !== rule.id && !(item.hidden && item.sourceRuleId === rule.id),
      );
      await saveInstance('规则已删除。', true);
    },
  });
}
/* ---------------- Web 规则站点配置 ---------------- */
const ruleSiteConfigModel = computed({
  get: () => ruleDraft.value?.siteConfig ?? '',
  set: (value: string) => {
    if (ruleDraft.value) {
      ruleDraft.value.siteConfig = value;
      if (!ruleConfigProgrammatic.value) ruleConfigDirty.value = true;
    }
  },
});
const ruleSiteDetection = computed(() => detectSiteFlavor(ruleHostInfo.value));
const ruleSiteFlavor = computed<SiteConfigFlavor>(
  () => ruleDraft.value?.siteConfigFlavor ?? ruleSiteDetection.value.flavor,
);
const ruleSiteSourceLabel = computed(() => {
  if (ruleConfigDetecting.value) return '正在检测服务器 Web 软件…';
  if (!ruleSiteDetection.value.detected) return '未探测到常见 Web 服务，当前按 Nginx 模板显示';
  return `已检测到 ${ruleSiteDetection.value.serviceName} · 按 ${siteFlavorLabel(ruleSiteFlavor.value)} 语法显示`;
});
const ruleConfigWarnings = computed(() => {
  const rule = ruleDraft.value;
  if (!rule || ruleKind.value !== 'web') return [];
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  const certificate = state.value.serverCertificates.find((item) => item.ruleId === rule.id);
  return generateSiteConfig({
    rule,
    server: target ? instanceServer(target) : undefined,
    hostInfo: ruleHostInfo.value,
    tlsMode: ruleTlsPlan.value?.mode,
    certificateId: certificate?.id,
  }).warnings;
});

async function refreshRuleHostInfo() {
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  if (!target || ruleConfigDetecting.value) return;
  // 服务器页已有同机探测结果时直接复用，避免无谓 SSH 往返。
  if (selectedServer.value === target.serverId && hostInfo.value) {
    ruleHostInfo.value = hostInfo.value;
    ruleHostInfoServerId.value = target.serverId;
    return;
  }
  if (ruleHostInfoServerId.value === target.serverId && ruleHostInfo.value) return;
  ruleConfigDetecting.value = true;
  try {
    ruleHostInfo.value = await rpc<HostInfo>('server:detect', target.serverId);
    ruleHostInfoServerId.value = target.serverId;
  } catch (e) {
    toastWarning(`未获取到服务器 Web 软件信息：${(e as Error).message}；已使用通用模板。`);
  } finally {
    ruleConfigDetecting.value = false;
  }
  refreshRuleTlsPlan(target.serverId);
}

/** 用服务端 vhostHTTPPort 判定方案，探测/注入/探针只作为方案 A 的申请条件。 */
function planForInstance(instance: Instance): TlsPlan {
  const server = instanceServer(instance);
  const include = state.value.webIncludes[instance.serverId];
  return decideTlsPlan({
    httpPort: server?.httpPort,
    hostInfo: ruleHostInfoServerId.value === instance.serverId ? ruleHostInfo.value : undefined,
    webInclude: include,
    probe: include?.probe,
  });
}
function refreshRuleTlsPlan(serverId?: string) {
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  if (!target || (serverId && serverId !== target.serverId)) return;
  ruleTlsPlan.value = planForInstance(target);
}

async function switchRuleTab(tab: 'basic' | 'config' | 'ssl') {
  ruleTab.value = tab;
  if (tab === 'ssl') {
    void loadRuleCertDetail();
    return;
  }
  if (tab !== 'config') return;
  // 已有探测结果或 SSH 已连接时自动套用；否则给出检测按钮，不在打开弹窗时突然发起 SSH。
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  if (!target) return;
  const cached = selectedServer.value === target.serverId && hostInfo.value;
  if (cached || runtime.value.ssh[target.serverId] === 'connected') await refreshRuleHostInfo();
  if (ruleTlsPlan.value?.mode === 'server') await loadServerSiteConfig();
}

/** 方案 A：读取服务器托管目录中的真实配置，异步期间由编辑器显示 loading。 */
async function loadServerSiteConfig(force = false) {
  const rule = ruleDraft.value;
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  if (!rule || !target || ruleKind.value !== 'web' || ruleTlsPlan.value?.mode !== 'server') return;
  if (ruleConfigLoading.value) return;
  if (ruleConfigDirty.value && !force) return;
  ruleConfigLoading.value = true;
  try {
    const remote = await rpc<SiteConfigReadResult>(ACTIONS.siteConfigRead, {
      serverId: target.serverId,
      ruleId: rule.id,
    });
    const certificate = state.value.serverCertificates.find((item) => item.ruleId === rule.id);
    const content = remote.exists
      ? remote.content
      : generateSiteConfig({
          rule,
          server: target ? instanceServer(target) : undefined,
          hostInfo: ruleHostInfo.value,
          tlsMode: 'server',
          certificateId: certificate?.id,
        }).content;
    ruleConfigProgrammatic.value = true;
    rule.siteConfig = content;
    rule.siteConfigFlavor =
      remote.flavor === 'nginx' || remote.flavor === 'apache' ? remote.flavor : 'nginx';
    if (remote.exists) rule.siteConfigPath = remote.path;
    ruleConfigDirty.value = false;
    if (!remote.exists)
      toastInfo('服务器还没有站点配置，已生成本地模板；点击「保存配置」写入服务器。');
  } catch (e) {
    toastWarning(`读取服务器配置失败：${(e as Error).message}`);
  } finally {
    ruleConfigProgrammatic.value = false;
    ruleConfigLoading.value = false;
  }
}

/** 当前规则是否已启用证书（方案 A 标记或方案 B 隐藏伴随规则）。 */
const ruleActiveCertificate = computed(() => {
  const rule = ruleDraft.value;
  if (!rule || ruleKind.value !== 'web') return undefined;
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  const companion = target?.proxies.find(
    (item) => item.hidden && item.sourceRuleId === rule.id && item.certificateId,
  );
  if (companion) {
    return {
      plan: 'local' as const,
      certificateId: companion.certificateId,
    };
  }
  const serverCert = state.value.serverCertificates.find((item) => item.ruleId === rule.id);
  if (rule.publicHttps && serverCert) {
    return { plan: 'server' as const, certificateId: serverCert.id };
  }
  if (rule.certificateId) return { plan: 'local' as const, certificateId: rule.certificateId };
  return undefined;
});

async function regenerateSiteConfig() {
  const rule = ruleDraft.value;
  if (!rule || ruleKind.value !== 'web' || ruleConfigRegenerating.value) return;
  ruleConfigRegenerating.value = true;
  try {
    const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
    const certificate = state.value.serverCertificates.find((item) => item.ruleId === rule.id);
    const generated = generateSiteConfig({
      rule,
      server: target ? instanceServer(target) : undefined,
      hostInfo: ruleHostInfo.value,
      tlsMode: ruleTlsPlan.value?.mode,
      certificateId: certificate?.id,
    });
    ruleConfigProgrammatic.value = true;
    rule.siteConfig = generated.content;
    rule.siteConfigFlavor = generated.flavor;
    rule.siteConfigUpdatedAt = Date.now();
    ruleConfigDirty.value = false;
    toastSuccess(`已按 ${siteFlavorLabel(generated.flavor)} 重新生成配置模板。`);
  } finally {
    ruleConfigProgrammatic.value = false;
    ruleConfigRegenerating.value = false;
  }
}

async function copyRuleSiteConfig() {
  if (ruleConfigCopying.value) return;
  const value = ruleSiteConfigModel.value;
  if (!value.trim()) {
    toastWarning('配置内容为空，无需复制。');
    return;
  }
  ruleConfigCopying.value = true;
  try {
    await rpc('clipboard', value);
    toastSuccess('配置已复制。');
  } catch (e) {
    toastError((e as Error).message);
  } finally {
    ruleConfigCopying.value = false;
  }
}

async function saveRuleSiteConfig() {
  const rule = ruleDraft.value;
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  if (!rule || !target || ruleKind.value !== 'web' || ruleConfigSaving.value) return;
  if (!rule.siteConfig?.trim()) {
    toastWarning('配置内容为空，请先生成或填写配置。');
    return;
  }
  const flavor = ruleSiteFlavor.value;
  if (flavor !== 'nginx' && flavor !== 'apache') {
    toastWarning('当前未识别到可写入的 Web 软件，请先刷新检测；也可复制配置手动部署。');
    return;
  }
  ruleConfigSaving.value = true;
  try {
    const r = await act(
      ACTIONS.siteConfigSave,
      {
        serverId: target.serverId,
        ruleId: rule.id,
        content: rule.siteConfig,
        flavor,
      },
      '',
    );
    if (!r.ok || !r.data) return;
    rule.siteConfigPath = (r.data as { path: string }).path;
    rule.siteConfigUpdatedAt = Date.now();
    ruleConfigDirty.value = false;
    await saveRule();
  } finally {
    ruleConfigSaving.value = false;
  }
}

/* ---------------- Web 规则 SSL / 证书申请 ---------------- */
const certApplyDomainList = computed(() => ruleDraft.value?.domains ?? []);
function openCertApply() {
  const rule = ruleDraft.value;
  if (!rule || ruleKind.value !== 'web' || !rule.domains.length) {
    toastWarning('请先在「基础」里填写 Web 规则的域名。');
    return;
  }
  const instance = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  if (!instance) return;
  selectedCertServer.value = instance.serverId;
  Object.assign(certApplyDraft, {
    provider: 'letsencrypt',
    keySize: 2048,
    challenge: 'dns-01',
    domainIds: [...rule.domains],
    allDomains: true,
    email: state.value.settings.acmeEmail ?? '',
    dnsAccountId: state.value.dnsAccounts[0]?.id ?? '',
    termsAgreed: false,
  });
  openModal('cert-apply');
  // 端口判定秒出方案 A/B；服务器 Web 服务 / 权限 / include / 探针由主进程实时探测补全。
  // 不能直接拿渲染层缓存的 ruleHostInfo：它只在「配置」标签探测过，直接从 SSL 进入时为空，
  // 会把真实的 nginx + root 误判成“未检测到 Web 服务 / 非 root 无免密 sudo”。
  certApplyPlan.value = planForInstance(instance);
  ruleTlsPlan.value = certApplyPlan.value;
  void refreshCertApplyPlan(instance.serverId);
}

/** 复用主进程 tls:plan（内部实时 SSH 探测 hostInfo），刷新申请弹窗的方案门槛。 */
async function refreshCertApplyPlan(serverId?: string) {
  const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
  const id = serverId ?? target?.serverId;
  if (!id) return;
  const seq = ++certApplyPlanSeq;
  certApplyPlanLoading.value = true;
  try {
    const fresh = await rpc<TlsPlan>(ACTIONS.tlsPlan, { serverId: id });
    if (seq !== certApplyPlanSeq) return;
    certApplyPlan.value = fresh;
    ruleTlsPlan.value = fresh;
  } catch (e) {
    if (seq !== certApplyPlanSeq) return;
    toastWarning(`读取服务器环境失败：${(e as Error).message}；请检查 SSH 连接后点「重新检测」。`);
  } finally {
    if (seq === certApplyPlanSeq) certApplyPlanLoading.value = false;
  }
}
function toggleCertDomain(domain: string) {
  const set = new Set(certApplyDraft.domainIds);
  if (set.has(domain)) set.delete(domain);
  else set.add(domain);
  certApplyDraft.domainIds = [...set];
  certApplyDraft.allDomains = certApplyDraft.domainIds.length === certApplyDomainList.value.length;
}
function toggleAllCertDomains() {
  certApplyDraft.allDomains = !certApplyDraft.allDomains;
  certApplyDraft.domainIds = certApplyDraft.allDomains ? [...certApplyDomainList.value] : [];
}
async function submitCertApply() {
  const active = certificateProgress.value;
  if (active && ['running', 'retrying', 'waiting-user', 'cancelling'].includes(active.status)) {
    toastWarning('已有证书签发任务进行中，请等待完成或取消。');
    return;
  }
  if (certApplyPlanLoading.value) {
    toastWarning('正在读取服务器环境，请稍候…');
    return;
  }
  if (!certApplyPlan.value?.canIssue) {
    toastWarning(
      `当前方案不满足申请条件：${certApplyPlan.value?.blockers.join('；') ?? '方案未就绪'}`,
    );
    return;
  }
  const domains = certApplyDraft.domainIds.filter((d) => certApplyDomainList.value.includes(d));
  if (!domains.length) {
    toastWarning('请至少选择一个域名。');
    return;
  }
  const challenge = certApplyDraft.challenge;
  const account = state.value.dnsAccounts.find((item) => item.id === certApplyDraft.dnsAccountId);
  if (challenge === 'dns-01' && !account) {
    toastWarning('DNS 验证需要选择已保存的 DNS 账户。');
    return;
  }
  if (!certApplyDraft.email.trim()) {
    toastWarning('请填写联系邮箱。');
    return;
  }
  if (!certApplyDraft.termsAgreed) {
    toastWarning('请先同意签发机构的服务条款。');
    return;
  }
  const rule = ruleDraft.value;
  if (!rule) return;
  const taskId = uid();
  activeCertificateTask.value = taskId;
  certificateProgressHistory.value = [];
  certificateProgress.value = {
    taskId,
    status: 'running',
    step: '准备签发',
    message: `正在为 Web 规则申请证书（${challenge === 'http-01' ? '文件验证' : 'DNS 验证'}）。`,
    dnsAutomation: challenge === 'dns-01' ? 'api' : 'manual',
    updatedAt: Date.now(),
  };
  closeModal();
  try {
    if (certApplyDraft.email.trim())
      await rpc(ACTIONS.settingsSave, { acmeEmail: certApplyDraft.email.trim() });
    const record = await rpc<ServerCertificate>(ACTIONS.certificateIssueServer, {
      taskId,
      serverId: selectedCertServer.value,
      name: rule.name,
      domains,
      provider: certApplyDraft.provider,
      email: certApplyDraft.email,
      challenge,
      dnsAutomation: challenge === 'dns-01' ? 'api' : 'manual',
      ...(challenge === 'dns-01' && account ? { dnsAccountId: account.id } : {}),
      keySize: certApplyDraft.keySize,
      termsAgreed: certApplyDraft.termsAgreed,
      ruleId: rule.id,
    });
    if (record.tlsPlan === 'server') {
      // 方案 A：证书已部署到服务器，规则已切成 http 回源 + publicHttps，无需本机 PEM。
      rule.publicHttps = true;
      rule.type = 'http';
      rule.certificateId = undefined;
      rule.siteConfigPath = record.serverConfigPath;
    } else {
      const pem = await rpc<{ certPem: string; keyPem: string }>(ACTIONS.certificateReadPem, {
        id: record.localCertificateId ?? record.id,
      });
      rule.certPem = pem.certPem;
      rule.keyPem = pem.keyPem;
      rule.certificateId = record.localCertificateId ?? record.id;
    }
    await refresh();
    if (record.tlsPlan === 'server') await loadServerSiteConfig(true);
    ruleTab.value = 'ssl';
    openModal('rule');
    toastSuccess(
      record.tlsPlan === 'server'
        ? '证书已部署到服务器，规则已切换为 HTTPS 回源。'
        : '证书已签发并回填，点击「保存并启用证书」应用到规则。',
    );
  } catch (e) {
    toastError((e as Error).message);
    if (
      certificateProgress.value &&
      !['succeeded', 'failed', 'cancelled'].includes(certificateProgress.value.status)
    )
      updateCertificateProgress({
        ...certificateProgress.value,
        status: 'failed',
        message: (e as Error).message,
        updatedAt: Date.now(),
      });
  }
}
async function saveRuleCert() {
  const rule = ruleDraft.value;
  if (!rule || ruleKind.value !== 'web') return;
  const certPem = rule.certPem?.trim() ?? '';
  const keyPem = rule.keyPem?.trim() ?? '';
  if (!certPem || !keyPem) {
    toastWarning('请填写证书 PEM 与私钥 KEY，或先点击「申请证书」。');
    return;
  }
  try {
    const record = await rpc<{ id: string }>(ACTIONS.certificateImportPem, {
      instanceId: ruleInstanceId.value,
      name: rule.name,
      domains: rule.domains,
      certPem,
      keyPem,
    });
    toastSuccess('证书已保存，已创建隐藏 HTTPS 伴随规则；原 HTTP 规则保持不变。');
    await refresh();
    const target = state.value.instances.find((item) => item.id === ruleInstanceId.value);
    const companion = target?.proxies.find(
      (item) => item.hidden && item.sourceRuleId === rule.id && item.certificateId === record.id,
    );
    if (companion) {
      rule.certificateId = record.id;
      try {
        const pem = await rpc<{ certPem: string; keyPem: string }>(ACTIONS.certificateReadPem, {
          id: record.id,
        });
        rule.certPem = pem.certPem;
        rule.keyPem = pem.keyPem;
      } catch {
        // 证书文件读取失败不影响已创建的伴随规则。
      }
    }
  } catch (e) {
    toastError((e as Error).message);
  }
}
async function removeRuleCertificate() {
  const rule = ruleDraft.value;
  if (!rule || ruleKind.value !== 'web' || ruleCertRemoving.value) return;
  const active = ruleActiveCertificate.value;
  if (!active) {
    toastWarning('当前规则没有已启用的证书。');
    return;
  }
  const planLabel = active.plan === 'server' ? '服务器证书' : '本机证书与隐藏 HTTPS 规则';
  askConfirm({
    title: '移除证书并回退 HTTP？',
    level: 'warning',
    message: `将移除当前规则的${planLabel}，恢复为普通 HTTP 访问。`,
    impacts: [
      active.plan === 'server'
        ? '服务器上的证书文件与 443 配置会被删除，站点配置恢复为 HTTP'
        : '隐藏的 HTTPS 伴随规则会被删除，用户创建的 HTTP 规则保留',
      '运行中的客户端实例会在保存后重启以应用变更',
    ],
    confirmLabel: '移除证书',
    onConfirm: async () => {
      ruleCertRemoving.value = true;
      try {
        await act(
          ACTIONS.certificateRemove,
          { instanceId: ruleInstanceId.value, ruleId: rule.id },
          '证书已移除，规则已恢复 HTTP。',
        );
        await refresh();
        rule.publicHttps = false;
        rule.certificateId = undefined;
        rule.certPath = '';
        rule.keyPath = '';
        rule.certPem = '';
        rule.keyPem = '';
        ruleConfigDirty.value = false;
        if (ruleTlsPlan.value?.mode === 'server') await loadServerSiteConfig(true);
      } finally {
        ruleCertRemoving.value = false;
      }
    },
  });
}
function ruleDomainsText(rule: ProxyRule) {
  return rule.domains.join('\n');
}
function setRuleDomains(rule: ProxyRule, event: Event) {
  rule.domains = (event.target as HTMLTextAreaElement).value
    .split(/[\n,，;；]+/)
    .map((domain) => domain.trim().toLowerCase());
}
function addresses(rule: ProxyRule, target: Instance) {
  const targetServer = state.value.servers.find((item) => item.id === target.serverId);
  if (!targetServer) return [];
  if (rule.type === 'http' || rule.type === 'https')
    return rule.domains.map((domain) =>
      accessAddress({ ...rule, domains: [domain] }, targetServer),
    );
  return [accessAddress(rule, targetServer)];
}
function address(rule: ProxyRule, target: Instance) {
  return addresses(rule, target)[0] ?? '';
}
function siteRules(target: Instance) {
  return target.proxies.filter(
    (rule) => !rule.hidden && (rule.type === 'http' || rule.type === 'https'),
  );
}
function serviceRules(target: Instance) {
  return target.proxies.filter(
    (rule) => !rule.hidden && (rule.type === 'tcp' || rule.type === 'udp'),
  );
}
function currentRules(target: Instance) {
  return ruleListTab.value === 'site' ? siteRules(target) : serviceRules(target);
}
function currentRuleAddresses(target: Instance) {
  return currentRules(target).flatMap((rule) =>
    addresses(rule, target).map((url) => ({
      url,
      web: rule.type === 'http' || rule.type === 'https',
    })),
  );
}

/* ---------------- 证书签发进度 ---------------- */
function updateCertificateProgress(progress: CertificateIssueProgress) {
  if (progress.taskId !== activeCertificateTask.value) return;
  certificateProgress.value = progress;
  const previous = certificateProgressHistory.value.at(-1);
  if (!previous || previous.step !== progress.step || previous.message !== progress.message)
    certificateProgressHistory.value.push(progress);
}
async function cancelCertificateIssue() {
  const progress = certificateProgress.value;
  if (!progress || !activeCertificateTask.value) return;
  updateCertificateProgress({
    ...progress,
    status: 'cancelling',
    step: '正在取消',
    message: '正在中止 CA 请求并清理临时验证配置。',
    updatedAt: Date.now(),
  });
  try {
    await rpc(ACTIONS.certificateCancel, activeCertificateTask.value);
  } catch (e) {
    toastError((e as Error).message);
  }
}
async function continueDnsChallenge() {
  if (!activeCertificateTask.value) return;
  try {
    await rpc(ACTIONS.certificateChallengeResponse, {
      id: activeCertificateTask.value,
      continueIssue: true,
    });
  } catch (e) {
    toastError((e as Error).message);
  }
}
async function copyDnsRecord(value: string) {
  try {
    await rpc('clipboard', value);
    toastSuccess('TXT 值已复制。');
  } catch (e) {
    toastError((e as Error).message);
  }
}
function certificateName(provider: string) {
  return provider === 'letsencrypt'
    ? 'Let’s Encrypt'
    : provider === 'litessl'
      ? 'LiteSSL'
      : '手动证书';
}

/* ---------------- 证书管理：搜索 / 分页 / 详情 / 下载 / 删除 ---------------- */
const filteredCerts = computed(() => {
  const keyword = certSearch.value.trim().toLowerCase();
  if (!keyword) return state.value.serverCertificates;
  return state.value.serverCertificates.filter((cert) =>
    [cert.name, certificateName(cert.provider), ...cert.domains].some((value) =>
      value.toLowerCase().includes(keyword),
    ),
  );
});
const certTotalPages = computed(() =>
  Math.max(1, Math.ceil(filteredCerts.value.length / certPageSize)),
);
const pagedCerts = computed(() =>
  filteredCerts.value.slice((certPage.value - 1) * certPageSize, certPage.value * certPageSize),
);
watch(certSearch, () => {
  certPage.value = 1;
});
watch(certTotalPages, (total) => {
  if (certPage.value > total) certPage.value = total;
});
async function openCertDetail(cert: ServerCertificate) {
  certDetailOpen.value = true;
  certDetail.value = undefined;
  certDetailLoading.value = true;
  try {
    certDetail.value = await rpc<CertificateDetail>(ACTIONS.certificateDetail, cert.id);
  } catch (error) {
    toastError(`读取证书详情失败：${(error as Error).message}`);
    certDetailOpen.value = false;
  } finally {
    certDetailLoading.value = false;
  }
}
function closeCertDetail() {
  certDetailOpen.value = false;
}
function downloadCertMaterial(kind: 'cert' | 'key') {
  const detail = certDetail.value;
  if (!detail || certDownloading.value) return;
  const content = kind === 'cert' ? detail.certPem : detail.keyPem;
  if (!content.trim()) {
    toastWarning('证书内容为空，无法下载。');
    return;
  }
  certDownloading.value = true;
  try {
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${detail.id}-${kind === 'cert' ? 'fullchain.crt' : 'private.key'}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toastSuccess(kind === 'cert' ? '证书链已下载。' : '私钥已下载，请妥善保管。');
  } finally {
    certDownloading.value = false;
  }
}
function deleteCertFromPage() {
  const detail = certDetail.value;
  if (!detail || certDeleting.value) return;
  const cert = state.value.serverCertificates.find((item) => item.id === detail.id);
  askConfirm({
    title: '删除证书',
    level: 'danger',
    message: `删除证书「${cert?.name ?? detail.id}」？`,
    impacts: [
      detail.storage === 'server'
        ? '将删除服务器上的证书文件并恢复该站点 HTTP 配置'
        : '将删除本机证书与隐藏 HTTPS 伴随规则，HTTP 规则保留',
      '删除后使用该证书的 HTTPS 访问会立即失效',
    ],
    confirmLabel: '删除证书',
    onConfirm: async () => {
      certDeleting.value = true;
      try {
        await act(ACTIONS.certificateDelete, detail.id, '证书已删除。');
        closeCertDetail();
        await refresh();
      } finally {
        certDeleting.value = false;
      }
    },
  });
}
async function loadRuleCertDetail() {
  const id = ruleActiveCertificate.value?.certificateId;
  if (ruleTab.value !== 'ssl' || !id) {
    ruleCertDetail.value = undefined;
    return;
  }
  ruleCertDetailLoading.value = true;
  ruleCertDetailError.value = '';
  try {
    ruleCertDetail.value = await rpc<CertificateDetail>(ACTIONS.certificateDetail, id);
  } catch (error) {
    ruleCertDetailError.value = (error as Error).message;
    ruleCertDetail.value = undefined;
  } finally {
    ruleCertDetailLoading.value = false;
  }
}
watch([ruleTab, () => ruleActiveCertificate.value?.certificateId], () => {
  void loadRuleCertDetail();
});

/* ---------------- 实例 ---------------- */
function saveInstanceInstanceForm() {
  void saveInstance();
}
async function saveInstance(successMessage = '实例已保存，点击启动开始分享。', fromRule = false) {
  const draft = instanceDraft.value!;
  const resolution =
    instanceResolution.value ??
    (await rpc<VersionResolution>(ACTIONS.versionResolve, {
      purpose: 'client',
      serverId: draft.serverId,
      version: instanceVersionOverride.value || undefined,
      platform: state.value.platform,
      arch: state.value.arch,
    }));
  if (!resolution?.version || !resolution.archSupported) {
    toastError(resolution?.note || '尚未获取官方版本列表，请先在版本库点击「获取版本列表」。');
    return;
  }
  let key = resolution.key;
  if (!resolution.installed) {
    const prepared = await prepareVersion(
      {
        purpose: 'client',
        serverId: draft.serverId,
        version: instanceVersionOverride.value || undefined,
        platform: resolution.platform,
        arch: resolution.arch,
      },
      `客户端安装包 FRP ${resolution.version} · ${resolution.platform}/${resolution.arch}`,
    );
    // 下载失败或被取消时不保存实例，避免留下指向不存在二进制的配置。
    if (!prepared) return;
    key = prepared.version.key;
  }
  draft.versionKey = key;
  const r = await rpc<{ restarted: boolean }>('instance:save', draft);
  if (r.restarted) toastSuccess('配置已保存并重启实例。');
  else toastSuccess(successMessage);
  // instance:save 是直接 RPC，不走 act() 的自动刷新；必须在这里重新拉取状态，
  // 否则新建实例/规则只有重启应用后才会出现。
  await refresh();
  selectedInstance.value = draft.id;
  if (!fromRule) closeModal();
}
async function enterRaw() {
  try {
    instanceDraft.value!.rawConfig = await rpc<string>('instance:preview', instanceDraft.value);
    instanceDraft.value!.mode = 'raw';
  } catch (e) {
    toastError((e as Error).message);
  }
}
function restoreForm() {
  if (abandonRaw.value) {
    instanceDraft.value!.mode = 'form';
    instanceDraft.value!.rawConfig = '';
    abandonRaw.value = false;
  } else abandonRaw.value = true;
}
async function choose(purpose: string, setter: (file: string) => void) {
  try {
    const file = await rpc<string>('file:pick', purpose);
    if (file) setter(file);
  } catch (e) {
    toastError((e as Error).message);
  }
}
async function importConfig(target: 'server' | 'instance') {
  try {
    const data = await rpc<{ content: string; format: 'toml' | 'ini' | 'yaml' | 'json' } | null>(
      'file:read-config',
    );
    if (!data) return;
    if (target === 'server')
      Object.assign(serverDraft.value!, {
        configMode: 'raw',
        rawConfig: data.content,
        rawFormat: data.format,
      });
    else
      Object.assign(instanceDraft.value!, {
        mode: 'raw',
        rawConfig: data.content,
        rawFormat: data.format,
      });
  } catch (e) {
    toastError((e as Error).message);
  }
}

/* ---------------- 版本库 ---------------- */
async function fetchCatalog(force = false, next = false) {
  // 启动只回显 state.json；联网只发生在用户手动点击「获取 / 刷新列表」时。
  const payload: Record<string, unknown> = {
    page: next ? (catalog.value?.page ?? 0) + 1 : 1,
    force: force || !next,
  };
  const r = await act(ACTIONS.versionCatalog, payload);
  const data = r.data as Catalog | undefined;
  if (!data) return;
  catalog.value =
    next && catalog.value
      ? {
          ...data,
          releases: Array.from(
            new Map(
              [...catalog.value.releases, ...data.releases].map((release) => [
                release.version,
                release,
              ]),
            ).values(),
          ),
        }
      : data;
}
async function loadCachedCatalog() {
  try {
    const data = await rpc<Catalog | null>(ACTIONS.versionCatalogCached);
    if (data) catalog.value = data;
  } catch {
    // 首次离线无缓存，属正常情况。
  }
}
function assetFor(release: Catalog['releases'][number]) {
  return release.assets.find(
    (a) =>
      a.name ===
      `frp_${release.version}_${targetPlatform.value}_${targetArch.value}.${targetPlatform.value === 'windows' ? 'zip' : 'tar.gz'}`,
  );
}
async function installRelease(release: Catalog['releases'][number]) {
  const asset = assetFor(release);
  if (!asset) return;
  const label = `下载 FRP ${release.version} · ${targetPlatform.value}/${targetArch.value}`;
  await runManualInstall(
    {
      version: release.version,
      platform: targetPlatform.value,
      arch: targetArch.value,
      url: asset.url,
      digest: asset.digest,
    },
    label,
  );
}
async function installManual() {
  const label = `${manual.localPath ? '导入' : '下载'} FRP ${manual.version || ''} · ${targetPlatform.value}/${targetArch.value}`;
  const result = await runManualInstall(
    {
      version: manual.version,
      platform: targetPlatform.value,
      arch: targetArch.value,
      url: manual.url || undefined,
      localPath: manual.localPath || undefined,
      digest: manual.digest || undefined,
    },
    label,
  );
  if (result) closeModal();
}
const catalogStale = computed(() => state.value.catalog?.stale ?? catalog.value?.stale ?? false);
const catalogUpdatedAt = computed(
  () => state.value.catalog?.updatedAt ?? catalog.value?.updatedAt ?? '',
);
const catalogWarning = computed(() => state.value.catalog?.warning ?? catalog.value?.warning ?? '');
// 明确区分「本次在线取得」与「启动时从 state.json 回显」，不再笼统写「使用缓存」。
const catalogSourceLabel = computed(() => {
  const source = catalog.value?.source ?? state.value.catalog?.source;
  const from =
    source === 'api'
      ? 'GitHub Releases API'
      : source === 'github-web'
        ? 'GitHub 官方发布页'
        : '本地记录';
  if (catalogStale.value) return '离线缓存';
  if (!catalogUpdatedAt.value) return '尚未获取';
  return catalog.value && !catalog.value.cached ? `在线获取 · ${from}` : `本地缓存回显 · ${from}`;
});
const catalogSourceTone = computed(() =>
  catalogStale.value ? 'warning' : catalog.value && !catalog.value.cached ? 'success' : 'info',
);
const catalogOutdated = computed(() => {
  const updated = Date.parse(catalogUpdatedAt.value);
  if (!Number.isFinite(updated)) return false;
  return Date.now() - updated > (state.value.settings.catalogCacheHours || 24) * 3600000;
});

/* ---------------- 使用点版本自动解析与自动准备包 ---------------- */
const serverResolution = ref<VersionResolution | null>(null);
const deployVersionOverride = ref('');
const instanceResolution = ref<VersionResolution | null>(null);
const instanceVersionOverride = ref('');

async function refreshServerResolution() {
  const current = server.value;
  if (!current || current.deployment) {
    serverResolution.value = null;
    return;
  }
  try {
    serverResolution.value = await rpc<VersionResolution>(ACTIONS.versionResolve, {
      purpose: 'server',
      serverId: current.id,
      version: deployVersionOverride.value || undefined,
      arch: hostInfo.value?.arch,
    });
  } catch {
    serverResolution.value = null;
  }
}
async function refreshInstanceResolution() {
  const draft = instanceDraft.value;
  if (!draft) {
    instanceResolution.value = null;
    return;
  }
  try {
    instanceResolution.value = await rpc<VersionResolution>(ACTIONS.versionResolve, {
      purpose: 'client',
      serverId: draft.serverId,
      version: instanceVersionOverride.value || undefined,
      platform: state.value.platform,
      arch: state.value.arch,
    });
  } catch {
    instanceResolution.value = null;
  }
}
// 选服务器 / 探测到架构 / 手动改版本后立即重新解析，界面所见即最终所用。
watch(
  () => [server.value?.id, hostInfo.value?.arch, deployVersionOverride.value],
  () => void refreshServerResolution(),
  { immediate: true },
);
watch(
  () => [instanceDraft.value?.serverId, instanceVersionOverride.value],
  () => void refreshInstanceResolution(),
  { immediate: true },
);
function versionReadyLabel(resolution: VersionResolution | null): string {
  if (!resolution?.version) return '待获取版本列表';
  if (!resolution.archSupported) return '待确认架构';
  if (resolution.installed) return '本机已就绪';
  return resolution.available ? '未下载 · 将自动下载' : '需检查官方列表';
}
function versionReadyTone(resolution: VersionResolution | null): string {
  if (!resolution?.version || !resolution.archSupported) return 'warning';
  return resolution.installed ? 'success' : 'info';
}

async function deployServerWithPrepare() {
  const current = server.value;
  if (!current) return;
  // 点击瞬间就打开右下角安装步骤窗口，SSH 预检的每一阶段都写进同一条时间线。
  const taskId = uid();
  seedServerDeploy(taskId, current.id);
  const advance = (
    step: string,
    message: string,
    percent: number | null,
    status: ServerDeployProgress['status'] = 'running',
    extra: Partial<ServerDeployProgress> = {},
  ) =>
    updateServerDeploy({
      taskId,
      serverId: current.id,
      status,
      step,
      message,
      percent,
      updatedAt: Date.now(),
      ...extra,
    });
  let info = hostInfo.value;
  // 未连接时先自动连一次并探测架构，用户不用再手动走一遍连接流程。
  if (!info) {
    advance('连接服务器', '正在连接 SSH 并采集主机信息', 3);
    const connected = await act('server:connect', current.id, 'SSH 已连接并完成主机信息采集。');
    const data = connected.data;
    if (data && typeof data === 'object' && 'supported' in data) info = data as HostInfo;
  }
  if (!info?.supported) {
    const message = '请先连接服务器并完成架构探测，再安装服务端。';
    advance('无法继续', message, null, 'failed', {
      error: message,
      hint: '检查 SSH 账号与服务器系统后重试。',
    });
    toastError(message);
    return;
  }
  let resolution: VersionResolution;
  try {
    advance('确定安装包', '正在匹配服务器架构与安装包版本', 8);
    resolution = await rpc<VersionResolution>(ACTIONS.versionResolve, {
      purpose: 'server',
      serverId: current.id,
      version: deployVersionOverride.value || undefined,
      arch: info.arch,
    });
  } catch (error) {
    advance('版本解析失败', (error as Error).message, null, 'failed', {
      error: (error as Error).message,
    });
    toastError((error as Error).message);
    return;
  }
  if (!resolution.version || !resolution.archSupported) {
    const message = resolution.note || '尚未获取官方版本列表，请先在版本库点击「获取版本列表」。';
    advance('版本不可用', message, null, 'failed', {
      error: message,
      hint: '到版本库获取官方列表后重试。',
    });
    toastError(message);
    return;
  }
  const res = resolution;

  // 安装前预检：端口占用、已有 FRP 服务、安装目录残留一次查清，全程上报到安装窗口。
  let precheck: InstallPrecheck;
  try {
    precheck = await rpc<InstallPrecheck>(ACTIONS.serverInstallPrecheck, {
      id: current.id,
      taskId,
    });
  } catch (error) {
    const message = (error as Error).message;
    // 主进程已上报失败的阶段时不要重复追加时间线。
    if (
      serverDeployProgress.value?.taskId === taskId &&
      ['starting', 'running'].includes(serverDeployProgress.value.status)
    )
      advance('预检失败', message, null, 'failed', {
        error: message,
        hint: '检查 SSH 连接与服务器权限后重试；预检只读，不会修改服务器。',
      });
    toastError(message);
    return;
  }
  // ① 端口被占用：终止安装，明确告知改哪里，不做任何服务器改动。
  if (precheck.portConflicts.length) {
    advance(
      '安装已终止',
      `服务器端口 ${precheck.portConflicts.join('、')} 已被占用，FRP 无法监听。`,
      null,
      'cancelled',
      { hint: '请到服务器配置更换 FRP / HTTP / HTTPS 入口端口后重新发起安装。' },
    );
    askConfirm({
      title: '端口被占用，安装已终止',
      level: 'danger',
      message: `服务器端口 ${precheck.portConflicts.join('、')} 已被占用，FRP 无法监听。`,
      impacts: [
        '本次安装已终止，服务器上未做任何改动',
        '请到服务器配置更换 FRP / HTTP / HTTPS 入口端口后重试',
        '展开服务器信息的「系统信息」可核对 80/443 占用与 Web 服务',
      ],
      confirmLabel: '知道了',
      cancelLabel: '关闭',
      onConfirm: () => {},
    });
    return;
  }

  // 预检通过后沿用同一 taskId，用户能在一条时间线里看完检查、决策与部署。
  const doDeploy = async (overwrite = false) => {
    let key = res.key;
    if (!res.installed) {
      const prepared = await prepareVersion(
        {
          purpose: 'server',
          serverId: current.id,
          version: deployVersionOverride.value || undefined,
          arch: info!.arch,
        },
        `服务端安装包 FRP ${res.version} · linux/${res.arch}`,
      );
      if (!prepared) {
        updateServerDeploy({
          taskId,
          serverId: current.id,
          status: 'failed',
          step: '准备失败',
          message: '安装包准备失败或已取消，服务端未安装。下载详情见右下角任务中心。',
          percent: null,
          updatedAt: Date.now(),
        });
        return;
      }
      key = prepared.version.key;
    }
    const result = await act(
      'server:deploy',
      { id: current.id, key, taskId, overwrite, confirmed: true },
      'FRP 服务端已安装并启动。',
    );
    // 主进程通常已上报终态；此处兜底 IPC 异常，避免浮层永久停在「进行中」。
    if (
      !result.ok &&
      serverDeployProgress.value?.taskId === taskId &&
      ['starting', 'running'].includes(serverDeployProgress.value.status)
    )
      updateServerDeploy({
        taskId,
        serverId: current.id,
        status: 'failed',
        step: '安装失败',
        message: '安装请求未完成，请重试或检查与服务器的连接。',
        percent: null,
        updatedAt: Date.now(),
      });
  };

  // ② 预检发现已有 FRP 服务：保存只读 / 移除重装 / 取消，三选一。
  if (precheck.existingServices.length) {
    const candidate = precheck.existingServices[0];
    advance('等待处理方式', `检测到已有服务 ${candidate.service}，请在弹窗中选择处理方式`, null);
    const removeThenDeploy = async () => {
      advance('移除已有服务', `正在停止并备份 ${candidate.service} 的程序与配置`, 65);
      const removed = await act(
        'server:remove-existing',
        { id: current.id, service: candidate, confirmed: true },
        `已移除已有服务 ${candidate.service}，继续安装新服务。`,
      );
      if (!removed.ok) {
        advance('移除失败', `无法移除 ${candidate.service}，未安装新服务。`, null, 'failed', {
          error: `无法移除 ${candidate.service}`,
          hint: '检查 SSH 权限与服务单元所在位置后重试；未注册为系统服务的进程不会被检测。',
        });
        return;
      }
      await doDeploy(true);
    };
    askConfirm({
      title: '检测到已有 FRP 服务',
      level: 'warning',
      message: `服务器上发现 FRP 服务「${candidate.service}」（${candidate.manager} · ${candidate.state}）。请选择处理方式：`,
      impacts: [
        '保存为只读：尝试读取服务端 frps 配置，把端口与令牌回填到本地服务器配置，仅供创建客户端，不安装新服务',
        '移除并重新安装：停服务、禁开机、备份程序与配置（.bak）、删服务单元后安装新服务',
        '取消：终止本次安装，服务器不做任何改动',
      ],
      confirmLabel: '移除并重新安装',
      altLabel: '保存为只读连接',
      altTone: 'soft',
      cancelLabel: '取消安装',
      onConfirm: () => void removeThenDeploy(),
      onAlt: () => void importFrpsService(candidate, taskId, current.id),
      onCancel: () =>
        advance('已取消安装', '你选择了取消，服务器未做任何改动。', null, 'cancelled'),
    });
    return;
  }

  // ③ 安装目录已有程序且不是刚移除的：询问是否覆盖上传。
  if (precheck.installDirExists) {
    advance('等待覆盖确认', '本工具安装目录已有 frps 程序，请在弹窗中确认是否覆盖', null);
    askConfirm({
      title: '安装目录已有程序',
      level: 'warning',
      message: '预检发现本工具安装目录已有 frps 程序。是否用本机选中的安装包覆盖上传并重新安装？',
      impacts: [
        '将覆盖服务器上的 frps 程序与 frps 配置文件',
        '原程序不会直接删除，旧文件保留 .bak 备份以便回滚',
        '取消则终止安装，服务器不做任何改动',
      ],
      confirmLabel: '覆盖上传并安装',
      cancelLabel: '取消',
      onConfirm: () => void doDeploy(true),
      onCancel: () =>
        advance('已取消安装', '你选择了取消，服务器未做任何改动。', null, 'cancelled'),
    });
    return;
  }

  // ④ 常规安装确认（危险确认开关关闭时可跳过）。
  if (state.value.settings.confirmDangerous === false) {
    void doDeploy();
    return;
  }
  advance('等待安装确认', '预检已完成，请在弹窗中确认开始安装', null);
  askConfirm({
    title: '安装 FRP 服务端',
    level: 'warning',
    message: `目标 Linux/${res.arch} · FRP ${res.version}。${res.installed ? '安装包已在本机，无需下载。' : '安装包未就绪，会先自动下载并在任务中心显示进度。'}`,
    impacts: [
      '上传 frps 程序与配置到服务器',
      '写入服务管理方式（如 systemd）并立即启动服务',
      '不会修改防火墙或云安全组',
    ],
    confirmLabel: '准备并部署',
    onConfirm: () => void doDeploy(),
    onCancel: () => advance('已取消安装', '你选择了取消，服务器未做任何改动。', null, 'cancelled'),
  });
}

/* ---------------- 服务器连接 / 部署 ---------------- */
async function detectServer() {
  const r = await act('server:detect', selectedServer.value);
  if (r.data) {
    hostInfo.value = r.data as HostInfo;
    versionChoice.value = '';
  }
}
async function connectServer() {
  const r = await act('server:connect', server.value?.id, 'SSH 已连接并完成主机信息采集。');
  if (r.data && typeof r.data === 'object' && 'supported' in r.data) {
    hostInfo.value = r.data as HostInfo;
    versionChoice.value = '';
  }
}
async function disconnectServer() {
  if (server.value) {
    const r = await act('server:disconnect', server.value.id, 'SSH 已断开，远程服务继续运行。');
    if (r.ok) hostInfo.value = undefined;
  }
}
function selectServer(id: string) {
  selectedServer.value = id;
  hostInfo.value = undefined;
  versionChoice.value = '';
  deployVersionOverride.value = '';
  if (runtime.value.ssh[id] === 'connected') void detectServer();
}
function capacity(kilobytes: number | null) {
  return kilobytes === null ? '不可用' : `${(kilobytes / 1024 / 1024).toFixed(1)} GiB`;
}
function managerLabel(info: HostInfo) {
  const privileged = info.root || info.sudo;
  if (info.serviceManager === 'systemd' && privileged) return 'systemd 系统服务';
  if (info.serviceManager === 'systemd' && info.userSystemd) return 'systemd 用户服务';
  if (info.serviceManager === 'openrc' && privileged) return 'OpenRC 服务';
  if (info.serviceManager === 'sysv' && privileged) return 'SysV 服务';
  return '后台进程（当前权限或系统条件不支持系统服务）';
}
function deploymentLabel(deployment: Deployment) {
  const manager = deployment.manager ?? (deployment.mode === 'process' ? 'process' : 'systemd');
  if (manager === 'process') return '后台进程';
  const names: Record<string, string> = { systemd: 'systemd', openrc: 'OpenRC', sysv: 'SysV' };
  return `${names[manager] ?? manager}${deployment.mode === 'user' ? ' 用户服务' : ' 系统服务'}`;
}
function hostManagerName(manager: HostInfo['serviceManager']) {
  return { systemd: 'systemd', openrc: 'OpenRC', sysv: 'SysV init', unknown: '未识别' }[manager];
}
function portStateLabel(port: HostPortStatus) {
  if (port.state === 'occupied') return `已占用${port.owner ? ` · ${port.owner}` : ''}`;
  if (port.state === 'free') return '空闲';
  return '未探测到';
}
function webServiceSummary(info: HostInfo) {
  if (!info.webServices.length) return '未探测到常见 Web 服务（nginx / Apache / Caddy 等）';
  return info.webServices
    .map(
      (item) =>
        `${item.name}（${item.installed ? '已安装' : '未安装'}${item.running ? ' · 运行中' : ''}）`,
    )
    .join('、');
}
const injectableWebServices = computed(() =>
  (hostInfo.value?.webServices ?? []).filter(
    (item) =>
      (item.installed || item.running) &&
      ['nginx', 'openresty', 'apache2', 'httpd'].includes(item.name),
  ),
);
async function inspectWebInclude() {
  const id = selectedServer.value;
  if (!id) return;
  webIncludeLoading.value = true;
  try {
    webIncludeStatus.value = await rpc<WebIncludeStatus>(ACTIONS.webIncludeInspect, id);
  } catch (error) {
    webIncludeStatus.value = undefined;
    toastError((error as Error).message);
  } finally {
    webIncludeLoading.value = false;
  }
}
function openWebIncludeModal() {
  if (!server.value) return;
  openModal('web-include');
  void inspectWebInclude();
}
async function applyWebInclude(flavor: WebIncludeFlavor) {
  if (webIncludeApplying.value || webIncludeRemoving.value || busy.value) return;
  webIncludeApplying.value = flavor;
  try {
    const r = await act(ACTIONS.webIncludeApply, { serverId: selectedServer.value, flavor }, '');
    if (r.ok) await inspectWebInclude();
  } finally {
    webIncludeApplying.value = '';
  }
}
async function removeWebInclude() {
  if (webIncludeApplying.value || webIncludeRemoving.value || busy.value) return;
  webIncludeRemoving.value = true;
  try {
    const r = await act(ACTIONS.webIncludeRemove, selectedServer.value, '');
    if (r.ok) {
      if (state.value.webIncludes[selectedServer.value]) webIncludeStatus.value = undefined;
      await inspectWebInclude();
    }
  } finally {
    webIncludeRemoving.value = false;
  }
}
async function loadLogs(kind: 'server' | 'instance') {
  if (busy.value) return;
  logKind.value = kind;
  logTarget.value = kind === 'server' ? selectedServer.value : selectedInstance.value;
  busy.value = true;
  try {
    // 日志读取只打开日志窗口，不再叠加一条成功 Toast。
    const text = await rpc<string>(`${kind}:logs`, logTarget.value);
    logText.value = text;
    openModal('logs');
  } catch (e) {
    toastError((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function readRemoteConfig() {
  if (busy.value) return;
  busy.value = true;
  try {
    const text = await rpc<string>('server:read-config', selectedServer.value);
    editServer();
    serverDraft.value!.configMode = 'raw';
    serverDraft.value!.rawConfig = text;
    toastInfo('已读取远程配置，保存后会自动应用到服务器并重启服务。');
  } catch (e) {
    toastError((e as Error).message);
  } finally {
    busy.value = false;
  }
}
function serviceRunning(id: string) {
  return ['active', 'running', 'activating'].includes(runtime.value.services?.[id] ?? '');
}
async function generateToken() {
  try {
    serverDraft.value!.token = await rpc<string>('token:generate');
  } catch (e) {
    toastError((e as Error).message);
  }
}
async function loadBackups() {
  const r = await act('server:backups', selectedServer.value);
  if (r.data) {
    backups.value = r.data;
    openModal('backups');
  }
}
function serviceLabel(id: string) {
  const value = runtime.value.services?.[id];
  return (
    (
      {
        active: '运行中',
        running: '运行中',
        inactive: '已停止',
        failed: '运行失败',
        activating: '启动中',
        stopped: '已停止',
        'pid-mismatch': 'PID 不匹配',
      } as Record<string, string>
    )[value] ?? (value?.startsWith('stopped') ? '已停止 / PID 不匹配' : '状态未确认')
  );
}
function versionLabel(v: InstalledVersion) {
  return `${v.version} · ${v.platform}/${v.arch}`;
}
function formatTime(value: string | number) {
  if (!value) return '未知';
  const date = typeof value === 'number' ? new Date(value) : new Date(value);
  return Number.isNaN(date.getTime()) ? '未知' : date.toLocaleString('zh-CN');
}
function instanceServer(i: Instance) {
  return state.value.servers.find((s) => s.id === i.serverId);
}

/* ---------------- 危险操作（渲染层确认，带 confirmed:true） ---------------- */
function uninstallServer() {
  const s = server.value;
  if (!s) return;
  const remote = !!s.deployment;
  runDangerous(
    {
      title: s.accessMode === 'readonly' ? '移除只读配置' : '卸载服务器',
      level: 'danger',
      message: `即将${remote ? '停止并卸载远端 FRP 服务，同时移除本机配置' : '移除本机服务器配置'}。`,
      impacts: remote
        ? [
            '停止远端 FRP 服务',
            '删除远端程序、配置、日志与 PID 文件',
            '历史备份保留',
            '有关联客户端实例时需先解除关联',
          ]
        : ['移除本机配置记录', '远端服务（如有）继续运行'],
      confirmWord: remote ? '卸载' : undefined,
      confirmLabel: remote ? '确认卸载' : '移除',
    },
    'server:uninstall',
    { id: s.id, removeRemote: remote, confirmed: true },
    '服务器配置已移除。',
  );
}
async function toggleAutostart(enabled: boolean | string | number) {
  const id = selectedServer.value;
  const target = !!enabled;
  const result = await act(
    'server:control',
    { id, action: target ? 'enable' : 'disable' },
    target ? '已开启开机启动。' : '已关闭开机启动。',
  );
  if (!result.ok) await refreshRuntime();
}
function openVersionModal() {
  versionChoice.value = '';
  openModal('server-version');
}
async function switchServerVersion() {
  const current = server.value;
  if (!current || !versionChoice.value) return;
  const version = versionChoice.value;
  const doSwitch = async () => {
    const prepared = await prepareVersion(
      {
        purpose: 'server',
        serverId: current.id,
        version,
        arch: hostInfo.value?.arch,
      },
      `服务端安装包 FRP ${version} · linux/${hostInfo.value?.arch ?? 'amd64'}`,
    );
    if (!prepared) return;
    const result = await act(
      'server:version',
      { id: current.id, key: prepared.version.key, confirmed: true },
      '版本已切换，请手动启动服务。',
    );
    if (result.ok) closeModal();
  };
  if (state.value.settings.confirmDangerous === false) {
    void doSwitch();
    return;
  }
  askConfirm({
    title: '切换服务端版本',
    level: 'warning',
    message: `切换到 FRP ${version}：本机尚无该版本时会先自动下载。切换会先停止正在运行的服务，替换程序后再等待手动启动。`,
    impacts: ['停止当前服务', '替换服务端程序文件', '切换后需手动启动'],
    confirmLabel: '切换版本',
    onConfirm: () => void doSwitch(),
  });
}
function restoreBackup(path: string) {
  runDangerous(
    {
      title: '恢复部署备份',
      level: 'danger',
      message: '恢复会覆盖当前的程序或配置文件，建议先停止服务。',
      impacts: ['用所选备份覆盖现有文件', '恢复后需明确启动服务'],
      confirmLabel: '恢复备份',
    },
    'server:restore',
    { id: selectedServer.value, path, confirmed: true },
    '备份已恢复，请启动服务。',
  );
}
function deleteInstance() {
  const i = instance.value;
  if (!i) return;
  runDangerous(
    {
      title: '删除客户端实例',
      level: 'danger',
      message: `将删除「${i.name}」及其全部代理规则。`,
      impacts: ['停止并移除本机实例', '全部代理规则与访问地址失效'],
      confirmLabel: '删除实例',
    },
    'instance:delete',
    i.id,
    '实例已删除。',
  );
}
function deleteVersion(key: string, label: string) {
  runDangerous(
    {
      title: '删除已安装版本',
      level: 'warning',
      message: `将删除本地版本「${label}」的安装文件。`,
      impacts: ['删除本机安装包目录', '使用此版本的实例将无法启动'],
      confirmLabel: '删除版本',
    },
    'version:delete',
    key,
    '版本已删除。',
  );
}
function clearLogsConfirmed() {
  runDangerous(
    {
      title: '清理日志',
      level: 'normal',
      message: '将清空当前查看的运行日志（脱敏副本不受影响）。',
      confirmLabel: '清空',
    },
    `${logKind.value}:logs:clear`,
    logTarget.value,
    '日志已清理。',
  );
}
function confirmQuit() {
  runDangerous(
    {
      title: '退出并停止本机穿透',
      level: 'warning',
      message: '将停止所有本机客户端实例并退出应用。',
      impacts: ['停止全部本机穿透实例', '远端服务继续运行'],
      confirmLabel: '退出',
    },
    'app:quit',
    undefined,
    '',
  );
}

/* ---------------- 设置 ---------------- */
const dnsProviderOptions: Array<{ value: DnsProviderId; label: string }> = [
  { value: 'dnspod', label: 'DNSPod' },
  { value: 'aliyun', label: '阿里云 DNS' },
  { value: 'cloudflare', label: 'Cloudflare' },
];
function dnsProviderLabel(provider: DnsProviderId) {
  return dnsProviderOptions.find((item) => item.value === provider)?.label ?? provider;
}
// 每个服务商只显示它真正需要的凭据字段，避免 Cloudflare 用户面对无关输入。
type DnsCredentialKey = 'secretId' | 'secretKey' | 'token' | 'endpoint';
interface DnsCredentialField {
  key: DnsCredentialKey;
  label: string;
  hint?: string;
  placeholder?: string;
  password?: boolean;
}
const keepValueHint = '编辑时留空表示沿用已保存值';
const dnsCredentialFields: Record<DnsProviderId, DnsCredentialField[]> = {
  dnspod: [
    { key: 'secretId', label: 'SecretId', hint: keepValueHint },
    { key: 'secretKey', label: 'SecretKey', hint: keepValueHint, password: true },
  ],
  aliyun: [
    { key: 'secretId', label: 'AccessKey ID', hint: keepValueHint },
    { key: 'secretKey', label: 'AccessKey Secret', hint: keepValueHint, password: true },
  ],
  cloudflare: [
    {
      key: 'token',
      label: 'API Token',
      hint: '只需 Token；权限至少包含 Zone:Read 与 Zone.DNS:Edit',
      password: true,
    },
  ],
};
const activeDnsCredentialFields = computed(() => dnsCredentialFields[dnsAccountDraft.provider]);
function dnsFieldPlaceholder(field: DnsCredentialField) {
  const saved = dnsAccountMasked.value[field.key];
  return saved ? `已保存：${saved}（留空沿用）` : (field.placeholder ?? '留空表示沿用已保存值');
}
// 只保留服务商 API 自动化；保留函数供签发进度沿用同一显示字段。
function dnsLevelForProvider(_provider?: DnsProviderId): DnsAutomation {
  return 'api';
}
watch(
  () => certApplyDraft.dnsAccountId,
  (id) => {
    const account = state.value.dnsAccounts.find((item) => item.id === id);
    dnsAutomation.value = dnsLevelForProvider(account?.provider);
  },
);
function resetDnsAccountDraft() {
  Object.assign(dnsAccountDraft, {
    id: '',
    name: '',
    provider: 'dnspod',
    secretId: '',
    secretKey: '',
    token: '',
    endpoint: '',
  });
  dnsAccountResult.value = '';
  dnsAccountResultTone.value = 'success';
}
async function openDnsAccountModal(account?: DnsAccount) {
  resetDnsAccountDraft();
  dnsAccountMasked.value = {};
  if (account)
    Object.assign(dnsAccountDraft, {
      id: account.id,
      name: account.name,
      provider: account.provider,
    });
  dnsAccountResult.value = account ? '凭据留空表示沿用已保存值。' : '';
  dnsAccountResultTone.value = 'success';
  openModal('dns-account');
  if (account) {
    try {
      dnsAccountMasked.value = await rpc<MaskedCredentials>(ACTIONS.dnsAccountMasked, account.id);
    } catch {
      dnsAccountMasked.value = {};
    }
  }
}
function editDnsAccount(account: DnsAccount) {
  openDnsAccountModal(account);
}
async function saveDnsAccount() {
  if (!dnsAccountDraft.name.trim()) {
    toastWarning('请填写账户名称。');
    return;
  }
  const r = await act(
    ACTIONS.dnsAccountSave,
    {
      id: dnsAccountDraft.id || undefined,
      name: dnsAccountDraft.name.trim(),
      provider: dnsAccountDraft.provider,
      secretId: dnsAccountDraft.secretId || undefined,
      secretKey: dnsAccountDraft.secretKey || undefined,
      token: dnsAccountDraft.token || undefined,
      endpoint: dnsAccountDraft.endpoint || undefined,
    },
    'DNS 账户已保存。',
  );
  if (r.ok) {
    resetDnsAccountDraft();
    closeModal();
  }
}
function deleteDnsAccount(account: DnsAccount) {
  askConfirm({
    title: '删除 DNS 账户',
    level: 'danger',
    message: `删除「${account.name}」及其已保存凭据？`,
    impacts: ['删除本机安全存储中的账户凭据', '使用此账户签发的证书续期时需重新选择账户'],
    confirmLabel: '删除',
    onConfirm: () => void act(ACTIONS.dnsAccountDelete, account.id, 'DNS 账户已删除。'),
  });
}
async function testDnsAccountDraft() {
  if (busy.value) return;
  // 测试接口的业务结果在 data.ok / data.message 里；不能用 act() 的 IPC 成功标记，
  // 否则主进程明确返回的「凭据校验失败」也会被当成成功提示。
  if (!dnsAccountDraft.id) dnsAccountDraft.id = uid();
  busy.value = true;
  try {
    const result = await rpc<{ ok: boolean; message: string }>(ACTIONS.dnsAccountTest, {
      id: dnsAccountDraft.id,
      name: dnsAccountDraft.name.trim() || dnsProviderLabel(dnsAccountDraft.provider),
      provider: dnsAccountDraft.provider,
      secretId: dnsAccountDraft.secretId || undefined,
      secretKey: dnsAccountDraft.secretKey || undefined,
      token: dnsAccountDraft.token || undefined,
      endpoint: dnsAccountDraft.endpoint || undefined,
    });
    dnsAccountResultTone.value = result.ok ? 'success' : 'error';
    dnsAccountResult.value =
      result.message || (result.ok ? '凭据验证通过并已安全保存。' : '凭据验证失败。');
    if (result.ok) {
      toastSuccess(dnsAccountResult.value);
      await refresh();
    } else {
      toastError(dnsAccountResult.value);
    }
  } catch (error) {
    dnsAccountResultTone.value = 'error';
    dnsAccountResult.value = (error as Error).message;
    toastError(dnsAccountResult.value);
  } finally {
    busy.value = false;
  }
}
/* ---------------- DNS 管理：域名解析 ---------------- */
function dnsManageProvider(): DnsProviderId | '' {
  const account = state.value.dnsAccounts.find((item) => item.id === dnsManage.accountId);
  return account?.provider ?? '';
}
function resetDnsRecordDraft() {
  Object.assign(dnsRecordDraft, {
    recordId: '',
    name: '',
    type: 'A',
    value: '',
    ttl: 600,
    line: '',
    priority: '',
    proxied: false,
  });
}
async function loadDnsDomains() {
  dnsManage.domains = [];
  dnsManage.records = [];
  dnsManage.domain = '';
  const provider = dnsManageProvider();
  if (!dnsManage.accountId || !provider) return;
  dnsManage.loadingDomains = true;
  try {
    dnsManage.domains = await rpc<ManagedDnsDomain[]>(ACTIONS.dnsDomains, {
      accountId: dnsManage.accountId,
      provider,
    });
  } catch (error) {
    toastError(`读取域名列表失败：${(error as Error).message}`);
  } finally {
    dnsManage.loadingDomains = false;
  }
}
async function loadDnsRecords() {
  dnsManage.records = [];
  const provider = dnsManageProvider();
  if (!dnsManage.accountId || !dnsManage.domain || !provider) return;
  dnsManage.loadingRecords = true;
  try {
    dnsManage.records = await rpc<ManagedDnsRecord[]>(ACTIONS.dnsRecords, {
      accountId: dnsManage.accountId,
      provider,
      domain: dnsManage.domain,
    });
  } catch (error) {
    toastError(`读取解析记录失败：${(error as Error).message}`);
  } finally {
    dnsManage.loadingRecords = false;
  }
}
function onDnsManageAccountChange() {
  void loadDnsDomains();
}
function onDnsManageDomainChange() {
  void loadDnsRecords();
}
function openDnsRecordModal(record?: ManagedDnsRecord) {
  resetDnsRecordDraft();
  if (record) {
    Object.assign(dnsRecordDraft, {
      recordId: record.id,
      name: record.name,
      type: record.type,
      value: record.value,
      ttl: record.ttl,
      line: record.line ?? '',
      priority: record.priority ?? '',
      proxied: Boolean(record.proxied),
    });
  }
  openModal('dns-record');
}
const dnsRecordProvider = computed(() => dnsManageProvider());
async function saveDnsRecord() {
  const provider = dnsManageProvider();
  if (!dnsManage.accountId || !dnsManage.domain || !provider) {
    toastWarning('请先选择 DNS 账户与域名。');
    return;
  }
  if (!dnsRecordDraft.name.trim() || !dnsRecordDraft.value.trim()) {
    toastWarning('请填写记录名称与记录值。');
    return;
  }
  const ok = await act(
    ACTIONS.dnsRecordSave,
    {
      accountId: dnsManage.accountId,
      provider,
      domain: dnsManage.domain,
      ...(dnsRecordDraft.recordId ? { recordId: dnsRecordDraft.recordId } : {}),
      name: dnsRecordDraft.name.trim(),
      type: dnsRecordDraft.type,
      value: dnsRecordDraft.value.trim(),
      ttl: dnsRecordDraft.ttl,
      line: dnsRecordDraft.line || undefined,
      priority:
        dnsRecordDraft.type === 'MX' && dnsRecordDraft.priority !== ''
          ? Number(dnsRecordDraft.priority)
          : undefined,
      ...(dnsRecordProvider.value === 'cloudflare' ? { proxied: dnsRecordDraft.proxied } : {}),
    },
    dnsRecordDraft.recordId ? '解析记录已更新。' : '解析记录已新增。',
  );
  if (ok.ok) {
    closeModal();
    await loadDnsRecords();
  }
}
function deleteDnsRecord(record: ManagedDnsRecord) {
  const provider = dnsManageProvider();
  if (!provider) return;
  askConfirm({
    title: '删除解析记录',
    level: 'danger',
    message: `删除 ${record.name}（${record.type}）？`,
    impacts: ['该操作会立即调用 DNS 服务商接口删除记录', '删除后解析生效需要等待 TTL 过期'],
    confirmLabel: '删除',
    onConfirm: async () => {
      const r = await act(
        ACTIONS.dnsRecordDelete,
        {
          accountId: dnsManage.accountId,
          provider,
          domain: dnsManage.domain,
          recordId: record.id,
        },
        '解析记录已删除。',
      );
      if (r.ok) await loadDnsRecords();
    },
  });
}

function syncSettingsDraft() {
  const s = state.value.settings;
  settingsDraft.proxyUrl = s.proxyUrl ?? '';
  settingsDraft.acmeEmail = s.acmeEmail ?? '';
  settingsDraft.eabKid = '';
  settingsDraft.eabHmac = '';
  settingsDraft.deployDefault = s.deployDefault ?? 'manual';
  settingsDraft.catalogCacheHours = s.catalogCacheHours ?? 24;
  settingsDraft.downloadRetries = s.downloadRetries ?? 3;
  settingsDraft.confirmDangerous = s.confirmDangerous ?? true;
  settingsDraft.theme = s.theme ?? 'light';
}
const resolvedTheme = ref<'light' | 'dark'>('light');
function applyTheme(theme: string) {
  const root = document.documentElement;
  const dark =
    theme === 'dark' ||
    (theme !== 'light' && !!window.matchMedia?.('(prefers-color-scheme: dark)').matches);
  root.dataset.theme = dark ? 'dark' : 'light';
  resolvedTheme.value = dark ? 'dark' : 'light';
}
// Ant Design Vue 主题跟随应用自身的明暗设置，避免组件库与现有设计变量出现两套配色。
const antdTheme = computed(() => {
  const dark = resolvedTheme.value === 'dark';
  return {
    token: {
      colorPrimary: dark ? '#6d70f0' : '#5457e5',
      colorSuccess: '#16855c',
      colorWarning: '#b26a08',
      colorError: '#c63c3c',
      colorText: dark ? '#e8ebf3' : '#161c2b',
      colorTextSecondary: dark ? '#b1bacb' : '#3a4356',
      colorBgContainer: dark ? '#181c26' : '#ffffff',
      colorBgElevated: dark ? '#1e232f' : '#ffffff',
      colorBorder: dark ? '#2a3040' : '#e2e6ed',
      borderRadius: 6,
      fontSize: 14,
      controlHeight: 38,
      fontFamily:
        "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif",
    },
    components: {
      Select: {
        optionSelectedBg: dark ? '#232655' : '#eef0ff',
        optionHoverBg: dark ? '#262c3a' : '#f0f2f5',
      },
    },
  };
});
watch(
  () => settingsDraft.theme,
  (value) => applyTheme(value),
);
async function saveSettings() {
  const payload: Record<string, unknown> = {
    proxyUrl: settingsDraft.proxyUrl,
    acmeEmail: settingsDraft.acmeEmail.trim(),
    deployDefault: settingsDraft.deployDefault,
    catalogCacheHours: Number(settingsDraft.catalogCacheHours),
    downloadRetries: Number(settingsDraft.downloadRetries),
    confirmDangerous: settingsDraft.confirmDangerous,
    theme: settingsDraft.theme,
  };
  if (settingsDraft.eabKid.trim()) payload.eabKid = settingsDraft.eabKid.trim();
  if (settingsDraft.eabHmac.trim()) payload.eabHmac = settingsDraft.eabHmac.trim();
  const r = await act(ACTIONS.settingsSave, payload, '设置已保存。');
  if (r.ok) {
    applyTheme(settingsDraft.theme);
    syncSettingsDraft();
  }
}

/* ---------------- 终端 ---------------- */
async function openTerminalForServer(serverId: string) {
  if (!terminalServer(serverId)) return;
  const id = uid();
  const terminalTab = {
    id,
    serverId,
    title: `${terminalServer(serverId)?.name ?? '服务器'} · ${terminalTabs.value.filter((tab) => tab.serverId === serverId).length + 1}`,
    history: { shell: 'unknown', commands: [], available: false } as TerminalHistory,
  };
  terminalTabs.value.push(terminalTab);
  activeTerminalId.value = id;
  page.value = 'terminal';
  await nextTick();
  const host = document.querySelector<HTMLElement>(`[data-terminal-screen="${id}"]`);
  if (!host) return;
  const terminal = new Terminal({
    cursorBlink: true,
    fontFamily: 'Menlo, Monaco, "Cascadia Code", monospace',
    fontSize: 13,
    convertEol: false,
    scrollback: 5000,
    theme: { background: '#101827', foreground: '#d8e1f0', cursor: '#8db4ff' },
  });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open(host);
  terminalInstances.set(id, { terminal, fit });
  terminal.onData((data) => api?.terminalInput(id, data));
  fit.fit();
  terminal.focus();
  try {
    await rpc('terminal:open', {
      serverId,
      terminalId: id,
      cols: terminal.cols,
      rows: terminal.rows,
    });
    terminalResize(id);
    await loadTerminalHistory(id);
  } catch (e) {
    terminal.writeln(`\r\n\x1b[31m连接失败：${(e as Error).message}\x1b[0m`);
  }
}
function terminalResize(id: string) {
  const instance = terminalInstances.get(id);
  if (!instance || activeTerminalId.value !== id) return;
  try {
    instance.fit.fit();
    api?.terminalResize(id, instance.terminal.cols, instance.terminal.rows);
  } catch {
    // 标签尚未布局完成时忽略尺寸同步。
  }
}
async function selectTerminal(id: string) {
  activeTerminalId.value = id;
  await nextTick();
  terminalResize(id);
  terminalInstances.get(id)?.terminal.focus();
  await loadTerminalHistory(id);
}
async function loadTerminalHistory(id: string) {
  const tab = terminalTabs.value.find((item) => item.id === id);
  if (!tab) return;
  terminalHistoryLoading.value = true;
  terminalHistoryNotice.value = '';
  try {
    tab.history = await rpc<TerminalHistory>('terminal:history', tab.serverId);
    if (tab.history.available && !tab.history.commands.length)
      terminalHistoryNotice.value =
        '服务器 history 文件中暂无已保存命令；当前 shell 的新命令可能要等退出后才写入。';
    else if (!tab.history.available)
      terminalHistoryNotice.value = `未找到可读取的 ${tab.history.shell} history 文件。`;
  } catch (e) {
    terminalHistoryNotice.value = (e as Error).message;
  } finally {
    terminalHistoryLoading.value = false;
  }
}
function runTerminalCommand(command: string) {
  if (!activeTerminalId.value || !terminalInstances.has(activeTerminalId.value)) {
    toastWarning('请先打开一个终端标签。');
    return;
  }
  api?.terminalInput(activeTerminalId.value, `${command}\r`);
  terminalInstances.get(activeTerminalId.value)?.terminal.focus();
}
function closeTerminalTab(id: string) {
  api?.terminalClose(id);
  const instance = terminalInstances.get(id);
  instance?.terminal.dispose();
  terminalInstances.delete(id);
  terminalTabs.value = terminalTabs.value.filter((tab) => tab.id !== id);
  if (activeTerminalId.value === id) {
    const next = terminalTabs.value.at(-1);
    activeTerminalId.value = next?.id ?? '';
    if (next) void selectTerminal(next.id);
  }
}
function addTerminalFavorite(command: string) {
  if (state.value.terminalFavorites.some((item) => item.command === command)) return;
  Object.assign(terminalFavoriteDraft, {
    id: uid(),
    name: command.trim().split(/\s+/).slice(0, 4).join(' ').slice(0, 100) || '快捷命令',
    command,
  });
  openModal('terminal-favorite');
  terminalContextMenu.value = undefined;
}
function showTerminalContextMenu(event: MouseEvent, command: string, favoriteId?: string) {
  const width = 210;
  const height = favoriteId ? 140 : 100;
  terminalContextMenu.value = {
    x: Math.min(event.clientX, window.innerWidth - width - 12),
    y: Math.min(event.clientY, window.innerHeight - height - 12),
    command,
    favoriteId,
  };
}
function editTerminalFavorite(item?: TerminalFavorite) {
  if (!item) return;
  Object.assign(terminalFavoriteDraft, { id: item.id, name: item.name, command: item.command });
  openModal('terminal-favorite');
}
function navigatePage(target: string) {
  page.value = target as PageKey;
  if (target === 'terminal' && activeTerminalId.value) {
    void nextTick(() => {
      terminalResize(activeTerminalId.value);
      terminalInstances.get(activeTerminalId.value)?.terminal.focus();
    });
  }
}
async function saveTerminalFavorite() {
  const current = state.value.terminalFavorites.find(
    (item) => item.id === terminalFavoriteDraft.id,
  );
  const r = await act(
    'terminal-favorite:save',
    {
      ...terminalFavoriteDraft,
      order: current?.order ?? state.value.terminalFavorites.length,
      updatedAt: Date.now(),
    },
    '快捷命令已保存。',
  );
  if (r.ok) closeModal();
}
function removeTerminalFavorite(id: string) {
  runDangerous(
    {
      title: '删除快捷命令',
      level: 'normal',
      message: '将删除此条常用命令，不会影响服务器上的任何内容。',
      confirmLabel: '删除',
    },
    'terminal-favorite:delete',
    id,
    '快捷命令已删除。',
  );
}
async function moveTerminalFavorite(id: string, offset: number) {
  const ordered = [...state.value.terminalFavorites].sort((a, b) => a.order - b.order);
  const index = ordered.findIndex((item) => item.id === id);
  const target = index + offset;
  if (index < 0 || target < 0 || target >= ordered.length) return;
  [ordered[index], ordered[target]] = [ordered[target], ordered[index]];
  await act(
    'terminal-favorite:reorder',
    ordered.map((item) => item.id),
  );
}
function clientStatus(id: string) {
  return runtime.value.clients[id]?.status ?? 'stopped';
}
function statusLabel(value: string) {
  return (
    (
      {
        stopped: '已停止',
        running: '运行中',
        connected: '已连接',
        starting: '启动中',
        error: '异常',
        disconnected: '未连接',
        connecting: '连接中',
      } as Record<string, string>
    )[value] ?? value
  );
}
function clientTone(id: string) {
  return (
    (
      {
        running: 'success',
        connected: 'success',
        starting: 'running',
        error: 'danger',
      } as Record<string, string>
    )[clientStatus(id)] ?? 'neutral'
  );
}

/* ---------------- 生命周期 ---------------- */
onMounted(async () => {
  unsubscribeTerminal = api?.onTerminalEvent((event) => {
    const terminal = terminalInstances.get(event.terminalId)?.terminal;
    if (!terminal) return;
    if (event.type === 'data' && event.data) terminal.write(event.data);
    else if (event.type === 'error')
      terminal.writeln(`\r\n\x1b[31m终端错误：${event.message ?? '连接异常'}\x1b[0m`);
    else if (event.type === 'closed') terminal.writeln('\r\n[SSH 终端已关闭]');
  });
  window.addEventListener('resize', resizeActiveTerminal);
  unsubscribeCertificateProgress = api?.onCertificateProgress(updateCertificateProgress);
  unsubscribeDownloadProgress = api?.onDownloadProgress(upsertDownloadTask);
  unsubscribeServerDeployProgress = api?.onServerDeployProgress(updateServerDeploy);
  try {
    await refresh();
    syncSettingsDraft();
    applyTheme(settingsDraft.theme);
    targetPlatform.value = state.value.platform as InstallRequest['platform'];
    targetArch.value = state.value.arch as InstallRequest['arch'];
    selectedCertServer.value = state.value.servers[0]?.id ?? '';
    await loadCachedCatalog();
  } catch (e) {
    toastError((e as Error).message);
  }
  unsubscribe = api?.onChange(() => {
    void refreshRuntime().catch(() => {});
  });
  timer = setInterval(() => {
    void refreshRuntime().catch(() => {});
  }, 3000);
});
onUnmounted(() => {
  clearInterval(timer);
  unsubscribe?.();
  unsubscribeCertificateProgress?.();
  unsubscribeDownloadProgress?.();
  unsubscribeServerDeployProgress?.();
  unsubscribeTerminal?.();
  window.removeEventListener('resize', resizeActiveTerminal);
  document.body.classList.remove('no-scroll');
});
function resizeActiveTerminal() {
  if (activeTerminalId.value) terminalResize(activeTerminalId.value);
}
</script>

<template>
  <a-config-provider :theme="antdTheme">
    <div class="app-shell">
      <AppSidebar
        :items="navItems"
        :active="page"
        :platform="state.platform"
        :arch="state.arch"
        :secure-storage="state.secureStorage"
        :collapsed="sidebarCollapsed"
        :logo="logoUrl"
        @navigate="navigatePage"
        @quit="confirmQuit"
        @toggle-collapse="sidebarCollapsed = !sidebarCollapsed"
      />

      <main class="app-main">
        <header class="app-header">
          <div class="app-header__meta">
            <div class="app-header__heading">
              <h1 class="app-header__title">{{ titles[page] }}</h1>
              <StatusBadge :tone="runtimeTone" :label="runtimeLabel" />
            </div>
            <p class="app-header__desc">{{ descriptions[page] }}</p>
          </div>
          <div class="app-header__actions">
            <button
              v-if="page === 'servers'"
              class="ui-btn ui-btn--primary"
              type="button"
              :disabled="busy"
              @click="newServer"
            >
              ＋ 添加服务器
            </button>
            <button
              v-else-if="page === 'clients'"
              class="ui-btn ui-btn--primary"
              type="button"
              :disabled="busy"
              @click="newInstance"
            >
              ＋ 创建实例
            </button>
            <button
              v-else-if="page === 'versions'"
              class="ui-btn ui-btn--soft"
              type="button"
              @click="openModal('manual')"
            >
              手动 / 离线导入
            </button>
            <button
              v-else-if="page === 'settings'"
              class="ui-btn ui-btn--primary"
              type="button"
              :disabled="busy"
              @click="saveSettings"
            >
              保存设置
            </button>
          </div>
        </header>

        <div v-if="!state.secureStorage" class="notice notice--warning">
          系统安全存储不可用：密码、令牌及 DNS 凭据只在本次会话保留，重启后需要重新输入。
        </div>

        <div class="page-body">
          <!-- ============ 基础设施：服务器 ============ -->
          <template v-if="page === 'servers'">
            <div class="section-title">
              <h2>
                我的服务器 <span>{{ state.servers.length }}</span>
              </h2>
            </div>
            <EmptyState
              v-if="!state.servers.length"
              icon="▤"
              title="从一台服务器开始"
              description="支持 SSH 密码或密钥登录。"
            />
            <div v-else class="split">
              <div class="item-list">
                <button
                  v-for="s in state.servers"
                  :key="s.id"
                  class="item"
                  :class="{ selected: selectedServer === s.id }"
                  type="button"
                  @click="selectServer(s.id)"
                >
                  <strong>{{ s.name }}</strong>
                  <small>{{ s.publicHost }}:{{ s.frpPort }}</small>
                  <StatusBadge
                    :tone="runtime.ssh[s.id] === 'connected' ? 'success' : 'neutral'"
                    :label="`SSH ${statusLabel(runtime.ssh[s.id] ?? 'disconnected')}`"
                  />
                  <small>{{
                    s.accessMode === 'readonly'
                      ? `只读 FRP · ${s.discoveredService?.name ?? '已检索'}`
                      : s.deployment
                        ? `FRP ${s.deployment.version} · ${s.deployment.mode}`
                        : '尚未部署服务端'
                  }}</small>
                </button>
              </div>
              <section v-if="server" class="panel server-panel">
                <div class="panel-heading">
                  <div class="server-panel__identity">
                    <h2>{{ server.name }}</h2>
                    <p>{{ server.username }}@{{ server.host }}:{{ server.sshPort }}</p>
                  </div>
                  <div class="server-panel__head-actions">
                    <StatusBadge
                      v-if="server.accessMode === 'readonly'"
                      tone="info"
                      label="只读连接"
                    />
                    <button
                      v-if="server.accessMode !== 'readonly'"
                      class="ui-btn ui-btn--sm ui-btn--soft"
                      type="button"
                      :disabled="busy"
                      @click="editServer"
                    >
                      编辑配置
                    </button>
                  </div>
                </div>
                <div class="server-ops">
                  <button
                    v-if="runtime.ssh[server.id] !== 'connected'"
                    class="ui-btn ui-btn--primary"
                    type="button"
                    :disabled="busy"
                    @click="connectServer"
                  >
                    连接 SSH
                  </button>
                  <StatusBadge v-else tone="success" label="SSH 已连接" />
                  <button
                    class="ui-btn ui-btn--sm"
                    type="button"
                    @click="openTerminalForServer(server.id)"
                  >
                    打开终端
                  </button>
                  <button
                    v-if="runtime.ssh[server.id] === 'connected'"
                    class="ui-btn ui-btn--sm"
                    type="button"
                    :disabled="busy"
                    @click="detectServer"
                  >
                    刷新主机信息
                  </button>
                  <button
                    v-if="runtime.ssh[server.id] === 'connected'"
                    class="ui-btn ui-btn--sm ui-btn--quiet"
                    type="button"
                    :disabled="busy"
                    @click="disconnectServer"
                  >
                    断开
                  </button>
                </div>
                <div v-if="hostInfo" class="info-box">
                  <button
                    class="info-box__toggle"
                    type="button"
                    :aria-expanded="systemInfoExpanded"
                    @click="systemInfoExpanded = !systemInfoExpanded"
                  >
                    <span class="info-box__chevron" :class="{ expanded: systemInfoExpanded }"
                      >›</span
                    >
                    <strong>系统信息</strong>
                    <small
                      >{{ hostInfo.distribution }} {{ hostInfo.version }} ·
                      {{ hostInfo.arch || '架构不可用' }}</small
                    >
                  </button>
                  <div v-show="systemInfoExpanded" class="info-box__body">
                    <p>
                      内核：{{ hostInfo.kernel || '不可用' }} · CPU：{{
                        hostInfo.cpuModel || '不可用'
                      }}（{{ hostInfo.cpuCores ?? '不可用' }} 核）<br />
                      内存：{{ capacity(hostInfo.memoryTotalKB) }} 总量 / 可用
                      {{ capacity(hostInfo.memoryAvailableKB) }} · 家目录磁盘：{{
                        capacity(hostInfo.diskTotalKB)
                      }}
                      总量 / 可用 {{ capacity(hostInfo.diskAvailableKB) }}<br />
                      服务管理器：{{ hostManagerName(hostInfo.serviceManager) }} · 自动运行方式：{{
                        managerLabel(hostInfo)
                      }}
                      ·
                      {{ hostInfo.root ? 'root' : hostInfo.sudo ? '可免交互 sudo' : '普通用户' }}
                    </p>
                    <div class="web-matrix">
                      <div>
                        <small>80 端口</small>
                        <StatusBadge
                          :tone="
                            hostInfo.port80.state === 'free'
                              ? 'success'
                              : hostInfo.port80.state === 'occupied'
                                ? 'warning'
                                : 'neutral'
                          "
                          :label="portStateLabel(hostInfo.port80)"
                          :dot="false"
                        />
                      </div>
                      <div>
                        <small>443 端口</small>
                        <StatusBadge
                          :tone="
                            hostInfo.port443.state === 'free'
                              ? 'success'
                              : hostInfo.port443.state === 'occupied'
                                ? 'warning'
                                : 'neutral'
                          "
                          :label="portStateLabel(hostInfo.port443)"
                          :dot="false"
                        />
                      </div>
                    </div>
                    <div class="web-include-row">
                      <div>
                        <p>Web 服务：{{ webServiceSummary(hostInfo) }}</p>
                        <p v-if="state.webIncludes[server.id]?.probe" class="hint">
                          include 探针：{{
                            state.webIncludes[server.id]?.probe?.ok ? '已生效' : '未确认生效'
                          }}
                          · {{ state.webIncludes[server.id]?.probe?.path }}
                        </p>
                      </div>
                      <div class="web-include-row__actions">
                        <button
                          v-if="injectableWebServices.length"
                          class="ui-btn ui-btn--sm"
                          type="button"
                          :disabled="
                            busy ||
                            webIncludeLoading ||
                            webIncludeRemoving ||
                            runtime.ssh[server.id] !== 'connected'
                          "
                          @click="openWebIncludeModal"
                        >
                          {{
                            webIncludeLoading
                              ? '检测中…'
                              : state.webIncludes[server.id]
                                ? '注入管理'
                                : '注入'
                          }}
                        </button>
                        <button
                          v-if="state.webIncludes[server.id]"
                          class="ui-btn ui-btn--sm ui-btn--danger-link"
                          type="button"
                          :disabled="
                            busy ||
                            webIncludeLoading ||
                            webIncludeRemoving ||
                            runtime.ssh[server.id] !== 'connected'
                          "
                          @click="removeWebInclude"
                        >
                          {{ webIncludeRemoving ? '解除中…' : '解除' }}
                        </button>
                      </div>
                    </div>
                    <p v-if="!hostInfo.supported || hostInfo.warning" class="muted">
                      {{ !hostInfo.supported ? '当前只支持 Linux 服务器。' : hostInfo.warning }}
                    </p>
                  </div>
                </div>
                <hr />
                <template v-if="server.accessMode === 'readonly'">
                  <h3>FRP 只读连接</h3>
                  <div class="notice notice--warning">
                    已从服务器服务配置导入连接参数。此记录仅供客户端实例连接，不会启停、修改或卸载服务器上的服务。
                  </div>
                  <div class="path-info">
                    服务：{{ server.discoveredService?.name }}（{{
                      server.discoveredService?.manager
                    }}）<br />
                    程序：{{ server.discoveredService?.binary }}<br />
                    配置：{{ server.discoveredService?.config }}<br />
                    FRP 端口：{{ server.frpPort }} · HTTP 入口：{{ server.httpPort }} · HTTPS
                    入口：{{ server.httpsPort }}
                  </div>
                </template>
                <template v-else>
                  <h3 class="server-section-title">服务端部署</h3>
                  <template v-if="!server.deployment">
                    <section class="panel version-auto">
                      <div class="kv-grid">
                        <div class="kv">
                          <small>目标架构</small>
                          <strong>Linux / {{ hostInfo?.arch ?? '待探测' }}</strong>
                        </div>
                        <div class="kv">
                          <small>建议版本</small>
                          <strong>{{
                            serverResolution?.version
                              ? 'FRP ' + serverResolution.version
                              : '待获取版本列表'
                          }}</strong>
                        </div>
                        <div class="kv">
                          <small>安装包状态</small>
                          <StatusBadge
                            :tone="versionReadyTone(serverResolution)"
                            :label="versionReadyLabel(serverResolution)"
                          />
                        </div>
                      </div>
                      <p v-if="serverResolution?.note" class="hint">
                        {{ serverResolution.note }}
                      </p>
                      <div class="inline-fields">
                        <AppSelect v-model="deployVersionOverride" aria-label="选择服务端版本">
                          <option value="">自动选择（最新稳定版）</option>
                          <option
                            v-for="release in catalog?.releases ?? []"
                            :key="release.version"
                            :value="release.version"
                          >
                            FRP {{ release.version }}
                          </option>
                        </AppSelect>
                        <button
                          class="ui-btn"
                          :class="
                            runtime.ssh[server.id] === 'connected'
                              ? 'ui-btn--primary'
                              : 'ui-btn--soft'
                          "
                          type="button"
                          :disabled="busy || !serverResolution?.version"
                          @click="deployServerWithPrepare"
                        >
                          安装服务端
                        </button>
                      </div>
                    </section>
                  </template>
                  <template v-else>
                    <div class="deployment-meta">
                      <button
                        class="badge-button"
                        type="button"
                        title="切换服务端版本"
                        :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                        @click="openVersionModal"
                      >
                        <StatusBadge tone="success" :label="`FRP ${server.deployment.version}`" />
                      </button>
                      <StatusBadge
                        :tone="serviceRunning(server.id) ? 'success' : 'warning'"
                        :label="`服务 ${serviceLabel(server.id)}`"
                      />
                      <label
                        v-if="
                          (server.deployment.manager ??
                            (server.deployment.mode === 'process' ? 'process' : 'systemd')) !==
                          'process'
                        "
                        class="autostart-toggle"
                      >
                        <a-switch
                          :checked="autostartEnabled === true"
                          :disabled="
                            busy ||
                            autostartEnabled === null ||
                            runtime.ssh[server.id] !== 'connected'
                          "
                          @change="toggleAutostart"
                        />
                        <span>开机启动</span>
                      </label>
                      <span v-else class="muted">后台进程模式不提供开机启动</span>
                    </div>
                    <p v-if="runtime.serviceErrors?.[server.id]" class="hint hint--error">
                      {{ runtime.serviceErrors[server.id] }}
                    </p>
                    <div class="actions">
                      <button
                        v-if="!serviceRunning(server.id)"
                        class="ui-btn"
                        :class="
                          runtime.ssh[server.id] === 'connected'
                            ? 'ui-btn--primary'
                            : 'ui-btn--soft'
                        "
                        type="button"
                        :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                        @click="act('server:control', { id: server.id, action: 'start' })"
                      >
                        启动
                      </button>
                      <template v-else>
                        <button
                          class="ui-btn"
                          type="button"
                          :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                          @click="act('server:control', { id: server.id, action: 'stop' })"
                        >
                          停止
                        </button>
                        <button
                          class="ui-btn"
                          type="button"
                          :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                          @click="act('server:control', { id: server.id, action: 'restart' })"
                        >
                          重启
                        </button>
                      </template>
                      <button
                        class="ui-btn"
                        type="button"
                        :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                        @click="loadLogs('server')"
                      >
                        查看日志
                      </button>
                    </div>
                    <details class="server-advanced">
                      <summary>更多操作</summary>
                      <div class="actions">
                        <button
                          class="ui-btn"
                          type="button"
                          :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                          @click="readRemoteConfig"
                        >
                          读取远程配置
                        </button>
                        <button
                          class="ui-btn"
                          type="button"
                          :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                          @click="loadBackups"
                        >
                          查看 / 恢复备份
                        </button>
                      </div>
                    </details>
                  </template>
                </template>
                <div class="server-panel__foot">
                  <button
                    class="ui-btn ui-btn--sm ui-btn--danger-link"
                    type="button"
                    :disabled="busy"
                    @click="uninstallServer"
                  >
                    {{ server.accessMode === 'readonly' ? '移除只读配置' : '卸载' }}
                  </button>
                </div>
              </section>
            </div>
          </template>

          <!-- ============ 基础设施：版本库 ============ -->
          <template v-if="page === 'versions'">
            <div class="cache-bar">
              <span class="cache-bar__info">
                <StatusBadge :tone="catalogSourceTone" :label="catalogSourceLabel" />
                <template v-if="catalogUpdatedAt">
                  · 列表更新于 {{ formatTime(catalogUpdatedAt) }}</template
                >
                <template v-else> · 尚未获取官方版本列表</template>
              </span>
            </div>
            <div
              v-if="catalogStale || catalogWarning"
              class="notice notice--warning"
              style="margin-top: var(--sp-5)"
            >
              {{ catalogWarning || '当前显示的是离线缓存，建议检查网络后点击「刷新列表」。' }}
            </div>
            <div
              v-else-if="catalogOutdated"
              class="notice notice--info"
              style="margin-top: var(--sp-5)"
            >
              列表距今已超过
              {{ state.settings.catalogCacheHours }}
              小时。需要新版本时点击「刷新列表」，本工具不会自动联网。
            </div>

            <SectionCard
              title="已安装版本"
              :description="`共 ${state.versions.length} 个安装包`"
              style="margin-top: var(--sp-5)"
            >
              <EmptyState
                v-if="!state.versions.length"
                icon="▦"
                title="还没有安装包"
                description="安装服务端或创建客户端时会自动按目标架构选择并下载；也可在下方手动安装。"
                compact
              />
              <div v-for="v in state.versions" :key="v.key" class="installed-row">
                <div>
                  <strong>{{ versionLabel(v) }}</strong>
                  <small>{{ v.source }} · {{ formatTime(v.installedAt) }}</small>
                </div>
                <StatusBadge
                  :tone="v.verified ? 'success' : 'warning'"
                  :label="v.verified ? 'SHA256 已核对' : '尚未核对发布 SHA256'"
                />
                <button
                  v-if="!v.verified"
                  class="ui-btn ui-btn--soft"
                  type="button"
                  :disabled="busy"
                  @click="act('version:verify', v.key, '已与 FRP 官方 SHA256 核对。')"
                >
                  核对官方 SHA256
                </button>
                <button
                  class="ui-btn ui-btn--danger-link"
                  type="button"
                  :disabled="busy"
                  @click="deleteVersion(v.key, versionLabel(v))"
                >
                  删除
                </button>
              </div>
            </SectionCard>

            <SectionCard title="官方发布版本">
              <template #actions>
                <div class="inline-fields" style="margin: 0">
                  <AppSelect v-model="targetPlatform" style="width: auto">
                    <option value="darwin">macOS</option>
                    <option value="windows">Windows</option>
                    <option value="linux">Linux</option>
                  </AppSelect>
                  <AppSelect v-model="targetArch" style="width: auto">
                    <option value="amd64">x64 / amd64</option>
                    <option value="arm64" :disabled="targetPlatform === 'windows'">arm64</option>
                  </AppSelect>
                  <button
                    class="ui-btn ui-btn--primary"
                    type="button"
                    :disabled="busy"
                    @click="fetchCatalog(false)"
                  >
                    {{ catalog ? '刷新列表' : '获取版本列表' }}
                  </button>
                </div>
              </template>
              <p v-if="catalog && !catalog.cached" class="muted">
                本次在线取得，来源：{{
                  catalog.source === 'github-web'
                    ? 'GitHub 官方发布页面（自动兜底）'
                    : 'GitHub Releases API'
                }}
                · 更新于 {{ formatTime(catalog.updatedAt) }}
              </p>
              <EmptyState
                v-if="!catalog || !catalog.releases.length"
                icon="▦"
                title="在线获取，离线也有入口"
                description="点击「获取版本列表」联网查询；查询失败会回退本机记录，首次离线可用手动 / 离线导入。"
                compact
              />
              <div v-for="release in catalog?.releases" :key="release.version" class="release-row">
                <div>
                  <strong>FRP {{ release.version }}</strong>
                  <small>{{ formatTime(release.publishedAt) }}</small>
                </div>
                <span class="muted">{{
                  assetFor(release)?.name ?? release.assetError ?? '此版本无对应平台安装包'
                }}</span>
                <button
                  class="ui-btn"
                  type="button"
                  :disabled="
                    busy ||
                    !assetFor(release) ||
                    state.versions.some(
                      (v) => v.key === `${release.version}_${targetPlatform}_${targetArch}`,
                    )
                  "
                  @click="installRelease(release)"
                >
                  {{
                    state.versions.some(
                      (v) => v.key === `${release.version}_${targetPlatform}_${targetArch}`,
                    )
                      ? '已安装'
                      : '下载并安装'
                  }}
                </button>
              </div>
              <button
                v-if="catalog?.hasMore"
                class="ui-btn"
                type="button"
                :disabled="busy"
                @click="fetchCatalog(false, true)"
              >
                加载更多版本
              </button>
            </SectionCard>

            <SectionCard
              v-if="state.downloads.length"
              title="下载记录与断点"
              description="分片进度已保存，失败后可重试。"
            >
              <div v-for="d in state.downloads" :key="d.key" class="installed-row">
                <div>
                  <strong>{{ d.key }}</strong>
                  <small
                    >{{ d.url }} · {{ Math.round((d.received / (d.total || 1)) * 100) }}%</small
                  >
                  <small>分片：{{ d.partPath }}</small>
                </div>
                <StatusBadge
                  :tone="
                    d.status === 'succeeded' ? 'success' : d.status === 'failed' ? 'danger' : 'info'
                  "
                  :label="d.status"
                />
              </div>
            </SectionCard>
          </template>

          <!-- ============ 穿透：客户端实例 ============ -->
          <template v-if="page === 'clients'">
            <div class="section-title">
              <h2>
                本机穿透实例 <span>{{ state.instances.length }}</span>
              </h2>
            </div>
            <EmptyState
              v-if="!state.instances.length"
              icon="⇄"
              title="分享你的本地服务"
              description="使用右上角「创建实例」新建；一个实例可包含多个网站或 TCP/UDP 服务。"
            />
            <div v-else class="split">
              <div class="item-list">
                <button
                  v-for="i in state.instances"
                  :key="i.id"
                  class="item"
                  :class="{ selected: selectedInstance === i.id }"
                  type="button"
                  @click="selectedInstance = i.id"
                >
                  <strong>{{ i.name }}</strong>
                  <small
                    >{{ instanceServer(i)?.name }} ·
                    {{ state.versions.find((v) => v.key === i.versionKey)?.version }}</small
                  >
                  <StatusBadge :tone="clientTone(i.id)" :label="statusLabel(clientStatus(i.id))" />
                  <small>{{
                    i.mode === 'raw' ? '高级原始配置' : `${i.proxies.length} 个代理规则`
                  }}</small>
                </button>
              </div>
              <section v-if="instance" class="panel">
                <div class="panel-heading">
                  <div>
                    <h2>{{ instance.name }}</h2>
                    <p>
                      {{ instanceServer(instance)?.publicHost }}:{{
                        instanceServer(instance)?.frpPort
                      }}
                    </p>
                  </div>
                  <button
                    class="ui-btn ui-btn--soft"
                    type="button"
                    :disabled="busy"
                    @click="editInstance"
                  >
                    编辑实例
                  </button>
                </div>
                <div class="actions">
                  <button
                    class="ui-btn ui-btn--primary"
                    type="button"
                    :disabled="
                      busy ||
                      ['running', 'connected', 'starting'].includes(clientStatus(instance.id))
                    "
                    @click="
                      act('instance:start', instance.id, '客户端进程已启动，请查看代理注册状态。')
                    "
                  >
                    启动
                  </button>
                  <button
                    class="ui-btn"
                    type="button"
                    :disabled="busy"
                    @click="act('instance:stop', instance.id, '本机实例已停止。')"
                  >
                    停止
                  </button>
                  <button
                    class="ui-btn"
                    type="button"
                    :disabled="busy"
                    @click="act('instance:restart', instance.id)"
                  >
                    重启
                  </button>
                  <button
                    class="ui-btn"
                    type="button"
                    :disabled="busy"
                    @click="loadLogs('instance')"
                  >
                    查看日志
                  </button>
                </div>
                <div class="instance-status">
                  <StatusBadge
                    :tone="clientTone(instance.id)"
                    :label="statusLabel(clientStatus(instance.id))"
                  />
                  <span>{{ runtime.clients[instance.id]?.message ?? '尚未启动' }}</span>
                </div>
                <p
                  v-if="
                    state.versions.find((v) => v.key === instance?.versionKey)?.version !==
                      instanceServer(instance)?.deployment?.version &&
                    instanceServer(instance)?.deployment
                  "
                  class="hint"
                >
                  客户端与服务端版本不同，允许启动，连接兼容性以运行结果为准。
                </p>
                <template v-if="instance.mode === 'form'">
                  <div class="rule-list-head">
                    <h3>代理与访问地址</h3>
                    <button
                      class="ui-btn ui-btn--sm ui-btn--primary"
                      type="button"
                      :disabled="busy"
                      @click="openRuleCreate(ruleListTab === 'site' ? 'web' : 'service')"
                    >
                      ＋ 新增{{ ruleListTab === 'site' ? '站点' : '服务' }}
                    </button>
                  </div>
                  <div class="tabs">
                    <button
                      class="tabs__item"
                      :class="{ 'tabs__item--active': ruleListTab === 'site' }"
                      type="button"
                      @click="ruleListTab = 'site'"
                    >
                      站点 <span>{{ siteRules(instance).length }}</span>
                    </button>
                    <button
                      class="tabs__item"
                      :class="{ 'tabs__item--active': ruleListTab === 'service' }"
                      type="button"
                      @click="ruleListTab = 'service'"
                    >
                      服务 <span>{{ serviceRules(instance).length }}</span>
                    </button>
                  </div>
                  <div class="table-wrap">
                    <table class="data-table">
                      <thead>
                        <tr>
                          <th>规则名称</th>
                          <th>类型</th>
                          <th>本地地址和端口</th>
                          <th class="data-table__actions">操作</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr v-for="rule in currentRules(instance)" :key="rule.id">
                          <td>
                            <button
                              class="link-btn"
                              type="button"
                              :disabled="busy"
                              @click="openRuleEdit(rule)"
                            >
                              {{ rule.name }}
                            </button>
                            <span class="muted rule-status">{{
                              runtime.clients[instance.id]?.proxies[rule.id] ?? '未启动'
                            }}</span>
                          </td>
                          <td>
                            <StatusBadge
                              tone="info"
                              :label="typeLabel(rule, instance)"
                              :dot="false"
                            />
                          </td>
                          <td>
                            <code>{{ rule.localIP }}:{{ rule.localPort }}</code>
                          </td>
                          <td class="data-table__actions">
                            <button
                              class="ui-btn ui-btn--sm"
                              type="button"
                              :disabled="busy"
                              @click="openRuleEdit(rule)"
                            >
                              编辑
                            </button>
                            <button
                              class="ui-btn ui-btn--sm ui-btn--danger-link"
                              type="button"
                              :disabled="busy"
                              @click="deleteRule(rule, instance)"
                            >
                              删除
                            </button>
                          </td>
                        </tr>
                        <tr v-if="!currentRules(instance).length">
                          <td colspan="4" class="data-table__empty">
                            还没有{{
                              ruleListTab === 'site' ? '站点' : '服务'
                            }}规则，点击右上角新增。
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  <div v-if="currentRuleAddresses(instance).length" class="address-summary">
                    <strong>访问地址</strong>
                    <div
                      v-for="item in currentRuleAddresses(instance)"
                      :key="item.url"
                      class="address"
                    >
                      <code>{{ item.url }}</code>
                      <button
                        class="ui-btn ui-btn--sm"
                        type="button"
                        @click="act('clipboard', item.url, '访问地址已复制。')"
                      >
                        复制
                      </button>
                      <button
                        v-if="item.web"
                        class="ui-btn ui-btn--sm"
                        type="button"
                        @click="act('link:open', item.url)"
                      >
                        打开
                      </button>
                    </div>
                  </div>
                </template>
                <p v-else class="hint">
                  高级配置的实际代理以 FRP 日志为准，建议将日志输出设为 console。
                </p>
                <div class="server-panel__foot">
                  <button
                    class="ui-btn ui-btn--sm ui-btn--danger-link"
                    type="button"
                    :disabled="busy"
                    @click="deleteInstance"
                  >
                    删除实例
                  </button>
                </div>
              </section>
            </div>
          </template>

          <!-- ============ 证书管理：只查看，申请从 Web 规则发起 ============ -->
          <template v-if="page === 'serverCerts'">
            <div class="section-title">
              <h2>
                证书管理 <span>{{ filteredCerts.length }}</span>
              </h2>
            </div>
            <div class="notice notice--info">
              此页展示已签发的证书。申请与移除入口在「客户端实例 → Web 规则 →
              SSL」；这里可查看详情、下载与删除。
            </div>
            <div class="cert-toolbar">
              <input
                v-model="certSearch"
                class="cert-search"
                type="search"
                aria-label="搜索证书"
                placeholder="搜索证书名称、域名或签发机构"
              />
              <span class="muted">{{ filteredCerts.length }} 张证书</span>
            </div>
            <EmptyState
              v-if="!filteredCerts.length"
              icon="◇"
              :title="state.serverCertificates.length ? '没有匹配的证书' : '还没有证书'"
              :description="
                state.serverCertificates.length
                  ? '试试更换搜索关键词。'
                  : '在客户端实例的 Web 规则中填写域名后，可在 SSL 标签申请证书。'
              "
            />
            <div v-else class="cert-grid">
              <article v-for="cert in pagedCerts" :key="cert.id" class="cert-card">
                <div class="cert-card__head">
                  <strong>{{ cert.name }}</strong>
                  <StatusBadge
                    tone="success"
                    :label="cert.tlsPlan === 'server' ? '服务器终止' : '本机终止'"
                  />
                </div>
                <p class="cert-card__domains">{{ cert.domains.join('、') }}</p>
                <div class="cert-card__meta">
                  <span>{{ certificateName(cert.provider) }}</span>
                  <span>{{ cert.tlsPlan === 'server' ? '服务器目录' : '本机证书库' }}</span>
                  <span>到期 {{ cert.expiresAt ? formatTime(cert.expiresAt) : '未知' }}</span>
                </div>
                <div class="cert-card__actions">
                  <button class="ui-btn ui-btn--sm" type="button" @click="openCertDetail(cert)">
                    查看详情
                  </button>
                </div>
              </article>
            </div>
            <div v-if="certTotalPages > 1" class="pager">
              <button
                class="ui-btn ui-btn--sm"
                type="button"
                :disabled="certPage <= 1"
                @click="certPage -= 1"
              >
                上一页
              </button>
              <span class="muted">{{ certPage }} / {{ certTotalPages }}</span>
              <button
                class="ui-btn ui-btn--sm"
                type="button"
                :disabled="certPage >= certTotalPages"
                @click="certPage += 1"
              >
                下一页
              </button>
            </div>
          </template>

          <!-- ============ 工具：终端 ============ -->
          <section
            v-show="page === 'terminal'"
            class="terminal-workspace"
            @click="terminalContextMenu = undefined"
          >
            <div class="terminal-toolbar">
              <div class="terminal-tabs" role="tablist" aria-label="终端标签">
                <button
                  v-for="tab in terminalTabs"
                  :key="tab.id"
                  class="terminal-tab"
                  :class="{ active: activeTerminalId === tab.id }"
                  role="tab"
                  :aria-selected="activeTerminalId === tab.id"
                  type="button"
                  @click="selectTerminal(tab.id)"
                >
                  {{ tab.title
                  }}<span @click.stop="closeTerminalTab(tab.id)" aria-label="关闭终端">×</span>
                </button>
              </div>
              <div class="inline-fields">
                <AppSelect v-model="selectedServer" aria-label="选择服务器">
                  <option value="">选择服务器</option>
                  <option v-for="item in state.servers" :key="item.id" :value="item.id">
                    {{ item.name }} · {{ item.host }}
                  </option>
                </AppSelect>
                <button
                  class="ui-btn ui-btn--primary"
                  type="button"
                  :disabled="!selectedServer"
                  @click="openTerminalForServer(selectedServer)"
                >
                  ＋ 新终端
                </button>
              </div>
            </div>
            <EmptyState
              v-if="!state.servers.length"
              icon="⌘"
              title="先添加一台服务器"
              description="终端使用已保存的 SSH 配置和主机指纹校验。"
            >
              <template #action
                ><button
                  class="ui-btn ui-btn--primary"
                  type="button"
                  @click="
                    page = 'servers';
                    newServer();
                  "
                >
                  添加服务器
                </button></template
              >
            </EmptyState>
            <EmptyState
              v-else-if="!terminalTabs.length"
              icon="⌘"
              title="打开一个 SSH 终端"
              description="每个标签对应独立的 SSH shell 会话；关闭标签会结束该会话。"
            >
              <template #action
                ><button
                  class="ui-btn ui-btn--primary"
                  type="button"
                  :disabled="!selectedServer"
                  @click="openTerminalForServer(selectedServer)"
                >
                  连接所选服务器
                </button></template
              >
            </EmptyState>
            <div v-else class="terminal-layout" :class="{ collapsed: terminalPaneCollapsed }">
              <aside class="terminal-shortcuts">
                <div class="shortcut-header">
                  <strong>快捷命令</strong>
                  <button
                    class="ui-btn ui-btn--sm"
                    type="button"
                    @click="terminalPaneCollapsed = !terminalPaneCollapsed"
                  >
                    {{ terminalPaneCollapsed ? '展开' : '收起' }}
                  </button>
                </div>
                <template v-if="!terminalPaneCollapsed">
                  <div class="shortcut-section">
                    <button
                      class="shortcut-heading"
                      type="button"
                      @click="terminalFavoritesCollapsed = !terminalFavoritesCollapsed"
                    >
                      常用 <span>{{ terminalFavoritesCollapsed ? '＋' : '−' }}</span>
                    </button>
                    <div v-if="!terminalFavoritesCollapsed" class="shortcut-list">
                      <div v-if="!state.terminalFavorites.length" class="shortcut-empty">
                        还没有常用命令
                      </div>
                      <div
                        v-for="(favorite, index) in [...state.terminalFavorites].sort(
                          (a, b) => a.order - b.order,
                        )"
                        :key="favorite.id"
                        class="shortcut-row"
                        @dblclick="runTerminalCommand(favorite.command)"
                        @contextmenu.prevent="
                          showTerminalContextMenu($event, favorite.command, favorite.id)
                        "
                        :title="favorite.command"
                      >
                        <button
                          class="shortcut-command"
                          type="button"
                          @click="runTerminalCommand(favorite.command)"
                        >
                          {{ favorite.name }}
                        </button>
                        <div class="shortcut-actions">
                          <button
                            type="button"
                            :disabled="index === 0"
                            title="上移"
                            @click="moveTerminalFavorite(favorite.id, -1)"
                          >
                            ↑
                          </button>
                          <button
                            type="button"
                            :disabled="index === state.terminalFavorites.length - 1"
                            title="下移"
                            @click="moveTerminalFavorite(favorite.id, 1)"
                          >
                            ↓
                          </button>
                          <button
                            type="button"
                            title="重命名或编辑"
                            @click="editTerminalFavorite(favorite)"
                          >
                            ✎
                          </button>
                          <button
                            type="button"
                            title="删除"
                            @click="removeTerminalFavorite(favorite.id)"
                          >
                            ×
                          </button>
                        </div>
                      </div>
                      <button class="add-favorite" type="button" @click="addTerminalFavorite('')">
                        ＋ 添加常用命令
                      </button>
                    </div>
                  </div>
                  <div class="shortcut-section history-section">
                    <button
                      class="shortcut-heading"
                      type="button"
                      @click="terminalHistoryCollapsed = !terminalHistoryCollapsed"
                    >
                      记录 <span>{{ terminalHistoryCollapsed ? '＋' : '−' }}</span>
                    </button>
                    <div v-if="!terminalHistoryCollapsed" class="shortcut-list">
                      <div v-if="terminalHistoryLoading" class="shortcut-empty">
                        正在读取服务器 history…
                      </div>
                      <div v-else-if="terminalHistoryNotice" class="shortcut-empty">
                        {{ terminalHistoryNotice }}
                      </div>
                      <div
                        v-for="(command, index) in activeTerminal?.history.commands ?? []"
                        :key="`${index}-${command}`"
                        class="history-command"
                        :title="command"
                        @dblclick="runTerminalCommand(command)"
                        @contextmenu.prevent="showTerminalContextMenu($event, command)"
                      >
                        {{ command }}
                      </div>
                      <div v-if="activeTerminal?.history.commands.length" class="shortcut-footnote">
                        双击执行 · 右键添加到常用
                      </div>
                    </div>
                  </div>
                </template>
              </aside>
              <div class="terminal-main">
                <div
                  v-for="tab in terminalTabs"
                  :key="tab.id"
                  v-show="activeTerminalId === tab.id"
                  :data-terminal-screen="tab.id"
                  class="terminal-screen"
                ></div>
              </div>
            </div>
            <div
              v-if="terminalContextMenu"
              class="terminal-context-menu"
              :style="{ left: `${terminalContextMenu.x}px`, top: `${terminalContextMenu.y}px` }"
              @click.stop
            >
              <button
                type="button"
                @click="
                  runTerminalCommand(terminalContextMenu.command);
                  terminalContextMenu = undefined;
                "
              >
                在当前终端执行
              </button>
              <button
                v-if="!terminalContextMenu.favoriteId"
                type="button"
                @click="addTerminalFavorite(terminalContextMenu.command)"
              >
                添加到常用
              </button>
              <template v-else>
                <button
                  type="button"
                  @click="
                    editTerminalFavorite(
                      state.terminalFavorites.find(
                        (item) => item.id === terminalContextMenu?.favoriteId,
                      ),
                    );
                    terminalContextMenu = undefined;
                  "
                >
                  编辑 / 重命名
                </button>
                <button
                  class="ui-btn ui-btn--danger-link"
                  type="button"
                  @click="
                    removeTerminalFavorite(terminalContextMenu.favoriteId!);
                    terminalContextMenu = undefined;
                  "
                >
                  删除
                </button>
              </template>
            </div>
          </section>

          <!-- ============ DNS 管理 ============ -->
          <template v-if="page === 'dns'">
            <div class="tabs dns-tabs" role="tablist" aria-label="DNS 管理">
              <button
                class="tabs__item"
                :class="{ 'tabs__item--active': dnsTab === 'records' }"
                type="button"
                role="tab"
                :aria-selected="dnsTab === 'records'"
                @click="dnsTab = 'records'"
              >
                域名解析管理
              </button>
              <button
                class="tabs__item"
                :class="{ 'tabs__item--active': dnsTab === 'accounts' }"
                type="button"
                role="tab"
                :aria-selected="dnsTab === 'accounts'"
                @click="dnsTab = 'accounts'"
              >
                账户管理
              </button>
            </div>
            <div v-show="dnsTab === 'accounts'">
              <SectionCard
                description="可保存多个服务商账户；同一服务商也能配置不同 SecretID，签发与解析管理共用账户。"
              >
                <div v-if="!state.dnsAccounts.length" class="notice notice--info">
                  还没有保存 DNS 账户。添加后即可在下方查询与维护域名解析。
                </div>
                <div v-else class="resource-list">
                  <div v-for="account in state.dnsAccounts" :key="account.id" class="resource-row">
                    <StatusBadge
                      tone="neutral"
                      :label="dnsProviderLabel(account.provider)"
                      :dot="false"
                    />
                    <div>
                      <strong>{{ account.name }}</strong>
                    </div>
                    <div class="inline-fields" style="margin: 0">
                      <button
                        class="ui-btn ui-btn--sm"
                        type="button"
                        @click="editDnsAccount(account)"
                      >
                        编辑
                      </button>
                      <button
                        class="ui-btn ui-btn--sm ui-btn--danger"
                        type="button"
                        :disabled="busy"
                        @click="deleteDnsAccount(account)"
                      >
                        删除
                      </button>
                    </div>
                  </div>
                </div>
                <div class="inline-fields" style="margin-top: var(--sp-4)">
                  <button
                    class="ui-btn ui-btn--primary"
                    type="button"
                    :disabled="busy"
                    @click="openDnsAccountModal()"
                  >
                    新增账户
                  </button>
                </div>
                <p v-if="!state.secureStorage" class="notice notice--warning">
                  系统安全存储不可用，DNS 凭据无法跨会话保存。
                </p>
              </SectionCard>
            </div>

            <div v-show="dnsTab === 'records'">
              <SectionCard
                description="选择账户后读取其名下域名与解析记录；新增、修改、删除会实时调用服务商 API。"
              >
                <div class="form-grid">
                  <FormField label="DNS 账户">
                    <AppSelect
                      :model-value="dnsManage.accountId"
                      @update:model-value="
                        (value: string | number | null) => {
                          dnsManage.accountId = String(value ?? '');
                          onDnsManageAccountChange();
                        }
                      "
                    >
                      <option value="">请选择账户</option>
                      <option
                        v-for="account in state.dnsAccounts"
                        :key="account.id"
                        :value="account.id"
                      >
                        {{ account.name }}（{{ dnsProviderLabel(account.provider) }}）
                      </option>
                    </AppSelect>
                  </FormField>
                  <FormField label="域名">
                    <AppSelect
                      :model-value="dnsManage.domain"
                      :disabled="!dnsManage.domains.length"
                      @update:model-value="
                        (value: string | number | null) => {
                          dnsManage.domain = String(value ?? '');
                          onDnsManageDomainChange();
                        }
                      "
                    >
                      <option value="">
                        {{ dnsManage.loadingDomains ? '正在读取域名…' : '请选择域名' }}
                      </option>
                      <option
                        v-for="domain in dnsManage.domains"
                        :key="domain.name"
                        :value="domain.name"
                      >
                        {{ domain.name }}
                      </option>
                    </AppSelect>
                  </FormField>
                </div>
                <div
                  v-if="
                    dnsManage.accountId && !dnsManage.domains.length && !dnsManage.loadingDomains
                  "
                  class="notice notice--info"
                >
                  该账户下没有读取到域名，请确认账户凭据具备域名列表权限。
                </div>
                <div class="dns-records__bar">
                  <h3>
                    解析记录 <span>{{ dnsManage.records.length }}</span>
                  </h3>
                  <button
                    class="ui-btn ui-btn--primary ui-btn--sm"
                    type="button"
                    :disabled="busy || !dnsManage.accountId || !dnsManage.domain"
                    @click="openDnsRecordModal()"
                  >
                    ＋ 新增记录
                  </button>
                </div>
                <div v-if="!dnsManage.domain" class="dns-records__empty">
                  选择账户与域名后，这里会显示解析记录。
                </div>
                <div v-else class="table-wrap">
                  <table class="data-table">
                    <thead>
                      <tr>
                        <th>记录名称</th>
                        <th>类型</th>
                        <th>记录值</th>
                        <th>TTL</th>
                        <th class="data-table__actions">操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="record in dnsManage.records" :key="record.id">
                        <td>
                          <code>{{ record.name }}</code>
                        </td>
                        <td><StatusBadge tone="info" :label="record.type" :dot="false" /></td>
                        <td>
                          <span class="dns-records__value">{{ record.value }}</span>
                        </td>
                        <td>{{ record.ttl }}</td>
                        <td class="data-table__actions">
                          <button
                            class="ui-btn ui-btn--sm"
                            type="button"
                            :disabled="busy"
                            @click="openDnsRecordModal(record)"
                          >
                            编辑
                          </button>
                          <button
                            class="ui-btn ui-btn--sm ui-btn--danger-link"
                            type="button"
                            :disabled="busy"
                            @click="deleteDnsRecord(record)"
                          >
                            删除
                          </button>
                        </td>
                      </tr>
                      <tr v-if="dnsManage.loadingRecords">
                        <td colspan="5" class="data-table__empty">正在读取解析记录…</td>
                      </tr>
                      <tr
                        v-else-if="
                          dnsManage.accountId && dnsManage.domain && !dnsManage.records.length
                        "
                      >
                        <td colspan="5" class="data-table__empty">
                          该域名下暂无解析记录，可点击「新增记录」。
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </SectionCard>
            </div>
          </template>

          <!-- ============ 工具：设置 ============ -->
          <template v-if="page === 'settings'">
            <div class="settings-grid">
              <SectionCard
                title="下载网络"
                description="仅影响版本查询与安装包下载，不修改系统代理或 SSH 连接。"
              >
                <FormField
                  label="代理地址"
                  hint="留空为直连。支持无内嵌账号密码的 HTTP、HTTPS、SOCKS5 代理。"
                >
                  <input
                    v-model="settingsDraft.proxyUrl"
                    placeholder="http://127.0.0.1:7890 或 socks5://127.0.0.1:1080"
                  />
                </FormField>
              </SectionCard>

              <SectionCard
                title="ACME 账户"
                description="联系邮箱首次签发后自动保存；LiteSSL EAB 密钥只写入系统安全存储。"
              >
                <FormField label="联系邮箱" hint="申请证书时可修改；修改后写回这里，下次自动读取。">
                  <input v-model="settingsDraft.acmeEmail" type="email" autocomplete="email" />
                </FormField>
                <div class="form-grid">
                  <FormField label="LiteSSL EAB KID" hint="留空表示沿用已保存值">
                    <input
                      v-model="settingsDraft.eabKid"
                      autocomplete="off"
                      :placeholder="
                        acmeMasked.eabKid ? `已保存：${acmeMasked.eabKid}（留空沿用）` : ''
                      "
                    />
                  </FormField>
                  <FormField label="LiteSSL EAB HMAC 密钥" hint="留空表示沿用已保存值">
                    <input
                      v-model="settingsDraft.eabHmac"
                      type="password"
                      autocomplete="new-password"
                      :placeholder="
                        acmeMasked.eabHmac ? `已保存：${acmeMasked.eabHmac}（留空沿用）` : ''
                      "
                    />
                  </FormField>
                </div>
                <p v-if="state.settings.litesslEabConfigured" class="hint">
                  已配置 LiteSSL
                  EAB；保存设置时留空即沿用当前密钥。重新填写并保存后，下次签发会强制注册新的 ACME
                  账户（EAB 变更时必需）。
                </p>
              </SectionCard>

              <SectionCard
                title="部署与下载策略"
                description="决定证书部署默认方式、版本缓存时长与下载重试次数。"
              >
                <FormField label="证书部署默认方式">
                  <AppSelect v-model="settingsDraft.deployDefault">
                    <option value="manual">手动部署（默认，L0）</option>
                    <option value="auto">自动部署</option>
                  </AppSelect>
                </FormField>
                <div class="form-grid">
                  <FormField label="版本缓存时长（小时）"
                    ><input
                      v-model.number="settingsDraft.catalogCacheHours"
                      type="number"
                      min="1"
                      max="720"
                  /></FormField>
                  <FormField label="下载重试次数"
                    ><input
                      v-model.number="settingsDraft.downloadRetries"
                      type="number"
                      min="0"
                      max="10"
                  /></FormField>
                </div>
              </SectionCard>

              <SectionCard title="外观与安全" description="主题与危险操作确认开关。">
                <FormField label="主题">
                  <AppSelect v-model="settingsDraft.theme">
                    <option value="light">浅色</option>
                    <option value="dark">深色</option>
                    <option value="system">跟随系统</option>
                  </AppSelect>
                </FormField>
                <label class="switch-row">
                  <span class="switch-row__text">
                    <strong>危险操作二次确认</strong>
                    <small>删除、卸载、覆盖配置前弹出确认框</small>
                  </span>
                  <a-switch v-model:checked="settingsDraft.confirmDangerous" />
                </label>
              </SectionCard>
            </div>
          </template>

          <!-- ============ 工具：帮助（独立页） ============ -->
          <template v-if="page === 'help'">
            <HelpPage :platform="state.platform" />
          </template>
        </div>
      </main>

      <!-- ============ 统一反馈层 ============ -->
      <ToastHost :items="toasts" @dismiss="dismissToast" @action="onToastAction" />

      <DownloadCenter
        :tasks="downloadTasks"
        :raised="floatTask?.kind === 'server-deploy'"
        @cancel="onDownloadTaskCancel"
        @retry="onDownloadTaskRetry"
        @dismiss="dismissDownloadTask"
        @clear-finished="clearFinishedDownloadTasks"
      />

      <ConfirmDialog
        :open="!!confirmState"
        :title="confirmState?.title ?? ''"
        :message="confirmState?.message"
        :level="confirmState?.level ?? 'normal'"
        :impacts="confirmState?.impacts"
        :confirm-word="confirmState?.confirmWord"
        :confirm-label="confirmState?.confirmLabel ?? '确认'"
        :cancel-label="confirmState?.cancelLabel ?? '取消'"
        :alt-label="confirmState?.altLabel"
        :alt-tone="confirmState?.altTone"
        :busy="busy"
        @confirm="acceptConfirm"
        @alt="acceptAltConfirm"
        @cancel="cancelConfirm"
      />

      <Teleport to="body">
        <div
          v-if="floatTask"
          class="task-float"
          :class="{ 'task-float--deploy': floatTask.kind === 'server-deploy' }"
        >
          <ProgressPanel
            v-bind="floatTask.view"
            @cancel="onTaskCancel"
            @retry="onTaskRetry"
            @close="onTaskClose"
          >
            <template
              v-if="floatTask.kind === 'server-deploy' && serverDeployProgress?.hint"
              #extra
            >
              <div class="deploy-hint">
                <strong>下一步</strong>
                <p>{{ serverDeployProgress.hint }}</p>
              </div>
            </template>
            <template v-else-if="certificateProgress?.dnsRecords?.length" #extra>
              <div class="dns-records">
                <p>请在 DNS 服务商处添加以下 TXT 记录，添加完成后点击「已添加，继续」：</p>
                <div
                  v-for="record in certificateProgress?.dnsRecords ?? []"
                  :key="`${record.record}:${record.value}`"
                  class="dns-record"
                >
                  <small>域名：{{ record.domain }} · 记录名：{{ record.record }}</small>
                  <code>{{ record.value }}</code>
                  <button
                    class="ui-btn ui-btn--sm"
                    type="button"
                    @click="copyDnsRecord(record.value)"
                  >
                    复制 TXT 值
                  </button>
                </div>
                <button
                  class="ui-btn ui-btn--primary ui-btn--sm"
                  type="button"
                  :disabled="certificateProgress?.status !== 'waiting-user'"
                  @click="continueDnsChallenge"
                >
                  已添加，继续验证
                </button>
              </div>
            </template>
          </ProgressPanel>
        </div>
      </Teleport>

      <!-- ============ 表单 / 详情弹窗（统一 AppModal 骨架） ============ -->
      <AppModal
        :open="activeModal === 'server'"
        title="服务器配置"
        size="lg"
        :busy="busy"
        @close="closeModal"
      >
        <form v-if="serverDraft" id="form-server" @submit.prevent="saveServer">
          <div class="form-grid">
            <FormField label="名称" required
              ><input v-model="serverDraft.name" required placeholder="例如：演示服务器"
            /></FormField>
            <FormField label="SSH 管理地址" required
              ><input v-model="serverDraft.host" required placeholder="IP 或主机名"
            /></FormField>
            <FormField label="SSH 端口" required
              ><input
                v-model.number="serverDraft.sshPort"
                type="number"
                min="1"
                max="65535"
                required
            /></FormField>
            <FormField label="用户名" required
              ><input v-model="serverDraft.username" required
            /></FormField>
            <FormField label="认证方式">
              <AppSelect v-model="serverDraft.auth">
                <option value="key">私钥</option>
                <option value="password">密码</option>
              </AppSelect>
            </FormField>
            <FormField
              v-if="serverDraft.auth === 'password'"
              label="SSH 密码"
              hint="留空保留已存密码"
            >
              <input v-model="serverDraft.password" type="password" autocomplete="new-password" />
            </FormField>
            <template v-else>
              <FormField label="私钥路径" full required>
                <div class="inline-fields" style="margin: 0">
                  <input
                    v-model="serverDraft.keyPath"
                    required
                    placeholder="支持直接输入绝对路径"
                  />
                  <button
                    class="ui-btn"
                    type="button"
                    @click="choose('key', (p) => (serverDraft!.keyPath = p))"
                  >
                    选择文件
                  </button>
                </div>
              </FormField>
              <FormField label="密钥口令" full hint="密钥无口令可留空；编辑时留空保留">
                <input
                  v-model="serverDraft.passphrase"
                  type="password"
                  autocomplete="new-password"
                />
              </FormField>
            </template>
            <FormField
              v-if="serverDraft.deployment"
              label="部署路径（只读）"
              full
              hint="由服务端安装记录生成，程序与配置文件位置"
            >
              <div class="path-info">
                程序：{{ serverDraft.deployment.binary }}<br />
                配置：{{ serverDraft.deployment.config }}
              </div>
            </FormField>
            <FormField label="FRP 公网地址" hint="留空使用 SSH 地址"
              ><input v-model="serverDraft.publicHost"
            /></FormField>
            <FormField label="FRP 绑定端口" required
              ><input
                v-model.number="serverDraft.frpPort"
                type="number"
                min="1"
                max="65535"
                required
            /></FormField>
            <FormField
              label="HTTP 入口端口"
              required
              hint="按服务器现状填写：80 空闲可直接占用，被占用则改高端口"
            >
              <input
                v-model.number="serverDraft.httpPort"
                type="number"
                min="1"
                max="65535"
                required
              />
            </FormField>
            <FormField
              label="HTTPS 入口端口"
              required
              hint="按服务器现状填写：443 空闲可直接占用，被占用则改高端口"
            >
              <input
                v-model.number="serverDraft.httpsPort"
                type="number"
                min="1"
                max="65535"
                required
              />
            </FormField>
            <FormField label="客户端连接认证令牌" full hint="新服务器需要填写；编辑时留空保留">
              <div class="inline-fields" style="margin: 0">
                <input v-model="serverDraft.token" type="password" autocomplete="new-password" />
                <button class="ui-btn" type="button" @click="generateToken">生成随机令牌</button>
              </div>
            </FormField>
            <FormField label="服务端配置模式" full>
              <AppSelect v-model="serverDraft.configMode">
                <option value="form">常用表单</option>
                <option value="raw">高级原始配置</option>
              </AppSelect>
            </FormField>
            <template v-if="serverDraft.configMode === 'raw'">
              <div class="full notice notice--warning">
                原始配置是唯一配置来源。切回表单将忽略原始内容，请确认没有需保留的高级字段。连接参数与令牌必须自行保持一致。
              </div>
              <FormField label="配置格式" full>
                <div class="inline-fields" style="margin: 0">
                  <AppSelect v-model="serverDraft.rawFormat">
                    <option v-for="f in ['toml', 'ini', 'yaml', 'json']" :key="f">{{ f }}</option>
                  </AppSelect>
                  <button class="ui-btn" type="button" @click="importConfig('server')">
                    导入配置文件
                  </button>
                </div>
              </FormField>
              <FormField full>
                <textarea
                  v-model="serverDraft.rawConfig"
                  class="code-editor"
                  rows="12"
                  placeholder="完整 frps 配置"
                ></textarea>
              </FormField>
            </template>
          </div>
        </form>
        <template #footer>
          <button class="ui-btn" type="button" @click="closeModal">取消</button>
          <button class="ui-btn ui-btn--primary" type="submit" form="form-server" :disabled="busy">
            保存并应用
          </button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'instance'"
        title="客户端实例配置"
        size="lg"
        :busy="busy"
        @close="closeModal"
      >
        <form v-if="instanceDraft" id="form-instance" @submit.prevent="saveInstanceInstanceForm">
          <div class="form-grid">
            <FormField label="实例名称" required
              ><input v-model="instanceDraft.name" required
            /></FormField>
            <FormField label="服务器" required>
              <AppSelect v-model="instanceDraft.serverId" required>
                <option v-for="s in state.servers" :key="s.id" :value="s.id">{{ s.name }}</option>
              </AppSelect>
            </FormField>
            <FormField label="FRP 版本" full>
              <div class="version-auto">
                <div class="version-auto__head">
                  <strong>{{
                    instanceResolution?.version
                      ? 'FRP ' + instanceResolution.version
                      : '待获取版本列表'
                  }}</strong>
                  <span class="muted">{{
                    instanceResolution
                      ? instanceResolution.platform + '/' + instanceResolution.arch
                      : ''
                  }}</span>
                  <StatusBadge
                    :tone="versionReadyTone(instanceResolution)"
                    :label="versionReadyLabel(instanceResolution)"
                  />
                </div>
                <p class="hint">
                  {{ instanceResolution?.note || '选择服务器后自动确定版本。' }}
                </p>
                <AppSelect v-model="instanceVersionOverride" aria-label="更换 FRP 版本">
                  <option value="">自动选择（跟随服务器部署版本）</option>
                  <option
                    v-for="release in catalog?.releases ?? []"
                    :key="release.version"
                    :value="release.version"
                  >
                    FRP {{ release.version }}
                  </option>
                </AppSelect>
              </div>
            </FormField>
          </div>
          <template v-if="instanceDraft.mode === 'form'">
            <div class="notice notice--info">
              代理规则已移到实例详情页的「站点 /
              服务」标签中单独管理；保存配置时若实例正在运行会自动重启。
            </div>
            <div class="actions-row">
              <button class="ui-btn" type="button" @click="enterRaw">
                生成完整配置并进入高级模式
              </button>
              <button class="ui-btn" type="button" @click="instanceDraft.mode = 'raw'">
                直接编写高级配置
              </button>
            </div>
          </template>
          <template v-else>
            <div class="notice notice--warning">
              高级配置为唯一来源，表单数据不会覆盖它。服务器和版本选择用于管理；实际连接地址由原始配置决定。
            </div>
            <div class="inline-fields">
              <AppSelect v-model="instanceDraft.rawFormat">
                <option v-for="f in ['toml', 'ini', 'yaml', 'json']" :key="f">{{ f }}</option>
              </AppSelect>
              <button class="ui-btn" type="button" @click="importConfig('instance')">
                导入配置文件
              </button>
              <button class="ui-btn" type="button" @click="restoreForm">
                {{ abandonRaw ? '确认放弃原始内容，恢复表单' : '放弃高级配置并恢复表单' }}
              </button>
            </div>
            <textarea
              v-model="instanceDraft.rawConfig"
              class="code-editor"
              rows="16"
              placeholder="完整 frpc 配置"
            ></textarea>
          </template>
        </form>
        <template #footer>
          <button class="ui-btn" type="button" @click="closeModal">取消</button>
          <button
            class="ui-btn ui-btn--primary"
            type="submit"
            form="form-instance"
            :disabled="busy"
          >
            保存实例
          </button>
        </template>
      </AppModal>

      <!-- 规则编辑：Web 规则编辑态显示左侧标签（基础 / SSL），新增时只有一个基础表单 -->
      <AppModal
        :open="activeModal === 'rule'"
        :title="ruleIsEdit ? '编辑规则' : '新增规则'"
        size="lg"
        :busy="busy"
        @close="closeModal"
      >
        <div v-if="ruleDraft" class="rule-modal">
          <nav v-if="ruleIsEdit && ruleKind === 'web'" class="rule-side-tabs">
            <button
              class="rule-side-tabs__item"
              :class="{ 'rule-side-tabs__item--active': ruleTab === 'basic' }"
              type="button"
              @click="switchRuleTab('basic')"
            >
              基础
            </button>
            <button
              class="rule-side-tabs__item"
              :class="{ 'rule-side-tabs__item--active': ruleTab === 'config' }"
              type="button"
              @click="switchRuleTab('config')"
            >
              配置文件
            </button>
            <button
              class="rule-side-tabs__item"
              :class="{ 'rule-side-tabs__item--active': ruleTab === 'ssl' }"
              type="button"
              @click="switchRuleTab('ssl')"
            >
              SSL
            </button>
          </nav>
          <div class="rule-modal__content">
            <form
              v-if="ruleTab === 'basic'"
              id="form-rule"
              class="form-grid"
              @submit.prevent="saveRule"
            >
              <FormField label="规则名称" required
                ><input v-model="ruleDraft.name" required
              /></FormField>
              <FormField label="类型">
                <AppSelect :model-value="ruleKind" @update:model-value="onRuleKindChange">
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="web">Web</option>
                </AppSelect>
              </FormField>
              <FormField label="本地地址" required
                ><input v-model="ruleDraft.localIP" required
              /></FormField>
              <FormField label="本地端口" required
                ><input
                  v-model.number="ruleDraft.localPort"
                  type="number"
                  min="1"
                  max="65535"
                  required
              /></FormField>
              <FormField v-if="ruleKind === 'tcp' || ruleKind === 'udp'" label="公网端口" required>
                <input
                  v-model.number="ruleDraft.remotePort"
                  type="number"
                  min="1"
                  max="65535"
                  required
                />
              </FormField>
              <template v-else>
                <div class="notice notice--info">
                  规则默认走 HTTP；申请证书后会自动生成 HTTPS 伴随规则，无需在此切换协议。
                </div>
                <FormField label="公网域名（每行一个，也可用逗号分隔）" full required>
                  <textarea
                    :value="ruleDomainsText(ruleDraft)"
                    required
                    rows="3"
                    placeholder="demo.example.com"
                    @input="setRuleDomains(ruleDraft, $event)"
                  ></textarea>
                </FormField>
              </template>
            </form>
            <div v-else-if="ruleTab === 'config'" class="site-config-panel">
              <div class="site-config-panel__head">
                <div>
                  <strong>站点配置 · {{ siteFlavorLabel(ruleSiteFlavor) }}</strong>
                  <small>{{ ruleSiteSourceLabel }}</small>
                </div>
                <div class="inline-fields">
                  <button
                    v-if="ruleTlsPlan?.mode === 'server'"
                    class="ui-btn ui-btn--sm"
                    type="button"
                    :disabled="ruleConfigLoading || ruleConfigSaving"
                    @click="loadServerSiteConfig(true)"
                  >
                    {{ ruleConfigLoading ? '读取中…' : '读取服务器' }}
                  </button>
                  <button
                    class="ui-btn ui-btn--sm"
                    type="button"
                    :disabled="ruleConfigDetecting"
                    @click="refreshRuleHostInfo"
                  >
                    {{ ruleConfigDetecting ? '检测中…' : '刷新检测' }}
                  </button>
                </div>
              </div>
              <div class="notice notice--info">
                {{
                  ruleTlsPlan?.mode === 'server'
                    ? '当前为方案 A：TLS 由服务器 nginx 终止。下方内容来自服务器托管文件；申请证书时若文件不存在会自动生成并同步。'
                    : '当前按方案 B 生成：TLS 由本机 frpc 终止，nginx 需做 stream 透传；保存配置会写入服务器注入目录。'
                }}
                点击「保存配置」会写入服务器注入目录并校验生效，同时保存在规则数据中供查看和复制。需先在服务器面板完成
                include 注入。
              </div>
              <p v-if="ruleDraft?.siteConfigPath" class="hint">
                服务端文件：{{ ruleDraft.siteConfigPath
                }}{{
                  ruleDraft.siteConfigUpdatedAt
                    ? ` · ${formatTime(ruleDraft.siteConfigUpdatedAt)}`
                    : ''
                }}
              </p>
              <ul v-if="ruleConfigWarnings.length" class="site-config-panel__warnings">
                <li v-for="warning in ruleConfigWarnings" :key="warning">{{ warning }}</li>
              </ul>
              <CodeEditor
                v-model="ruleSiteConfigModel"
                :flavor="ruleSiteFlavor"
                :loading="ruleConfigLoading"
                height="420px"
                @save="saveRuleSiteConfig"
              />
              <div class="actions-row">
                <button
                  class="ui-btn ui-btn--primary"
                  type="button"
                  :disabled="busy || ruleConfigSaving || ruleConfigLoading"
                  @click="saveRuleSiteConfig"
                >
                  {{ ruleConfigSaving ? '保存中…' : '保存配置' }}
                </button>
                <button
                  class="ui-btn"
                  type="button"
                  :disabled="busy || ruleConfigRegenerating || ruleConfigLoading"
                  @click="regenerateSiteConfig"
                >
                  {{ ruleConfigRegenerating ? '生成中…' : '重新生成' }}
                </button>
                <button
                  class="ui-btn"
                  type="button"
                  :disabled="ruleConfigCopying"
                  @click="copyRuleSiteConfig"
                >
                  {{ ruleConfigCopying ? '复制中…' : '复制配置' }}
                </button>
              </div>
            </div>
            <div v-else-if="ruleTab === 'ssl'" class="cert-panel">
              <div class="cert-panel__section">
                <h3>当前方案</h3>
                <div class="notice notice--info">
                  {{
                    ruleTlsPlan?.mode === 'server'
                      ? '方案 A：证书部署在服务器 nginx，HTTP 与 HTTPS 两个 server 块共存；移除证书会把服务器配置恢复为 HTTP。'
                      : '方案 B：证书由本机 frpc 使用，申请或导入后会自动创建隐藏 HTTPS 伴随规则，HTTP 规则保持不变。'
                  }}
                </div>
              </div>
              <div class="cert-panel__section">
                <h3>证书状态与存放位置</h3>
                <div v-if="ruleCertDetailLoading" class="notice notice--info">
                  正在读取证书存放位置…
                </div>
                <div v-else-if="ruleActiveCertificate && ruleCertDetail" class="cert-location">
                  <div class="cert-location__row">
                    <small>状态</small>
                    <strong>
                      已启用 HTTPS（{{
                        ruleActiveCertificate.plan === 'server' ? '服务器终止' : '本机终止'
                      }}）
                    </strong>
                  </div>
                  <div class="cert-location__row">
                    <small>证书存放位置</small>
                    <code>{{ ruleCertDetail.certPath || '未记录' }}</code>
                  </div>
                  <div class="cert-location__row">
                    <small>私钥存放位置</small>
                    <code>{{ ruleCertDetail.keyPath || '未记录' }}</code>
                  </div>
                  <div v-if="ruleCertDetail.configPath" class="cert-location__row">
                    <small>站点配置</small>
                    <code>{{ ruleCertDetail.configPath }}</code>
                  </div>
                </div>
                <div v-else-if="ruleActiveCertificate" class="notice notice--info">
                  证书已关联，但未读取到存放位置；可在「证书管理」中查看。
                  <small v-if="ruleCertDetailError">{{ ruleCertDetailError }}</small>
                </div>
                <div v-else class="notice notice--info">
                  该规则尚未启用 HTTPS，可先申请或导入证书。
                </div>
              </div>
              <div v-if="ruleTlsPlan?.mode !== 'server'" class="cert-panel__section">
                <h3>手动导入证书</h3>
                <FormField label="证书 PEM（含证书链）" full>
                  <textarea
                    v-model="ruleDraft.certPem"
                    class="code-editor"
                    rows="7"
                    placeholder="-----BEGIN CERTIFICATE-----"
                  ></textarea>
                </FormField>
                <FormField label="私钥 KEY" full>
                  <textarea
                    v-model="ruleDraft.keyPem"
                    class="code-editor"
                    rows="7"
                    placeholder="-----BEGIN PRIVATE KEY-----"
                  ></textarea>
                </FormField>
                <div class="actions-row">
                  <button
                    class="ui-btn ui-btn--primary"
                    type="button"
                    :disabled="busy"
                    @click="saveRuleCert"
                  >
                    保存并启用证书
                  </button>
                </div>
              </div>
              <div class="cert-panel__section">
                <h3>证书操作</h3>
                <div class="actions-row">
                  <button class="ui-btn" type="button" :disabled="busy" @click="openCertApply">
                    {{ ruleActiveCertificate ? '重新申请证书' : '申请证书' }}
                  </button>
                  <button
                    v-if="ruleActiveCertificate"
                    class="ui-btn ui-btn--danger-link"
                    type="button"
                    :disabled="busy || ruleCertRemoving"
                    @click="removeRuleCertificate"
                  >
                    {{ ruleCertRemoving ? '移除中…' : '移除证书并回退 HTTP' }}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
        <template #footer>
          <button class="ui-btn" type="button" @click="closeModal">取消</button>
          <button
            v-if="ruleTab === 'basic'"
            class="ui-btn ui-btn--primary"
            type="submit"
            form="form-rule"
            :disabled="busy"
          >
            保存规则
          </button>
        </template>
      </AppModal>

      <!-- 证书申请：从 Web 规则 SSL 面板发起 -->
      <AppModal
        :open="activeModal === 'cert-apply'"
        title="申请证书"
        size="md"
        :busy="busy"
        @close="closeModal"
      >
        <form id="form-cert-apply" @submit.prevent="submitCertApply">
          <div v-if="certApplyPlan" class="tls-plan-panel">
            <div class="tls-plan-panel__head">
              <div>
                <strong>
                  TLS 方案：{{
                    certApplyPlan.mode === 'server' ? '服务器终止（方案 A）' : '本机终止（方案 B）'
                  }}
                </strong>
                <span>{{
                  certApplyPlanLoading ? '正在读取服务器 Web 服务与权限…' : certApplyPlan.reason
                }}</span>
              </div>
              <button
                class="ui-btn ui-btn--sm"
                type="button"
                :disabled="busy || certApplyPlanLoading"
                @click="refreshCertApplyPlan()"
              >
                {{ certApplyPlanLoading ? '检测中…' : '重新检测' }}
              </button>
            </div>
            <template v-if="!certApplyPlanLoading">
              <ul class="tls-plan-panel__checks">
                <li
                  v-for="check in certApplyPlan.checks"
                  :key="check.label"
                  :class="!check.required ? 'is-muted' : check.ok ? 'is-ok' : 'is-bad'"
                >
                  {{ check.required ? (check.ok ? '✓' : '✗') : '·' }} {{ check.label }}：{{
                    check.note
                  }}
                </li>
              </ul>
              <ul v-if="certApplyPlan.warnings.length" class="tls-plan-panel__warnings">
                <li v-for="(warning, index) in certApplyPlan.warnings" :key="index">
                  {{ warning }}
                </li>
              </ul>
              <div v-if="!certApplyPlan.canIssue" class="notice notice--warning">
                方案 A 的前置条件未满足，已阻止申请：{{ certApplyPlan.blockers.join('；') }}
              </div>
            </template>
          </div>
          <div class="form-grid">
            <FormField label="签发机构" full>
              <div class="radio-row">
                <label class="radio-option">
                  <input v-model="certApplyDraft.provider" type="radio" value="letsencrypt" />
                  <span>Let’s Encrypt</span>
                </label>
                <label class="radio-option">
                  <input v-model="certApplyDraft.provider" type="radio" value="litessl" />
                  <span>LiteSSL</span>
                </label>
              </div>
            </FormField>
            <FormField label="证书算法">
              <AppSelect v-model.number="certApplyDraft.keySize">
                <option :value="2048">RSA 2048</option>
                <option :value="3072">RSA 3072</option>
                <option :value="4096">RSA 4096</option>
              </AppSelect>
            </FormField>
            <FormField label="验证方式">
              <div class="radio-row">
                <label class="radio-option">
                  <input v-model="certApplyDraft.challenge" type="radio" value="http-01" />
                  <span>文件验证</span>
                </label>
                <label class="radio-option">
                  <input v-model="certApplyDraft.challenge" type="radio" value="dns-01" />
                  <span>DNS 验证</span>
                </label>
              </div>
            </FormField>
            <FormField
              v-if="certApplyDraft.challenge === 'dns-01'"
              label="DNS 账户"
              hint="使用设置中已保存的账户"
            >
              <AppSelect v-model="certApplyDraft.dnsAccountId" required>
                <option value="">选择 DNS 账户</option>
                <option v-for="account in state.dnsAccounts" :key="account.id" :value="account.id">
                  {{ account.name }}（{{ dnsProviderLabel(account.provider) }}）
                </option>
              </AppSelect>
            </FormField>
            <FormField label="联系邮箱" full required
              ><input v-model="certApplyDraft.email" type="email" required
            /></FormField>
            <FormField label="域名（勾选当前 Web 规则配置的域名）" full required>
              <div class="check-list">
                <label class="check-all">
                  <input
                    type="checkbox"
                    :checked="certApplyDraft.allDomains"
                    @change="toggleAllCertDomains"
                  />
                  <span>全选</span>
                </label>
                <label v-for="domain in certApplyDomainList" :key="domain" class="check-option">
                  <input
                    type="checkbox"
                    :checked="certApplyDraft.domainIds.includes(domain)"
                    @change="toggleCertDomain(domain)"
                  />
                  <span>{{ domain }}</span>
                </label>
              </div>
            </FormField>
          </div>
          <div v-if="certApplyDraft.challenge === 'http-01'" class="notice notice--info">
            文件验证由当前 Web 规则所属的客户端实例自动承载，无需选择实例。
          </div>
          <label class="terms-row">
            <input v-model="certApplyDraft.termsAgreed" type="checkbox" required />
            <span>我已阅读并同意签发机构的服务条款</span>
          </label>
        </form>
        <template #footer>
          <button class="ui-btn" type="button" @click="closeModal">取消</button>
          <button
            class="ui-btn ui-btn--primary"
            type="submit"
            form="form-cert-apply"
            :disabled="busy || certApplyPlanLoading || (!!certApplyPlan && !certApplyPlan.canIssue)"
          >
            申请证书
          </button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'manual'"
        title="手动下载 / 离线导入"
        size="lg"
        :busy="busy"
        @close="closeModal"
      >
        <form id="form-manual" @submit.prevent="installManual">
          <div class="form-grid">
            <FormField label="FRP 版本" required
              ><input v-model="manual.version" required placeholder="例如 0.71.0"
            /></FormField>
            <FormField label="系统">
              <AppSelect v-model="targetPlatform">
                <option value="darwin">macOS</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
              </AppSelect>
            </FormField>
            <FormField label="架构">
              <AppSelect v-model="targetArch">
                <option value="amd64">x64 / amd64</option>
                <option value="arm64">arm64</option>
              </AppSelect>
            </FormField>
            <FormField label="下载地址" full
              ><input v-model="manual.url" placeholder="官方安装包 URL，与本地文件二选一"
            /></FormField>
            <FormField label="本地完整安装包" full>
              <div class="inline-fields" style="margin: 0">
                <input
                  v-model="manual.localPath"
                  placeholder="ZIP 或 tar.gz 路径；填写后优先使用本地文件"
                />
                <button
                  class="ui-btn"
                  type="button"
                  @click="choose('archive', (p) => (manual.localPath = p))"
                >
                  选择文件
                </button>
              </div>
            </FormField>
            <FormField label="发布方 SHA256（可选）" full
              ><input v-model="manual.digest" placeholder="64 位十六进制校验值"
            /></FormField>
          </div>
          <p class="hint">
            本机包会执行版本检测；Linux 服务器包会在部署时检查实际版本。无发布校验值时需确认来源。
          </p>
        </form>
        <template #footer>
          <button class="ui-btn" type="button" @click="closeModal">关闭</button>
          <button class="ui-btn ui-btn--primary" type="submit" form="form-manual" :disabled="busy">
            安装所选版本
          </button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'dns-account'"
        :title="dnsAccountDraft.id ? '编辑 DNS 账户' : '新增 DNS 账户'"
        description="凭据只写入本机安全存储；编辑时留空表示沿用已保存值。"
        size="md"
        :busy="busy"
        @close="closeModal"
      >
        <div class="form-grid">
          <FormField label="账户名称" required>
            <input v-model="dnsAccountDraft.name" placeholder="例如：主域名 DNSPod" />
          </FormField>
          <FormField label="服务商">
            <AppSelect v-model="dnsAccountDraft.provider">
              <option v-for="item in dnsProviderOptions" :key="item.value" :value="item.value">
                {{ item.label }}
              </option>
            </AppSelect>
          </FormField>
        </div>
        <div v-if="activeDnsCredentialFields.length" class="form-grid">
          <FormField
            v-for="field in activeDnsCredentialFields"
            :key="field.key"
            :label="field.label"
            :hint="field.hint"
          >
            <input
              v-model="dnsAccountDraft[field.key]"
              :type="field.password ? 'password' : 'text'"
              :placeholder="dnsFieldPlaceholder(field)"
              autocomplete="off"
            />
          </FormField>
        </div>
        <p
          v-if="dnsAccountResult"
          :class="dnsAccountResultTone === 'error' ? 'hint hint--error' : 'hint'"
        >
          {{ dnsAccountResult }}
        </p>
        <p v-if="!state.secureStorage" class="notice notice--warning">
          系统安全存储不可用，DNS 凭据无法跨会话保存。
        </p>
        <template #footer>
          <button class="ui-btn" type="button" :disabled="busy" @click="closeModal">取消</button>
          <button
            class="ui-btn ui-btn--soft"
            type="button"
            :disabled="busy"
            @click="testDnsAccountDraft"
          >
            测试并保存凭据
          </button>
          <button
            class="ui-btn ui-btn--primary"
            type="button"
            :disabled="busy"
            @click="saveDnsAccount"
          >
            保存账户
          </button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'dns-record'"
        :title="dnsRecordDraft.recordId ? '编辑解析记录' : '新增解析记录'"
        :description="`域名：${dnsManage.domain}`"
        size="md"
        :busy="busy"
        @close="closeModal"
      >
        <div class="form-grid">
          <FormField label="记录名称" required hint="如 www.example.com；主域名填 @">
            <input v-model="dnsRecordDraft.name" placeholder="www.example.com 或 @" />
          </FormField>
          <FormField label="记录类型" required>
            <AppSelect v-model="dnsRecordDraft.type">
              <option v-for="type in dnsRecordOptions" :key="type" :value="type">{{ type }}</option>
            </AppSelect>
          </FormField>
        </div>
        <FormField label="记录值" required>
          <input v-model="dnsRecordDraft.value" placeholder="IP、域名或文本值" />
        </FormField>
        <div class="form-grid">
          <FormField label="TTL（秒）">
            <input v-model.number="dnsRecordDraft.ttl" type="number" min="1" max="86400" />
          </FormField>
          <FormField v-if="dnsRecordDraft.type === 'MX'" label="优先级">
            <input v-model.number="dnsRecordDraft.priority" type="number" min="0" max="65535" />
          </FormField>
          <FormField v-if="dnsRecordProvider !== 'cloudflare'" label="解析线路" hint="留空为默认">
            <input v-model="dnsRecordDraft.line" placeholder="默认" />
          </FormField>
          <FormField v-if="dnsRecordProvider === 'cloudflare'" label="CDN 代理">
            <AppSelect
              :model-value="dnsRecordDraft.proxied ? 'yes' : 'no'"
              @update:model-value="
                (value: string | number | null) =>
                  (dnsRecordDraft.proxied = String(value) === 'yes')
              "
            >
              <option value="no">否（仅 DNS）</option>
              <option value="yes">是（代理）</option>
            </AppSelect>
          </FormField>
        </div>
        <template #footer>
          <button class="ui-btn" type="button" :disabled="busy" @click="closeModal">取消</button>
          <button
            class="ui-btn ui-btn--primary"
            type="button"
            :disabled="busy"
            @click="saveDnsRecord"
          >
            保存记录
          </button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'terminal-favorite'"
        title="快捷命令"
        size="sm"
        :busy="busy"
        @close="closeModal"
      >
        <form id="form-terminal-favorite" @submit.prevent="saveTerminalFavorite">
          <FormField label="显示名称" required
            ><input
              v-model="terminalFavoriteDraft.name"
              required
              maxlength="100"
              placeholder="例如：查看磁盘空间"
          /></FormField>
          <FormField
            label="命令"
            required
            hint="命令会发送到当前选中的服务器终端执行，请确认内容安全后再运行。"
          >
            <textarea
              v-model="terminalFavoriteDraft.command"
              required
              maxlength="8192"
              rows="5"
              placeholder="df -h"
            ></textarea>
          </FormField>
        </form>
        <template #footer>
          <button class="ui-btn" type="button" @click="closeModal">取消</button>
          <button
            class="ui-btn ui-btn--primary"
            type="submit"
            form="form-terminal-favorite"
            :disabled="busy"
          >
            保存
          </button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'server-version'"
        title="切换服务端版本"
        :busy="busy"
        @close="closeModal"
      >
        <div class="form-grid">
          <div class="full kv-grid">
            <div class="kv">
              <small>当前版本</small>
              <strong>FRP {{ server?.deployment?.version ?? '未知' }}</strong>
            </div>
            <div class="kv">
              <small>目标架构</small>
              <strong>Linux / {{ hostInfo?.arch ?? '待探测' }}</strong>
            </div>
          </div>
          <FormField
            label="目标版本"
            full
            hint="本机尚无该版本时会先自动下载；切换会停止当前服务并替换程序，之后需手动启动。"
          >
            <AppSelect v-model="versionChoice" aria-label="目标版本">
              <option value="">选择版本</option>
              <option
                v-for="release in catalog?.releases ?? []"
                :key="release.version"
                :value="release.version"
              >
                FRP {{ release.version }}
              </option>
            </AppSelect>
          </FormField>
        </div>
        <template #footer>
          <button class="ui-btn" type="button" @click="closeModal">取消</button>
          <button
            class="ui-btn ui-btn--primary"
            type="button"
            :disabled="busy || !versionChoice"
            @click="switchServerVersion"
          >
            切换版本
          </button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'web-include'"
        title="Web 服务 include 注入"
        size="lg"
        :busy="busy"
        @close="closeModal"
      >
        <p class="hint">
          只读取并修改探测到的 Nginx / Apache 主配置，写入带标记的 include
          指向本工具托管目录；所有写入都会先备份、校验通过后重载，失败自动回滚。include 位于 http
          块开头，同名站点以先定义者优先，因此本工具配置优先于后续 include。
        </p>
        <p v-if="webIncludeLoading" class="muted">正在探测服务器 Web 服务…</p>
        <template v-else>
          <p class="muted">
            权限：{{
              webIncludeStatus?.root
                ? 'root'
                : webIncludeStatus?.sudo
                  ? '免密 sudo'
                  : '普通用户（无法注入）'
            }}
          </p>
          <div
            v-for="item in webIncludeStatus?.candidates ?? []"
            :key="item.flavor"
            class="web-include-row"
          >
            <div>
              <strong
                >{{ item.serviceName }} · {{ item.flavor === 'nginx' ? 'Nginx' : 'Apache' }}</strong
              >
              <small>
                主配置：{{ item.mainConfig || '未定位' }}<br />
                {{ item.running ? '运行中' : '未运行'
                }}{{ item.reason ? ` · ${item.reason}` : ' · 可安全注入' }}
              </small>
            </div>
            <button
              class="ui-btn ui-btn--primary ui-btn--sm"
              type="button"
              :disabled="
                busy ||
                webIncludeLoading ||
                !!webIncludeApplying ||
                webIncludeRemoving ||
                !item.supported ||
                !!webIncludeStatus?.injected
              "
              @click="applyWebInclude(item.flavor)"
            >
              {{ webIncludeApplying === item.flavor ? '注入中…' : '注入' }}
            </button>
          </div>
          <div v-if="webIncludeStatus?.injected" class="web-include-row web-include-row--managed">
            <div>
              <strong>已注入 {{ webIncludeStatus.injected.serviceName }}</strong>
              <small>
                {{ webIncludeStatus.injected.includeDirective }}<br />
                托管目录：{{ webIncludeStatus.injected.managedDir }}<br />
                注入时间：{{ formatTime(webIncludeStatus.injected.injectedAt) }}<br />
                include 探针：{{ webIncludeStatus.probe?.ok ? '已生效' : '未确认生效' }} ·
                {{ webIncludeStatus.probe?.path }}
                <template v-if="webIncludeStatus.probe?.note"
                  ><br />{{ webIncludeStatus.probe.note }}</template
                >
              </small>
            </div>
            <button
              class="ui-btn ui-btn--sm ui-btn--danger-link"
              type="button"
              :disabled="busy || webIncludeLoading || !!webIncludeApplying || webIncludeRemoving"
              @click="removeWebInclude"
            >
              {{ webIncludeRemoving ? '解除中…' : '解除' }}
            </button>
          </div>
          <ul v-if="webIncludeStatus?.managedFiles.length" class="site-config-panel__warnings">
            <li v-for="file in webIncludeStatus.managedFiles" :key="file.name">
              {{ file.name }} · {{ file.size }} B · {{ formatTime(file.modifiedAt) }}
            </li>
          </ul>
          <p v-if="webIncludeStatus?.warnings.length" class="muted">
            {{ webIncludeStatus.warnings.join('；') }}
          </p>
        </template>
        <template #footer>
          <button
            class="ui-btn"
            type="button"
            :disabled="webIncludeLoading || !!webIncludeApplying || webIncludeRemoving"
            @click="inspectWebInclude"
          >
            {{ webIncludeLoading ? '检测中…' : '重新检测' }}
          </button>
          <button class="ui-btn" type="button" @click="closeModal">关闭</button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'logs'"
        title="运行日志"
        size="lg"
        :busy="busy"
        @close="closeModal"
      >
        <pre class="log-view">{{ logText || '暂无日志。' }}</pre>
        <template #footer>
          <button class="ui-btn ui-btn--danger-link" type="button" @click="clearLogsConfirmed">
            清理日志
          </button>
          <button class="ui-btn" type="button" @click="act('clipboard', logText, '日志已复制。')">
            复制脱敏日志
          </button>
          <button class="ui-btn" type="button" @click="closeModal">关闭</button>
        </template>
      </AppModal>

      <AppModal
        :open="activeModal === 'backups'"
        title="部署备份"
        size="lg"
        :busy="busy"
        @close="closeModal"
      >
        <p class="hint">先停止服务再恢复。程序与配置分别备份和校验，恢复后需明确启动。</p>
        <EmptyState v-if="!backups.length" icon="▦" title="暂无备份" compact />
        <div v-for="backup in backups" :key="backup.path" class="installed-row">
          <div>
            <strong>{{ backup.kind === 'binary' ? '程序备份' : '配置备份' }}</strong>
            <small>{{ backup.path }} · {{ formatTime(backup.time) }}</small>
          </div>
          <button class="ui-btn" type="button" :disabled="busy" @click="restoreBackup(backup.path)">
            恢复
          </button>
        </div>
        <template #footer
          ><button class="ui-btn" type="button" @click="closeModal">关闭</button></template
        >
      </AppModal>

      <!-- 证书详情抽屉：存放位置与证书/私钥内容按需从主进程读取 -->
      <AppDrawer
        :open="certDetailOpen"
        title="证书详情"
        :width="560"
        :busy="certDetailLoading || certDeleting"
        @close="closeCertDetail"
      >
        <div v-if="certDetailLoading" class="notice notice--info">正在读取证书存放位置与内容…</div>
        <template v-else-if="certDetail">
          <div class="cert-detail__head">
            <strong>{{
              state.serverCertificates.find((item) => item.id === certDetail?.id)?.name ??
              certDetail.id
            }}</strong>
            <StatusBadge
              tone="neutral"
              :label="
                certDetail.storage === 'server' ? '服务器终止（方案 A）' : '本机终止（方案 B）'
              "
              :dot="false"
            />
          </div>
          <div class="kv-grid">
            <div class="kv">
              <small>存放位置</small>
              <strong>{{
                certDetail.storage === 'server' ? '服务器托管目录' : '本机证书库'
              }}</strong>
            </div>
            <div class="kv">
              <small>证书文件</small>
              <strong class="cert-detail__path">{{ certDetail.certPath || '未记录' }}</strong>
            </div>
            <div class="kv">
              <small>私钥文件</small>
              <strong class="cert-detail__path">{{ certDetail.keyPath || '未记录' }}</strong>
            </div>
            <div v-if="certDetail.configPath" class="kv">
              <small>站点配置</small>
              <strong class="cert-detail__path">{{ certDetail.configPath }}</strong>
            </div>
          </div>
          <FormField label="证书内容（含证书链）" full>
            <pre class="code-block">{{ certDetail.certPem || '未读取到证书内容' }}</pre>
          </FormField>
          <FormField label="私钥内容" full hint="私钥敏感，请勿外泄">
            <pre class="code-block">{{ certDetail.keyPem || '未读取到私钥内容' }}</pre>
          </FormField>
        </template>
        <EmptyState v-else icon="◇" title="暂无详情" compact />
        <template #footer>
          <button
            class="ui-btn ui-btn--danger-link"
            type="button"
            :disabled="!certDetail || certDeleting"
            @click="deleteCertFromPage"
          >
            {{ certDeleting ? '删除中…' : '删除证书' }}
          </button>
          <button
            class="ui-btn"
            type="button"
            :disabled="!certDetail || certDownloading"
            @click="downloadCertMaterial('key')"
          >
            下载私钥
          </button>
          <button
            class="ui-btn ui-btn--primary"
            type="button"
            :disabled="!certDetail || certDownloading"
            @click="downloadCertMaterial('cert')"
          >
            下载证书
          </button>
        </template>
      </AppDrawer>
    </div>
  </a-config-provider>
</template>
