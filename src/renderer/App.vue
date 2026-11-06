<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue';
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
  Runtime,
  Deployment,
  FrpsServiceCandidate,
  InstallRequest,
  CertificateIssueProgress,
  ServerSiteProgress,
  TerminalFavorite,
  TerminalHistory,
} from '../shared/types';
import logoUrl from '../../assets/brand/logo.svg';
import { accessAddress } from '../shared/address';

const api = window.desktop;
const state = ref<State>({
  servers: [],
  instances: [],
  certificates: [],
  serverSites: [],
  serverCertificates: [],
  terminalFavorites: [],
  versions: [],
  settings: { proxyUrl: '' },
  secureStorage: true,
  platform: '',
  arch: '',
});
const runtime = ref<{
  clients: Record<string, Runtime>;
  ssh: Record<string, string>;
  services: Record<string, string>;
  serviceErrors: Record<string, string>;
}>({ clients: {}, ssh: {}, services: {}, serviceErrors: {} });
const page = ref('servers');
const busy = ref(false);
const error = ref('');
const message = ref('');
const selectedServer = ref('');
const selectedInstance = ref('');
const modal = ref('');
const logText = ref('');
const logKind = ref<'server' | 'instance'>('instance');
const logTarget = ref('');
const catalog = ref<Catalog>();
const targetPlatform = ref<InstallRequest['platform']>('darwin');
const targetArch = ref<InstallRequest['arch']>('arm64');
const serverDraft = ref<Server>();
const instanceDraft = ref<Instance>();
const versionChoice = ref('');
const hostInfo = ref<HostInfo>();
const backups = ref<Array<{ kind: 'binary' | 'config'; path: string; time: number }>>([]);
const proxyUrl = ref('');
const showGuide = ref(true);
const abandonRaw = ref(false);
const manual = reactive({ version: '', url: '', localPath: '', digest: '' });
const certificateDraft = reactive({
  name: '',
  domainsText: '',
  certificatePath: '',
  privateKeyPath: '',
  provider: 'letsencrypt' as 'letsencrypt' | 'litessl',
  email: '',
  challenge: 'dns-01' as 'http-01' | 'dns-01',
  termsAgreed: false,
  eabKid: '',
  eabHmac: '',
});
const certificateToAssociate = ref('');
const certificateTargets = ref<string[]>([]);
const siteSelection = ref('');
const siteMainConfig = ref('');
const siteProgress = ref<ServerSiteProgress>();
const certificateProgress = ref<CertificateIssueProgress>();
const certificateProgressHistory = ref<CertificateIssueProgress[]>([]);
const activeCertificateTask = ref('');
const serviceKeyword = ref('frps');
const serviceCandidates = ref<FrpsServiceCandidate[]>([]);
const serviceSearchDone = ref(false);
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
let unsubscribeTerminal: (() => void) | undefined;
let timer: ReturnType<typeof setInterval>;
let unsubscribe: () => void;
let unsubscribeCertificateProgress: () => void;
let unsubscribeServerSiteProgress: () => void;
const uid = () => crypto.randomUUID();
const server = computed(() => state.value.servers.find((s) => s.id === selectedServer.value));
const instance = computed(() => state.value.instances.find((s) => s.id === selectedInstance.value));
const certificateRules = computed(() =>
  state.value.instances.flatMap((item) =>
    item.mode === 'form'
      ? item.proxies
          .filter((rule) => rule.type === 'https' && rule.tlsMode === 'terminate')
          .map((rule) => ({ instance: item, rule }))
      : [],
  ),
);
const siteRules = computed(() =>
  state.value.instances
    .filter(
      (item) =>
        state.value.servers.find((server) => server.id === item.serverId)?.accessMode !==
        'readonly',
    )
    .flatMap((item) =>
      item.mode === 'form'
        ? item.proxies
            .filter((rule) => rule.type === 'http' && rule.domains.length)
            .map((rule) => ({ instance: item, rule }))
        : [],
    ),
);
const linuxVersions = computed(() =>
  state.value.versions.filter(
    (v) => v.platform === 'linux' && (!hostInfo.value || v.arch === hostInfo.value.arch),
  ),
);
const localVersions = computed(() =>
  state.value.versions.filter(
    (v) => v.platform === state.value.platform && v.arch === state.value.arch,
  ),
);
const activeTerminal = computed(() =>
  terminalTabs.value.find((tab) => tab.id === activeTerminalId.value),
);
const terminalServer = (id: string) => state.value.servers.find((item) => item.id === id);
const navIcons: Record<string, string> = {
  servers: '▤',
  terminal: '⌘',
  clients: '⇄',
  certificates: '◇',
  sites: '⌂',
  versions: '▦',
  settings: '⚙',
};
const modalTitles: Record<string, string> = {
  'terminal-favorite': '快捷命令',
  server: '服务器配置',
  instance: '客户端实例配置',
  manual: '手动安装与离线导入',
  'certificate-import': '导入 SSL 证书',
  'certificate-issue': '签发 SSL 证书',
  'certificate-progress': '证书签发进度',
  'certificate-associate': '关联 SSL 证书',
  logs: '运行日志',
  backups: '部署备份',
};
const titles: Record<string, string> = {
  servers: '服务器',
  terminal: '终端',
  clients: '客户端实例',
  certificates: 'SSL 证书',
  sites: '服务器站点',
  versions: '版本库',
  settings: '设置与帮助',
};
const descriptions: Record<string, string> = {
  servers: '连接服务器、检索已有 FRP 服务，或部署并管理服务端。',
  terminal: '通过 SSH 连接已添加的服务器，管理多个独立终端会话。',
  clients: '将本机服务分享出去，多套配置可以同时运行。',
  certificates: '在本机导入或签发证书，并关联到 HTTPS 客户端规则。',
  sites: '通过 SSH 管理 Nginx 站点和服务器端证书。',
  versions: '按版本、平台和架构管理程序，联网与离线都能安装。',
  settings: '调整下载网络，了解平台权限和部署注意事项。',
};
async function rpc<T>(action: string, payload?: unknown): Promise<T> {
  if (!api) throw new Error('此页面需在 Electron 桌面应用中使用，请运行 npm run dev。');
  const result = await api.call<T>(
    action,
    payload === undefined ? undefined : JSON.parse(JSON.stringify(payload)),
  );
  if (!result.ok) throw new Error(result.error);
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
}
async function refreshRuntime() {
  runtime.value = await rpc('runtime');
}
async function act(action: string, payload?: unknown, success = '') {
  if (busy.value) return;
  busy.value = true;
  error.value = '';
  message.value = '';
  try {
    const data = await rpc<any>(action, payload);
    message.value = typeof data === 'string' ? data : (data?.note ?? success);
    await refresh();
    return data;
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
async function createServerSite() {
  const [instanceId, ruleId] = siteSelection.value.split(':');
  const source = siteRules.value.find(
    (item) => item.instance.id === instanceId && item.rule.id === ruleId,
  );
  if (!source) return;
  const result = await act(
    'site:create',
    {
      instanceId: source.instance.id,
      ruleId: source.rule.id,
      ...(siteMainConfig.value ? { mainConfig: siteMainConfig.value } : {}),
    },
    'Nginx 站点已创建并应用。',
  );
  if (result) {
    siteSelection.value = '';
    siteMainConfig.value = '';
  }
}
async function searchFrpsServices() {
  if (!server.value) return;
  const result = await act('server:search-services', {
    id: server.value.id,
    keyword: serviceKeyword.value,
  });
  if (Array.isArray(result)) {
    serviceCandidates.value = result;
    serviceSearchDone.value = true;
  }
}
async function importFrpsService(candidate: FrpsServiceCandidate) {
  if (!server.value) return;
  await act(
    'server:import-service',
    { id: server.value.id, ...candidate },
    'FRP 服务连接信息已保存为只读服务器。',
  );
  if (!error.value) serviceCandidates.value = [];
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
  modal.value = 'server';
}
function editServer() {
  if (server.value) {
    serverDraft.value = JSON.parse(JSON.stringify(server.value));
    modal.value = 'server';
  }
}
async function saveServer() {
  const s = serverDraft.value!;
  if (!s.publicHost) s.publicHost = s.host;
  // 留空代表保留已保存的凭据，避免编辑普通字段时意外清空认证信息。
  const input = {
    ...s,
    password: s.password || undefined,
    passphrase: s.passphrase || undefined,
    token: s.token || undefined,
  };
  await act('server:save', input, '服务器配置已保存，尚未修改远程配置。');
  if (!error.value) {
    selectedServer.value = s.id;
    modal.value = '';
  }
}
function newInstance() {
  const s = server.value ?? state.value.servers[0];
  if (!s) {
    error.value = '请先添加服务器。';
    page.value = 'servers';
    return;
  }
  const preferred =
    localVersions.value.find((v) => v.version === s.deployment?.version) ?? localVersions.value[0];
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
  addProxy();
  abandonRaw.value = false;
  modal.value = 'instance';
}
function editInstance() {
  if (instance.value) {
    instanceDraft.value = JSON.parse(JSON.stringify(instance.value));
    abandonRaw.value = false;
    modal.value = 'instance';
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
function ruleDomainsText(rule: ProxyRule) {
  return rule.domains.join('\n');
}
function setRuleDomains(rule: ProxyRule, event: Event) {
  rule.domains = (event.target as HTMLTextAreaElement).value
    .split(/[\n,，;；]+/)
    .map((domain) => domain.trim().toLowerCase());
  // .filter(Boolean);
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
function setRuleCertificate(rule: ProxyRule, event: Event) {
  rule.certificateId = (event.target as HTMLSelectElement).value || undefined;
  rule.certPath = '';
  rule.keyPath = '';
}
function certificateCoversRule(certificateId: string, rule: ProxyRule) {
  const certificate = state.value.certificates.find((item) => item.id === certificateId);
  return !!certificate && rule.domains.every((domain) => certificate.domains.includes(domain));
}
function startCertificateIssue() {
  Object.assign(certificateDraft, {
    name: '',
    domainsText: 'frc.jinxianruanjian.cn',
    certificatePath: '',
    privateKeyPath: '',
    provider: 'letsencrypt',
    email: '228762287@qq.com',
    challenge: 'dns-01',
    termsAgreed: true,
    eabKid: '',
    eabHmac: '',
  });
  modal.value = 'certificate-issue';
}
function startCertificateImport() {
  Object.assign(certificateDraft, {
    name: '',
    domainsText: '',
    certificatePath: '',
    privateKeyPath: '',
  });
  modal.value = 'certificate-import';
}
async function submitCertificateIssue() {
  if (busy.value) return;
  const taskId = uid();
  activeCertificateTask.value = taskId;
  certificateProgressHistory.value = [];
  certificateProgress.value = {
    taskId,
    status: 'running',
    step: '准备签发',
    message: '正在提交签发任务。',
    updatedAt: Date.now(),
  };
  modal.value = 'certificate-progress';
  busy.value = true;
  error.value = '';
  message.value = '';
  try {
    await rpc('certificate:issue', {
      taskId,
      name: certificateDraft.name,
      domains: certificateDraft.domainsText
        .split(/[\n,，;；]+/)
        .map((domain) => domain.trim())
        .filter(Boolean),
      provider: certificateDraft.provider,
      email: certificateDraft.email,
      challenge: certificateDraft.challenge,
      termsAgreed: certificateDraft.termsAgreed,
      eabKid: certificateDraft.eabKid || undefined,
      eabHmac: certificateDraft.eabHmac || undefined,
    });
    message.value = '证书已签发并保存。';
    await refresh();
  } catch (e) {
    error.value = (e as Error).message;
    if (
      certificateProgress.value &&
      !['succeeded', 'failed', 'cancelled'].includes(certificateProgress.value.status)
    )
      updateCertificateProgress({
        ...certificateProgress.value,
        status: 'failed',
        message: error.value,
        updatedAt: Date.now(),
      });
  } finally {
    busy.value = false;
  }
}
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
    await rpc('certificate:cancel', activeCertificateTask.value);
  } catch (e) {
    error.value = (e as Error).message;
  }
}
async function continueDnsChallenge() {
  if (!activeCertificateTask.value) return;
  try {
    await rpc('certificate:challenge-response', {
      id: activeCertificateTask.value,
      continueIssue: true,
    });
  } catch (e) {
    error.value = (e as Error).message;
  }
}
async function copyDnsRecord(value: string) {
  try {
    await rpc('clipboard', value);
    message.value = 'TXT 值已复制。';
  } catch (e) {
    error.value = (e as Error).message;
  }
}
async function submitCertificateImport() {
  const result = await act(
    'certificate:import',
    {
      name: certificateDraft.name,
      domains: certificateDraft.domainsText
        .split(/[\n,，;；]+/)
        .map((domain) => domain.trim())
        .filter(Boolean),
      certificatePath: certificateDraft.certificatePath,
      privateKeyPath: certificateDraft.privateKeyPath,
    },
    '证书已导入。',
  );
  if (result) modal.value = '';
}
function startCertificateAssociation(certificateId: string) {
  certificateToAssociate.value = certificateId;
  const certificate = state.value.certificates.find((item) => item.id === certificateId);
  certificateTargets.value = certificateRules.value
    .filter(
      ({ rule }) =>
        certificate && rule.domains.every((domain) => certificate.domains.includes(domain)),
    )
    .map(({ instance: item, rule }) => `${item.id}::${rule.id}`);
  modal.value = 'certificate-associate';
}
function certificateUsage(certificateId: string) {
  return state.value.instances.reduce(
    (count, item) =>
      count + item.proxies.filter((rule) => rule.certificateId === certificateId).length,
    0,
  );
}
function certificateName(provider: string) {
  return provider === 'letsencrypt'
    ? 'Let’s Encrypt'
    : provider === 'litessl'
      ? 'LiteSSL'
      : '手动证书';
}
async function submitCertificateAssociation() {
  const result = await act('certificate:associate', {
    certificateId: certificateToAssociate.value,
    targets: certificateTargets.value.map((value) => {
      const [instanceId, ruleId] = value.split('::');
      return { instanceId, ruleId };
    }),
  });
  if (result) modal.value = '';
}
async function saveInstance() {
  const i = instanceDraft.value!;
  await act('instance:save', i, '实例已保存，点击启动开始分享。');
  if (!error.value) {
    selectedInstance.value = i.id;
    modal.value = '';
  }
}
async function enterRaw() {
  try {
    instanceDraft.value!.rawConfig = await rpc<string>('instance:preview', instanceDraft.value);
    instanceDraft.value!.mode = 'raw';
  } catch (e) {
    error.value = (e as Error).message;
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
    error.value = (e as Error).message;
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
    error.value = (e as Error).message;
  }
}
async function fetchCatalog(next = false) {
  const data = await act('version:catalog', next ? (catalog.value?.page ?? 0) + 1 : 1);
  if (data)
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
  await act(
    'version:install',
    {
      version: release.version,
      platform: targetPlatform.value,
      arch: targetArch.value,
      url: asset.url,
      digest: asset.digest,
    },
    '版本已安装。',
  );
}
async function installManual() {
  await act(
    'version:install',
    {
      version: manual.version,
      platform: targetPlatform.value,
      arch: targetArch.value,
      url: manual.url || undefined,
      localPath: manual.localPath || undefined,
      digest: manual.digest || undefined,
    },
    '版本已安装。',
  );
}
async function detectServer() {
  const result = await act('server:detect', selectedServer.value);
  if (result) {
    hostInfo.value = result;
    versionChoice.value = linuxVersions.value[0]?.key ?? '';
  }
}
async function connectServer() {
  const result = await act('server:connect', server.value?.id, 'SSH 已连接并完成主机信息采集。');
  if (result && typeof result === 'object' && 'supported' in result) {
    hostInfo.value = result as HostInfo;
    versionChoice.value = linuxVersions.value[0]?.key ?? '';
  }
}

function selectServer(id: string) {
  selectedServer.value = id;
  hostInfo.value = undefined;
  versionChoice.value = '';
  serviceCandidates.value = [];
  serviceSearchDone.value = false;
  if (runtime.value.ssh[id] === 'connected') void detectServer();
}
async function disconnectServer() {
  if (server.value) {
    await act('server:disconnect', server.value.id, 'SSH 已断开，远程服务继续运行。');
    if (!error.value) hostInfo.value = undefined;
  }
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
async function loadLogs(kind: 'server' | 'instance') {
  logKind.value = kind;
  logTarget.value = kind === 'server' ? selectedServer.value : selectedInstance.value;
  const data = await act(`${kind}:logs`, logTarget.value);
  if (typeof data === 'string') {
    logText.value = data;
    message.value = '';
    modal.value = 'logs';
  }
}
async function clearLogs() {
  const result = await act(`${logKind.value}:logs:clear`, logTarget.value);
  if (typeof result === 'string') logText.value = '';
}
async function readRemoteConfig() {
  const data = await act('server:read-config', selectedServer.value);
  if (typeof data === 'string') {
    editServer();
    serverDraft.value!.configMode = 'raw';
    serverDraft.value!.rawConfig = data;
    message.value = '已读取远程配置。请断开 SSH 后保存本机编辑，再连接并应用。';
  }
}
async function generateToken() {
  serverDraft.value!.token = await rpc<string>('token:generate');
}
async function loadBackups() {
  const data = await act('server:backups', selectedServer.value);
  if (data) {
    backups.value = data;
    modal.value = 'backups';
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
function formatTime(value: string) {
  return value ? new Date(value).toLocaleString('zh-CN') : '未知';
}
function instanceServer(i: Instance) {
  return state.value.servers.find((s) => s.id === i.serverId);
}
// 创建标签后再挂载 xterm，避免 SSH 输出落到尚未初始化的视图。
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
    // 标签尚未布局完成时忽略尺寸同步，显示后会再次适配。
  }
}
async function selectTerminal(id: string) {
  activeTerminalId.value = id;
  await nextTick();
  terminalResize(id);
  terminalInstances.get(id)?.terminal.focus();
  await loadTerminalHistory(id);
}
// 切换标签时读取服务器持久化 history；当前 shell 的未落盘命令不会被伪造补入。
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
    error.value = '请先打开一个终端标签。';
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
  modal.value = 'terminal-favorite';
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
  modal.value = 'terminal-favorite';
}
function navigatePage(target: string) {
  page.value = target;
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
  await act(
    'terminal-favorite:save',
    {
      ...terminalFavoriteDraft,
      order: current?.order ?? state.value.terminalFavorites.length,
      updatedAt: Date.now(),
    },
    '快捷命令已保存。',
  );
  if (!error.value) modal.value = '';
}
async function removeTerminalFavorite(id: string) {
  await act('terminal-favorite:delete', id, '快捷命令已删除。');
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
  unsubscribeServerSiteProgress = api?.onServerSiteProgress((progress) => {
    siteProgress.value = progress;
    if (progress.status === 'completed') setTimeout(() => (siteProgress.value = undefined), 5000);
  });
  try {
    await refresh();
    proxyUrl.value = state.value.settings.proxyUrl;
    targetPlatform.value = state.value.platform as InstallRequest['platform'];
    targetArch.value = state.value.arch as InstallRequest['arch'];
    showGuide.value = !state.value.servers.length;
  } catch (e) {
    error.value = (e as Error).message;
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
  unsubscribeServerSiteProgress?.();
  unsubscribeTerminal?.();
  window.removeEventListener('resize', resizeActiveTerminal);
});
function resizeActiveTerminal() {
  if (activeTerminalId.value) terminalResize(activeTerminalId.value);
}
</script>

<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark"><img :src="logoUrl" alt="穿透工作台标志" /></div>
        <div><strong>穿透工作台</strong><small>INTRANET / FRP</small></div>
      </div>
      <div class="nav-label">工作空间</div>
      <nav>
        <button
          v-for="(title, key) in titles"
          :key="key"
          :class="{ active: page === key }"
          @click="navigatePage(key)"
        >
          <span>{{ navIcons[key] }}</span
          >{{ title }}<b v-if="key === 'servers'">{{ state.servers.length }}</b
          ><b v-if="key === 'clients'">{{ state.instances.length }}</b>
        </button>
      </nav>
      <div class="sidebar-bottom">
        <span class="dot"></span>本机 · {{ state.platform || '正在连接' }} / {{ state.arch
        }}<small>FRP 独立运行 · 配置保存在本机</small
        ><button class="text-button" @click="act('app:quit')">退出并停止本机穿透</button>
      </div>
    </aside>
    <main>
      <header>
        <div>
          <div class="eyebrow">FRP MANAGEMENT</div>
          <h1>{{ titles[page] }}</h1>
          <p>{{ descriptions[page] }}</p>
        </div>
        <button class="secondary" @click="showGuide = !showGuide">
          {{ showGuide ? '收起向导' : '使用向导' }}
        </button>
      </header>
      <section v-if="showGuide" class="guide">
        <div>
          <span>01</span><strong>添加服务器</strong>
          <p>填写 SSH 和公网连接信息</p>
          <button
            @click="
              page = 'servers';
              newServer();
            "
          >
            添加服务器 →
          </button>
        </div>
        <div>
          <span>02</span><strong>准备与部署</strong>
          <p>安装本机及 Linux 版本，连接服务器部署</p>
          <button @click="page = 'versions'">打开版本库 →</button>
        </div>
        <div>
          <span>03</span><strong>启动并分享</strong>
          <p>添加本地规则，启动后复制访问地址</p>
          <button
            @click="
              page = 'clients';
              newInstance();
            "
          >
            创建实例 →
          </button>
        </div>
      </section>
      <div v-if="error" class="notice error" role="alert">
        {{ error }}<button @click="error = ''">×</button>
      </div>
      <div v-if="message && modal !== 'logs'" class="notice success" role="status">
        {{ message }}<button @click="message = ''">×</button>
      </div>
      <div v-if="siteProgress" class="notice progress" role="status">
        <strong>{{ siteProgress.step }}</strong> · {{ siteProgress.message }}
      </div>
      <div v-if="busy" class="notice progress">正在执行操作，请稍候…</div>
      <div v-if="!state.secureStorage" class="notice warning">
        系统安全存储不可用：密码、令牌及原始配置只在本次会话保留，重启后需要重新输入。
      </div>

      <template v-if="page === 'servers'">
        <div class="section-title">
          <h2>
            我的服务器 <span>{{ state.servers.length }}</span>
          </h2>
          <button class="primary" :disabled="busy" @click="newServer">＋ 添加服务器</button>
        </div>
        <div v-if="!state.servers.length" class="empty">
          <div class="empty-icon">▤</div>
          <h3>从一台服务器开始</h3>
          <p>支持 SSH 密码或密钥登录，可部署 FRP 服务端，或检索已有服务并保存只读连接。</p>
          <button class="primary" @click="newServer">添加第一台服务器</button>
        </div>
        <div v-else class="split">
          <div class="item-list">
            <button
              v-for="s in state.servers"
              :key="s.id"
              class="item"
              :class="{ selected: selectedServer === s.id }"
              @click="selectServer(s.id)"
            >
              <strong>{{ s.name }}</strong
              ><small>{{ s.publicHost }}:{{ s.frpPort }}</small
              ><span class="badge" :class="runtime.ssh[s.id]"
                >SSH {{ statusLabel(runtime.ssh[s.id] ?? 'disconnected') }}</span
              ><small>{{
                s.accessMode === 'readonly'
                  ? `只读 FRP · ${s.discoveredService?.name ?? '已检索'}`
                  : s.deployment
                    ? `FRP ${s.deployment.version} · ${s.deployment.mode}`
                    : '尚未部署服务端'
              }}</small>
            </button>
          </div>
          <section v-if="server" class="panel">
            <div class="panel-heading">
              <div>
                <h2>{{ server.name }}</h2>
                <p>{{ server.username }}@{{ server.host }}:{{ server.sshPort }}</p>
              </div>
              <button
                v-if="server.accessMode !== 'readonly'"
                class="secondary"
                :disabled="busy"
                @click="editServer"
              >
                编辑配置</button
              ><span v-else class="badge">只读连接</span>
            </div>
            <div class="actions">
              <button class="secondary" @click="openTerminalForServer(server.id)">打开终端</button>
              <button
                class="primary"
                :disabled="busy || runtime.ssh[server.id] === 'connected'"
                @click="connectServer"
              >
                连接 SSH</button
              ><button
                :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                @click="disconnectServer"
              >
                断开</button
              ><button
                :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                @click="detectServer"
              >
                刷新主机信息
              </button>
            </div>
            <div v-if="hostInfo" class="info-box">
              <strong
                >{{ hostInfo.distribution }} {{ hostInfo.version }} ·
                {{ hostInfo.arch || '架构不可用' }}</strong
              >
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
              <p v-if="!hostInfo.supported || hostInfo.warning" class="muted">
                {{ !hostInfo.supported ? '当前只支持 Linux 服务器。' : hostInfo.warning }}
              </p>
              <details>
                <summary>查看端口占用</summary>
                <pre>{{ hostInfo.ports }}</pre>
              </details>
            </div>
            <hr />
            <template v-if="server.accessMode === 'readonly'">
              <h3>FRP 只读连接</h3>
              <div class="notice warning">
                已从服务器服务配置导入连接参数。此记录仅供客户端实例连接，不会启停、修改或卸载服务器上的服务。
              </div>
              <div class="path-info">
                服务：{{ server.discoveredService?.name }}（{{
                  server.discoveredService?.manager
                }}）<br />
                程序：{{ server.discoveredService?.binary }}<br />
                配置：{{ server.discoveredService?.config }}<br />
                FRP 端口：{{ server.frpPort }} · HTTP 入口：{{ server.httpPort }} · HTTPS 入口：{{
                  server.httpsPort
                }}
              </div>
            </template>
            <template v-else>
              <h3>服务端部署</h3>
              <template v-if="!server.deployment"
                ><p class="muted">
                  已安装 FRP 服务可先检索并导入为只读连接；新服务请从版本库安装对应 Linux 包后部署。
                </p>
                <section class="panel compact-panel">
                  <h4>检索已有 FRP 服务</h4>
                  <p class="muted">
                    默认扫描应用命名的 FRP 服务和运行进程，也可输入服务名关键词筛选。
                  </p>
                  <div class="inline-fields">
                    <input v-model="serviceKeyword" placeholder="服务名关键词，如 intranet-frps" />
                    <button
                      class="secondary"
                      :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                      @click="searchFrpsServices"
                    >
                      检索服务
                    </button>
                  </div>
                  <div v-if="serviceCandidates.length" class="candidate-list">
                    <article
                      v-for="candidate in serviceCandidates"
                      :key="`${candidate.manager}:${candidate.service}`"
                      class="record-card"
                    >
                      <div>
                        <strong
                          >{{ candidate.service }} · {{ candidate.manager }} ·
                          {{ candidate.state }}</strong
                        >
                        <small>程序：{{ candidate.binary }}</small>
                        <small>配置：{{ candidate.config }}</small>
                      </div>
                      <button
                        class="primary"
                        :disabled="busy"
                        @click="importFrpsService(candidate)"
                      >
                        读取配置并保存只读连接
                      </button>
                    </article>
                  </div>
                  <p v-else-if="serviceSearchDone" class="hint">
                    没有找到匹配的 FRP 服务。检查服务名关键词、SSH
                    账号的服务可见权限，或确认服务正在以 FRP 服务端程序运行。
                  </p>
                </section>
                <div class="inline-fields">
                  <select v-model="versionChoice">
                    <option value="">选择 Linux 安装包</option>
                    <option v-for="v in linuxVersions" :key="v.key" :value="v.key">
                      {{ versionLabel(v) }}
                    </option>
                  </select>
                  <button
                    class="primary"
                    :disabled="
                      busy ||
                      !versionChoice ||
                      !hostInfo?.supported ||
                      runtime.ssh[server.id] !== 'connected'
                    "
                    @click="act('server:deploy', { id: server.id, key: versionChoice })"
                  >
                    安装服务端
                  </button>
                </div>
              </template>
              <template v-else
                ><div class="deployment-meta">
                  <span class="badge connected">FRP {{ server.deployment.version }}</span
                  ><span
                    class="badge"
                    :title="runtime.serviceErrors?.[server.id] || ''"
                    :class="
                      ['active', 'running'].includes(runtime.services?.[server.id])
                        ? 'connected'
                        : ''
                    "
                    >服务 {{ serviceLabel(server.id) }}</span
                  ><small v-if="runtime.serviceErrors?.[server.id]" class="muted">
                    {{ runtime.serviceErrors[server.id] }} </small
                  ><span
                    >{{ deploymentLabel(server.deployment) }} ·
                    {{ server.deployment.managed ? '工具安装' : '外部服务记录' }}</span
                  >
                </div>
                <div class="path-info">
                  程序：{{ server.deployment.binary }}<br />配置：{{ server.deployment.config }}
                </div>
                <div class="actions">
                  <button
                    v-for="(label, action) in { start: '启动', stop: '停止', restart: '重启' }"
                    :key="action"
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="act('server:control', { id: server.id, action })"
                  >
                    {{ label }}</button
                  ><button
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="act('server:status', server.id)"
                  >
                    查看服务状态</button
                  ><button
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="loadLogs('server')"
                  >
                    查看日志
                  </button>
                </div>
                <div class="actions">
                  <button
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="act('server:apply', server.id)"
                  >
                    应用已保存配置</button
                  ><button
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="readRemoteConfig"
                  >
                    读取远程配置</button
                  ><button
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="loadBackups"
                  >
                    查看 / 恢复备份</button
                  ><button
                    v-if="
                      (server.deployment.manager ??
                        (server.deployment.mode === 'process' ? 'process' : 'systemd')) !==
                      'process'
                    "
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="act('server:control', { id: server.id, action: 'enable' })"
                  >
                    开启开机启动</button
                  ><button
                    v-if="
                      (server.deployment.manager ??
                        (server.deployment.mode === 'process' ? 'process' : 'systemd')) !==
                      'process'
                    "
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="act('server:control', { id: server.id, action: 'disable' })"
                  >
                    关闭开机启动
                  </button>
                </div>
                <div class="inline-fields">
                  <select v-model="versionChoice">
                    <option value="">选择替换版本</option>
                    <option v-for="v in linuxVersions" :key="v.key" :value="v.key">
                      {{ versionLabel(v) }}
                    </option></select
                  ><button
                    :disabled="busy || !versionChoice || runtime.ssh[server.id] !== 'connected'"
                    @click="act('server:version', { id: server.id, key: versionChoice })"
                  >
                    停止后切换版本
                  </button>
                </div>
              </template>
            </template>
            <div class="actions">
              <button
                class="danger-link"
                :disabled="busy"
                @click="
                  act('server:uninstall', { id: server.id, removeRemote: !!server.deployment })
                "
              >
                {{ server.accessMode === 'readonly' ? '移除只读配置' : '卸载' }}
              </button>
            </div>
            <div class="hint">
              SSH 连接与 FRP 服务状态相互独立。请放行 FRP
              连接及代理入口端口；本工具不会自动修改防火墙。
            </div>
          </section>
        </div>
      </template>

      <template v-if="page === 'clients'">
        <div class="section-title">
          <h2>
            本机穿透实例 <span>{{ state.instances.length }}</span>
          </h2>
          <button class="primary" :disabled="busy" @click="newInstance">＋ 创建实例</button>
        </div>
        <div v-if="!state.instances.length" class="empty">
          <div class="empty-icon">⇄</div>
          <h3>分享你的本地服务</h3>
          <p>一个实例连接一台服务器，可包含多个网站或 TCP/UDP 服务。</p>
          <button class="primary" @click="newInstance">创建第一个实例</button>
        </div>
        <div v-else class="split">
          <div class="item-list">
            <button
              v-for="i in state.instances"
              :key="i.id"
              class="item"
              :class="{ selected: selectedInstance === i.id }"
              @click="selectedInstance = i.id"
            >
              <strong>{{ i.name }}</strong
              ><small
                >{{ instanceServer(i)?.name }} ·
                {{ state.versions.find((v) => v.key === i.versionKey)?.version }}</small
              ><span class="badge" :class="clientStatus(i.id)">{{
                statusLabel(clientStatus(i.id))
              }}</span
              ><small>{{
                i.mode === 'raw' ? '高级原始配置' : `${i.proxies.length} 个代理规则`
              }}</small>
            </button>
          </div>
          <section v-if="instance" class="panel">
            <div class="panel-heading">
              <div>
                <h2>{{ instance.name }}</h2>
                <p>
                  {{ instanceServer(instance)?.publicHost }}:{{ instanceServer(instance)?.frpPort }}
                </p>
              </div>
              <button class="secondary" :disabled="busy" @click="editInstance">编辑实例</button>
            </div>
            <div class="actions">
              <button
                class="primary"
                :disabled="
                  busy || ['running', 'connected', 'starting'].includes(clientStatus(instance.id))
                "
                @click="
                  act('instance:start', instance.id, '客户端进程已启动，请查看代理注册状态。')
                "
              >
                启动</button
              ><button
                :disabled="busy"
                @click="act('instance:stop', instance.id, '本机实例已停止。')"
              >
                停止</button
              ><button :disabled="busy" @click="act('instance:restart', instance.id)">重启</button
              ><button :disabled="busy" @click="loadLogs('instance')">查看日志</button
              ><button
                class="danger-link"
                :disabled="busy"
                @click="act('instance:delete', instance.id)"
              >
                删除
              </button>
            </div>
            <div class="info-box">{{ runtime.clients[instance.id]?.message ?? '尚未启动' }}</div>
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
            <template v-if="instance.mode === 'form'"
              ><h3>代理与访问地址</h3>
              <div v-for="rule in instance.proxies" :key="rule.id" class="proxy-card">
                <div class="proxy-title">
                  <strong>{{ rule.name }}</strong
                  ><span class="protocol">{{ rule.type.toUpperCase() }}</span
                  ><span class="muted">{{
                    runtime.clients[instance.id]?.proxies[rule.id] ?? '未启动'
                  }}</span>
                </div>
                <p class="muted">本地 {{ rule.localIP }}:{{ rule.localPort }}</p>
                <div class="address-list">
                  <div v-for="url in addresses(rule, instance)" :key="url" class="address">
                    <code>{{ url }}</code
                    ><button @click="act('clipboard', url, '访问地址已复制。')">复制</button
                    ><button
                      v-if="rule.type === 'http' || rule.type === 'https'"
                      @click="act('link:open', url)"
                    >
                      打开
                    </button>
                  </div>
                </div>
                <small v-if="rule.type === 'tcp'"
                  >如本地服务是 HTTP，可使用 http://{{ address(rule, instance) }} 访问。</small
                >
              </div></template
            >
            <p v-else class="hint">
              高级配置的实际代理以 FRP
              日志为准，界面不会解析未知字段或显示旧表单地址。建议将日志输出设为
              console，以便查看连接状态。
            </p>
            <div class="hint">
              “已注册”表示服务器接受了规则；访问仍取决于本地服务、DNS、证书以及防火墙和云安全组。
            </div>
          </section>
        </div>
      </template>

      <template v-if="page === 'certificates'">
        <div class="section-title">
          <h2>
            本机证书库 <span>{{ state.certificates.length }}</span>
          </h2>
          <div class="inline-fields">
            <button class="secondary" :disabled="busy" @click="startCertificateImport">
              导入手动证书
            </button>
            <button class="primary" :disabled="busy" @click="startCertificateIssue">
              申请 ACME 证书
            </button>
          </div>
        </div>
        <section class="panel">
          <div v-if="!state.certificates.length" class="empty compact">
            <h3>还没有 SSL 证书</h3>
            <p>导入 PEM 证书与私钥，或为多个域名签发一张 SAN 证书。</p>
          </div>
          <div
            v-for="certificate in state.certificates"
            :key="certificate.id"
            class="installed-row"
          >
            <div>
              <strong>{{ certificate.name }}</strong>
              <small
                >{{ certificateName(certificate.provider) }} ·
                {{ certificate.domains.join('、') }}</small
              >
              <small
                >到期时间：{{
                  certificate.expiresAt ? formatTime(certificate.expiresAt) : '未知'
                }}
                · 已关联 {{ certificateUsage(certificate.id) }} 条规则</small
              >
              <small v-if="certificate.pendingRestart" class="warning-text"
                >证书已更新或关联，相关客户端实例需重启后加载。</small
              >
            </div>
            <label v-if="certificate.provider !== 'manual'" class="inline-check">
              <input
                type="checkbox"
                :checked="certificate.autoRenew"
                :disabled="busy || !state.secureStorage"
                @change="
                  act('certificate:auto-renew', {
                    id: certificate.id,
                    enabled: ($event.target as HTMLInputElement).checked,
                  })
                "
                style="font-size: 12px"
              />
              到期前续期
            </label>
            <button
              class="secondary"
              :disabled="busy"
              @click="startCertificateAssociation(certificate.id)"
            >
              关联 HTTPS 规则
            </button>
            <button
              class="danger-link"
              :disabled="busy || certificateUsage(certificate.id) > 0"
              @click="act('certificate:delete', certificate.id)"
            >
              删除
            </button>
          </div>
          <p class="hint">
            私钥保存在本机应用数据目录。ACME
            证书可开启续期检查，且只在应用运行或托盘驻留时检查。DNS-01 续期时需按提示更新 TXT
            记录；更新后需重启关联实例加载新证书。
          </p>
          <p v-if="!state.secureStorage" class="notice warning">
            系统安全存储不可用，ACME 账号密钥不能跨会话保存，因此自动续期暂不可用。
          </p>
        </section>
      </template>

      <template v-if="page === 'sites'">
        <section class="panel">
          <div class="section-heading">
            <div>
              <h2>从 HTTP 规则创建站点</h2>
              <p>站点上游使用服务器配置的 FRP HTTP 入口端口。</p>
            </div>
          </div>
          <div class="form-grid">
            <label
              >来源规则
              <select v-model="siteSelection">
                <option value="">选择一条 HTTP 规则</option>
                <option
                  v-for="item in siteRules"
                  :key="`${item.instance.id}:${item.rule.id}`"
                  :value="`${item.instance.id}:${item.rule.id}`"
                >
                  {{ item.instance.name }} / {{ item.rule.name }} —
                  {{ item.rule.domains.join(', ') }}
                </option>
              </select>
            </label>
            <label
              >可选：Nginx 主配置绝对路径
              <input
                v-model="siteMainConfig"
                placeholder="自动检测失败时填写，如 /etc/nginx/nginx.conf"
              />
            </label>
            <button class="primary" :disabled="busy || !siteSelection" @click="createServerSite">
              创建并应用 Nginx 站点
            </button>
          </div>
        </section>
        <section class="panel">
          <div class="section-heading">
            <div>
              <h2>已管理站点</h2>
              <p>删除只清理本应用创建的 Nginx 站点文件。</p>
            </div>
          </div>
          <div v-if="!state.serverSites.length" class="empty">尚未创建服务器站点。</div>
          <article v-for="site in state.serverSites" :key="site.id" class="record-card">
            <div>
              <strong>{{ site.name }}</strong>
              <p>{{ site.domains.join(' · ') }}</p>
              <small
                >{{ state.servers.find((item) => item.id === site.serverId)?.name }} · 上游
                127.0.0.1:{{ site.upstreamPort }} ·
                {{ site.outOfSync ? '来源规则可能已变化' : 'HTTP' }}</small
              >
            </div>
            <button
              class="danger"
              :disabled="busy"
              @click="act('site:delete', { id: site.id }, '站点已删除。')"
            >
              删除站点
            </button>
          </article>
        </section>
      </template>

      <template v-if="page === 'versions'">
        <div class="section-title">
          <h2>
            已安装版本 <span>{{ state.versions.length }}</span>
          </h2>
          <button class="secondary" @click="modal = 'manual'">手动下载 / 离线导入</button>
        </div>
        <section class="panel">
          <div v-if="!state.versions.length" class="muted">
            还没有安装包。请分别准备本机客户端和服务器对应的 Linux 安装包。
          </div>
          <div v-for="v in state.versions" :key="v.key" class="installed-row">
            <div>
              <strong>{{ versionLabel(v) }}</strong
              ><small>{{ v.source }} · {{ formatTime(v.installedAt) }}</small>
            </div>
            <span class="badge" :class="v.verified ? 'connected' : 'running'">{{
              v.verified ? 'SHA256 已核对' : '尚未核对发布 SHA256'
            }}</span
            ><button
              v-if="!v.verified"
              class="secondary"
              :disabled="busy"
              @click="act('version:verify', v.key, '已与 FRP 官方 SHA256 核对。')"
            >
              核对官方 SHA256
            </button>
            <button class="danger-link" :disabled="busy" @click="act('version:delete', v.key)">
              删除
            </button>
          </div>
        </section>
        <div class="section-title">
          <h2>官方发布版本</h2>
          <div class="inline-fields">
            <select v-model="targetPlatform">
              <option value="darwin">macOS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option></select
            ><select v-model="targetArch">
              <option value="amd64">x64 / amd64</option>
              <option value="arm64" :disabled="targetPlatform === 'windows'">arm64</option></select
            ><button class="primary" :disabled="busy" @click="fetchCatalog()">
              {{ catalog ? '刷新列表' : '获取版本列表' }}
            </button>
          </div>
        </div>
        <div v-if="catalog?.cached" class="notice warning">
          使用缓存 · {{ formatTime(catalog.updatedAt) }}。{{ catalog.warning }}
        </div>
        <div v-if="catalog && !catalog.cached && catalog.warning" class="notice warning">
          {{ catalog.warning }}
        </div>
        <p v-if="catalog && !catalog.cached" class="muted">
          来源：{{
            catalog.source === 'github-web'
              ? 'GitHub 官方发布页面（自动兜底）'
              : 'GitHub Releases API'
          }}
          · 更新于 {{ formatTime(catalog.updatedAt) }}
        </p>
        <section class="panel">
          <div v-if="!catalog" class="empty compact">
            <h3>在线获取，离线也有入口</h3>
            <p>查询失败时使用缓存；首次离线时可指定地址或导入完整安装包。</p>
          </div>
          <div v-for="release in catalog?.releases" :key="release.version" class="release-row">
            <div>
              <strong>FRP {{ release.version }}</strong
              ><small>{{ formatTime(release.publishedAt) }}</small>
            </div>
            <span class="muted">{{
              assetFor(release)?.name ?? release.assetError ?? '此版本无对应平台安装包'
            }}</span
            ><button
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
          <button v-if="catalog?.hasMore" :disabled="busy" @click="fetchCatalog(true)">
            加载更多版本
          </button>
        </section>
      </template>

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
              @click="selectTerminal(tab.id)"
            >
              {{ tab.title
              }}<span @click.stop="closeTerminalTab(tab.id)" aria-label="关闭终端">×</span>
            </button>
          </div>
          <div class="inline-fields">
            <select v-model="selectedServer" aria-label="选择服务器">
              <option value="">选择服务器</option>
              <option v-for="item in state.servers" :key="item.id" :value="item.id">
                {{ item.name }} · {{ item.host }}
              </option>
            </select>
            <button
              class="primary"
              :disabled="!selectedServer"
              @click="openTerminalForServer(selectedServer)"
            >
              ＋ 新终端
            </button>
          </div>
        </div>
        <div v-if="!state.servers.length" class="empty">
          <h3>先添加一台服务器</h3>
          <p>终端使用已保存的 SSH 配置和主机指纹校验。</p>
          <button
            class="primary"
            @click="
              page = 'servers';
              newServer();
            "
          >
            添加服务器
          </button>
        </div>
        <div v-else-if="!terminalTabs.length" class="empty terminal-empty">
          <h3>打开一个 SSH 终端</h3>
          <p>每个标签对应独立的 SSH shell 会话；关闭标签会结束该会话。</p>
          <button
            class="primary"
            :disabled="!selectedServer"
            @click="openTerminalForServer(selectedServer)"
          >
            连接所选服务器
          </button>
        </div>
        <div v-else class="terminal-layout" :class="{ collapsed: terminalPaneCollapsed }">
          <aside class="terminal-shortcuts">
            <div class="shortcut-header">
              <strong>快捷命令</strong>
              <button @click="terminalPaneCollapsed = !terminalPaneCollapsed">
                {{ terminalPaneCollapsed ? '展开' : '收起' }}
              </button>
            </div>
            <template v-if="!terminalPaneCollapsed">
              <div class="shortcut-section">
                <button
                  class="shortcut-heading"
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
                    <button class="shortcut-command" @click="runTerminalCommand(favorite.command)">
                      {{ favorite.name }}
                    </button>
                    <div class="shortcut-actions">
                      <button
                        :disabled="index === 0"
                        title="上移"
                        @click="moveTerminalFavorite(favorite.id, -1)"
                      >
                        ↑
                      </button>
                      <button
                        :disabled="index === state.terminalFavorites.length - 1"
                        title="下移"
                        @click="moveTerminalFavorite(favorite.id, 1)"
                      >
                        ↓
                      </button>
                      <button title="重命名或编辑" @click="editTerminalFavorite(favorite)">
                        ✎
                      </button>
                      <button title="删除" @click="removeTerminalFavorite(favorite.id)">×</button>
                    </div>
                  </div>
                  <button class="add-favorite" @click="addTerminalFavorite('')">
                    ＋ 添加常用命令
                  </button>
                </div>
              </div>
              <div class="shortcut-section history-section">
                <button
                  class="shortcut-heading"
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
            @click="
              runTerminalCommand(terminalContextMenu.command);
              terminalContextMenu = undefined;
            "
          >
            在当前终端执行
          </button>
          <button
            v-if="!terminalContextMenu.favoriteId"
            @click="addTerminalFavorite(terminalContextMenu.command)"
          >
            添加到常用
          </button>
          <template v-else>
            <button
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
              class="danger-link"
              @click="
                removeTerminalFavorite(terminalContextMenu.favoriteId!);
                terminalContextMenu = undefined;
              "
            >
              删除
            </button>
          </template>
        </div>
        <p v-if="terminalTabs.length" class="terminal-history-hint">
          记录读取服务器登录用户的 shell history 文件；多数 shell
          会在退出时写入新命令，因此刚执行的命令可能暂时不显示。
        </p>
      </section>

      <template v-if="page === 'settings'">
        <section class="panel narrow">
          <h2>下载网络</h2>
          <p class="muted">仅影响版本查询与安装包下载，不修改系统代理或 SSH 连接。</p>
          <label
            >代理地址<input
              v-model="proxyUrl"
              placeholder="http://127.0.0.1:7890 或 socks5://127.0.0.1:1080"
          /></label>
          <p class="hint">留空为直连。支持无内嵌账号密码的 HTTP、HTTPS、SOCKS5 代理。</p>
          <button
            class="primary"
            :disabled="busy"
            @click="act('settings:save', { proxyUrl }, '网络设置已保存。')"
          >
            保存设置
          </button>
        </section>
        <section class="panel narrow">
          <h2>部署与平台帮助</h2>
          <details open>
            <summary>访问失败怎么排查？</summary>
            <p>
              先检查本地网站或服务可用，再检查 FRP
              是否登录成功、代理是否注册；随后确认服务器防火墙及云安全组放行 7000
              和实际入口端口。域名需解析到公网服务器，HTTPS 证书应匹配域名。
            </p>
          </details>
          <details>
            <summary>服务器信息与自动部署</summary>
            <p>
              SSH 连接后自动读取系统版本、内核、CPU、内存和家目录磁盘信息。应用按实际运行的
              systemd、OpenRC 或 SysV
              以及当前权限选择服务管理方式；条件不满足时使用后台进程。应用不会索取或保存交互 sudo
              密码。
            </p>
          </details>
          <details>
            <summary>Windows 风险提示与误报</summary>
            <p>
              优先从官方 Release 下载并核对 SHA256。SmartScreen
              提示与杀毒误报应分别处理，先核对文件来源、数字签名与安全产品检测结果；确定误报后通过安全产品的单文件恢复或误报申诉入口处理。本工具不会关闭安全防护或自动添加白名单。未签名开发包可能出现发行者提示。
            </p>
          </details>
          <details>
            <summary>macOS 与 Linux</summary>
            <p>
              macOS 发布需要开发者签名及公证，以减少 Gatekeeper 提示并保持钥匙串身份稳定。Linux
              需要图形桌面、托盘支持及可用密钥环；无安全存储时凭据只在会话中保留。
            </p>
          </details>
          <details>
            <summary>旧版本与高级配置</summary>
            <p>
              v0.52.0
              之前的版本只提供原始配置入口，兼容性未全面验证。进入高级模式后不会将未知字段反向转换为表单。切换版本不自动转换配置，启动时使用选定版本校验。
            </p>
          </details>
          <details>
            <summary>卸载服务器</summary>
            <p>
              有部署记录时确认框默认选择同时停止并卸载远端服务及其指定程序、配置、日志和 PID
              文件，历史备份保留；也可只移除本机配置，让远端服务继续运行。有关联客户端实例时需先解除关联。
            </p>
          </details>
        </section>
      </template>
    </main>

    <div v-if="modal" class="overlay" @click.self="!busy && (modal = '')">
      <section
        class="modal"
        :class="{
          wide:
            modal === 'instance' ||
            modal === 'logs' ||
            modal === 'certificate-associate' ||
            modal === 'certificate-progress',
        }"
      >
        <div class="modal-heading">
          <h2>{{ modalTitles[modal] }}</h2>
          <button :disabled="busy" @click="modal = ''">×</button>
        </div>
        <div v-if="error" class="notice error">{{ error }}</div>
        <form v-if="modal === 'terminal-favorite'" @submit.prevent="saveTerminalFavorite">
          <label
            >显示名称<input
              v-model="terminalFavoriteDraft.name"
              required
              maxlength="100"
              placeholder="例如：查看磁盘空间"
          /></label>
          <label
            >命令<textarea
              v-model="terminalFavoriteDraft.command"
              required
              maxlength="8192"
              rows="5"
              placeholder="df -h"
            />
          </label>
          <p class="hint">命令会发送到当前选中的服务器终端执行，请确认内容安全后再运行。</p>
          <div class="modal-actions">
            <button type="button" @click="modal = ''">取消</button
            ><button class="primary" type="submit">保存</button>
          </div>
        </form>
        <section
          v-if="modal === 'certificate-progress' && certificateProgress"
          class="issue-progress"
        >
          <div class="issue-current" :class="`issue-${certificateProgress.status}`">
            <div
              class="issue-spinner"
              v-if="['running', 'retrying', 'cancelling'].includes(certificateProgress.status)"
            ></div>
            <div>
              <strong>{{ certificateProgress.step }}</strong>
              <p>{{ certificateProgress.message }}</p>
            </div>
          </div>
          <div v-if="certificateProgress.dnsRecords?.length" class="dns-record-list">
            <p>请在 DNS 服务商处添加以下 TXT 记录：</p>
            <div
              v-for="record in certificateProgress.dnsRecords"
              :key="`${record.record}:${record.value}`"
              class="dns-record"
            >
              <small>域名：{{ record.domain }}</small>
              <code>{{ record.record }}</code>
              <div class="inline-fields">
                <code>{{ record.value }}</code>
                <button type="button" @click="copyDnsRecord(record.value)">复制 TXT 值</button>
              </div>
            </div>
            <button
              class="primary"
              :disabled="certificateProgress.status !== 'waiting-user'"
              @click="continueDnsChallenge"
            >
              已添加，继续验证
            </button>
          </div>
          <div class="issue-timeline">
            <h3>处理过程</h3>
            <ol>
              <li
                v-for="(item, index) in certificateProgressHistory"
                :key="`${item.updatedAt}-${index}`"
              >
                <strong>{{ item.step }}</strong>
                <small>{{ item.message }}</small>
              </li>
            </ol>
          </div>
          <p class="hint" v-if="certificateProgress.status === 'cancelling'">
            正在取消。若 CA 请求已经发出，可能要等当前网络操作返回；HTTP-01
            临时实例会在退出流程中清理并恢复。
          </p>
          <div class="modal-actions">
            <button
              v-if="['running', 'retrying', 'waiting-user'].includes(certificateProgress.status)"
              type="button"
              class="danger-link"
              @click="cancelCertificateIssue"
            >
              取消签发
            </button>
            <button
              v-else
              type="button"
              class="primary"
              @click="
                modal = '';
                activeCertificateTask = '';
              "
            >
              关闭
            </button>
          </div>
        </section>
        <form v-if="modal === 'server' && serverDraft" @submit.prevent="saveServer">
          <div class="form-grid">
            <label
              >名称<input
                v-model="serverDraft.name"
                required
                placeholder="例如：演示服务器" /></label
            ><label
              >SSH 管理地址<input
                v-model="serverDraft.host"
                required
                placeholder="IP 或主机名" /></label
            ><label
              >SSH 端口<input
                v-model.number="serverDraft.sshPort"
                type="number"
                min="1"
                max="65535"
                required /></label
            ><label>用户名<input v-model="serverDraft.username" required /></label
            ><label
              >认证方式<select v-model="serverDraft.auth">
                <option value="key">私钥</option>
                <option value="password">密码</option>
              </select></label
            ><label v-if="serverDraft.auth === 'password'"
              >SSH 密码<input
                v-model="serverDraft.password"
                type="password"
                placeholder="留空保留已存密码"
                autocomplete="new-password" /></label
            ><template v-else
              ><label class="full"
                >私钥路径
                <div class="inline-fields">
                  <input
                    v-model="serverDraft.keyPath"
                    placeholder="支持直接输入绝对路径"
                    required
                  /><button
                    type="button"
                    class="btn-md"
                    @click="choose('key', (p) => (serverDraft!.keyPath = p))"
                  >
                    选择文件
                  </button>
                </div></label
              ><label class="full"
                >密钥口令<input
                  v-model="serverDraft.passphrase"
                  type="password"
                  placeholder="密钥无口令可留空；编辑时留空保留"
                  autocomplete="new-password" /></label></template
            ><label
              >FRP 公网地址<input
                v-model="serverDraft.publicHost"
                placeholder="留空使用 SSH 地址" /></label
            ><label
              >FRP 绑定端口<input
                v-model.number="serverDraft.frpPort"
                type="number"
                min="1"
                max="65535"
                required /></label
            ><label
              >HTTP 入口端口<input
                v-model.number="serverDraft.httpPort"
                type="number"
                min="1"
                max="65535"
                required /></label
            ><label
              >HTTPS 入口端口<input
                v-model.number="serverDraft.httpsPort"
                type="number"
                min="1"
                max="65535"
                required /></label
            ><label class="full"
              >客户端连接认证令牌
              <div class="inline-fields">
                <input
                  v-model="serverDraft.token"
                  type="password"
                  placeholder="新服务器需要填写；编辑时留空保留"
                  autocomplete="new-password"
                /><button type="button" class="btn-md" @click="generateToken">生成随机令牌</button>
              </div></label
            >
            <label class="full">
              服务端配置模式
              <select v-model="serverDraft.configMode">
                <option value="form">常用表单</option>
                <option value="raw">高级原始配置</option>
              </select>
            </label>
            <template v-if="serverDraft.configMode === 'raw'">
              <div class="full notice warning">
                原始配置是唯一配置来源。切回表单将忽略原始内容，请确认没有需保留的高级字段。连接参数与令牌必须自行保持一致。
              </div>
              <label class="full">
                配置格式
                <div class="inline-fields">
                  <select v-model="serverDraft.rawFormat">
                    <option v-for="f in ['toml', 'ini', 'yaml', 'json']" :key="f">{{ f }}</option>
                  </select>
                  <button type="button" class="btn-md" @click="importConfig('server')">
                    导入配置文件
                  </button>
                </div>
              </label>

              <textarea
                v-model="serverDraft.rawConfig"
                class="full code-editor"
                rows="12"
                placeholder="完整 frps 配置"
              ></textarea>
            </template>
          </div>
          <div class="modal-actions">
            <button type="button" :disabled="busy" @click="modal = ''">取消</button
            ><button class="primary" :disabled="busy">保存配置</button>
          </div>
        </form>
        <form v-if="modal === 'instance' && instanceDraft" @submit.prevent="saveInstance">
          <div class="form-grid">
            <label>实例名称<input v-model="instanceDraft.name" required /></label
            ><label
              >服务器<select v-model="instanceDraft.serverId" required>
                <option v-for="s in state.servers" :key="s.id" :value="s.id">{{ s.name }}</option>
              </select></label
            ><label class="full"
              >本机 FRP 版本<select v-model="instanceDraft.versionKey" required>
                <option value="">请先在版本库安装本机版本</option>
                <option v-for="v in localVersions" :key="v.key" :value="v.key">
                  {{ versionLabel(v) }}
                </option>
              </select></label
            >
          </div>
          <template v-if="instanceDraft.mode === 'form'"
            ><div class="section-title">
              <h3>代理规则</h3>
              <button type="button" @click="addProxy">＋ 添加规则</button>
            </div>
            <div v-for="(rule, index) in instanceDraft.proxies" :key="rule.id" class="rule-editor">
              <div class="form-grid">
                <label>规则名称<input v-model="rule.name" required /></label
                ><label
                  >类型<select v-model="rule.type">
                    <option value="tcp">TCP（含 IP 端口访问网站）</option>
                    <option value="udp">UDP</option>
                    <option value="http">HTTP 域名</option>
                    <option value="https">HTTPS 域名</option>
                  </select></label
                ><label>本地地址<input v-model="rule.localIP" required /></label
                ><label
                  >本地端口<input
                    v-model.number="rule.localPort"
                    type="number"
                    min="1"
                    max="65535"
                    required /></label
                ><label v-if="rule.type === 'tcp' || rule.type === 'udp'"
                  >公网端口<input
                    v-model.number="rule.remotePort"
                    type="number"
                    min="1"
                    max="65535"
                    required
                /></label>
                <label v-else>
                  公网域名（每行一个，也可用逗号分隔）
                  <textarea
                    :value="ruleDomainsText(rule)"
                    required
                    rows="2"
                    placeholder="demo.example.com&#10;www.demo.example.com"
                    @input="setRuleDomains(rule, $event)"
                  />
                </label>
                <template v-if="rule.type === 'https'"
                  ><label
                    >HTTPS 方式<select v-model="rule.tlsMode">
                      <option value="passthrough">转发本地 HTTPS</option>
                      <option value="terminate">证书终止后访问本地 HTTP</option>
                    </select></label
                  ><template v-if="rule.tlsMode === 'terminate'"
                    ><label class="full"
                      >SSL 证书<select
                        :value="rule.certificateId ?? ''"
                        @change="setRuleCertificate(rule, $event)"
                      >
                        <option value="">请选择证书库中的证书</option>
                        <option
                          v-for="certificate in state.certificates.filter((item) =>
                            rule.domains.every((domain) => item.domains.includes(domain)),
                          )"
                          :key="certificate.id"
                          :value="certificate.id"
                        >
                          {{ certificate.name }} · {{ certificate.provider }}
                        </option>
                      </select></label
                    >
                    <p class="hint full">
                      证书终止后由 frpc 读取本机证书；请在“SSL 证书”页导入或签发，并关联到此规则。
                    </p></template
                  ></template
                >
              </div>
              <button
                type="button"
                class="danger-link"
                @click="instanceDraft.proxies.splice(index, 1)"
              >
                移除规则
              </button>
            </div>
            <div class="actions-row">
              <button type="button" @click="enterRaw">生成完整配置并进入高级模式</button>
              <button type="button" @click="instanceDraft.mode = 'raw'">直接编写高级配置</button>
            </div></template
          ><template v-else
            ><div class="notice warning">
              高级配置为唯一来源，表单数据不会覆盖它。服务器和版本选择用于管理；实际连接地址由原始配置决定。
            </div>
            <div class="inline-fields">
              <select v-model="instanceDraft.rawFormat">
                <option v-for="f in ['toml', 'ini', 'yaml', 'json']" :key="f">
                  {{ f }}
                </option></select
              ><button type="button" @click="importConfig('instance')">导入配置文件</button
              ><button type="button" @click="restoreForm">
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
          <div class="modal-actions">
            <button type="button" :disabled="busy" @click="modal = ''">取消</button>
            <button class="primary" :disabled="busy">保存实例</button>
          </div>
        </form>
        <form v-if="modal === 'manual'" @submit.prevent="installManual">
          <div class="form-grid">
            <label
              >FRP 版本<input v-model="manual.version" required placeholder="例如 0.71.0" /></label
            ><label
              >系统<select v-model="targetPlatform">
                <option value="darwin">macOS</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
              </select></label
            ><label
              >架构<select v-model="targetArch">
                <option value="amd64">x64 / amd64</option>
                <option value="arm64">arm64</option>
              </select></label
            ><label class="full"
              >下载地址<input
                v-model="manual.url"
                placeholder="官方安装包 URL，与本地文件二选一" /></label
            ><label class="full"
              >本地完整安装包
              <div class="inline-fields">
                <input
                  v-model="manual.localPath"
                  placeholder="ZIP 或 tar.gz 路径；填写后优先使用本地文件"
                /><button type="button" @click="choose('archive', (p) => (manual.localPath = p))">
                  选择文件
                </button>
              </div></label
            ><label class="full"
              >发布方 SHA256（可选）<input
                v-model="manual.digest"
                placeholder="64 位十六进制校验值"
            /></label>
          </div>
          <p class="hint">
            本机包会执行版本检测；Linux 服务器包会在部署时检查实际版本。无发布校验值时需确认来源。
          </p>
          <div class="modal-actions">
            <button type="button" :disabled="busy" @click="modal = ''">关闭</button
            ><button class="primary" :disabled="busy">安装所选版本</button>
          </div>
        </form>
        <form v-if="modal === 'certificate-import'" @submit.prevent="submitCertificateImport">
          <div class="form-grid">
            <label
              >证书名称<input v-model="certificateDraft.name" placeholder="例如：主站证书"
            /></label>
            <label class="full"
              >域名（每行一个，也可用逗号分隔）<textarea
                v-model="certificateDraft.domainsText"
                rows="3"
                required
                placeholder="demo.example.com&#10;www.demo.example.com"
              />
            </label>
            <label class="full"
              >证书 PEM 文件
              <div class="inline-fields">
                <input v-model="certificateDraft.certificatePath" required /><button
                  type="button"
                  @click="choose('certificate', (p) => (certificateDraft.certificatePath = p))"
                >
                  选择证书
                </button>
              </div>
            </label>
            <label class="full"
              >私钥 PEM 文件
              <div class="inline-fields">
                <input v-model="certificateDraft.privateKeyPath" required /><button
                  type="button"
                  @click="choose('key', (p) => (certificateDraft.privateKeyPath = p))"
                >
                  选择私钥
                </button>
              </div>
            </label>
          </div>
          <p class="hint">
            导入时会验证 PEM、证书有效期、私钥匹配关系及每个域名的 SAN
            覆盖，再复制到本机受限权限的证书库。
          </p>
          <div class="modal-actions">
            <button type="button" :disabled="busy" @click="modal = ''">取消</button
            ><button class="primary" :disabled="busy">验证并导入</button>
          </div>
        </form>
        <form v-if="modal === 'certificate-issue'" @submit.prevent="submitCertificateIssue">
          <div class="form-grid">
            <label
              >证书名称<input v-model="certificateDraft.name" placeholder="例如：主站 SAN 证书"
            /></label>
            <label
              >签发机构<select v-model="certificateDraft.provider">
                <option value="letsencrypt">Let’s Encrypt</option>
                <option value="litessl">LiteSSL</option>
              </select></label
            >
            <label class="full"
              >域名（批量签发为一张 SAN 证书，每行一个）<textarea
                v-model="certificateDraft.domainsText"
                rows="3"
                required
                placeholder="demo.example.com&#10;www.demo.example.com"
              />
            </label>
            <label class="full"
              >联系邮箱<input v-model="certificateDraft.email" type="email" required
            /></label>
            <label
              >验证方式<select v-model="certificateDraft.challenge">
                <option value="dns-01">手动 DNS-01（添加 TXT）</option>
                <option value="http-01">HTTP-01（通过 FRP 公网 80 验证）</option>
              </select></label
            >
            <template v-if="certificateDraft.provider === 'litessl'">
              <label
                >LiteSSL EAB KID<input v-model="certificateDraft.eabKid" autocomplete="off"
              /></label>
              <label class="full"
                >LiteSSL EAB HMAC 密钥<input
                  v-model="certificateDraft.eabHmac"
                  type="password"
                  autocomplete="new-password"
              /></label>
            </template>
          </div>
          <p class="hint">
            DNS-01 会逐项显示需要添加的 TXT 记录，验证完成后可移除记录。HTTP-01 仅适用于域名已指向
            FRP 服务器且其 HTTP 入口为公网 80 的表单实例；验证时需确认临时重启。
          </p>
          <label class="check-row">
            <input v-model="certificateDraft.termsAgreed" type="checkbox" required />
            <span>我已阅读并同意所选证书机构的服务条款</span>
          </label>
          <div class="modal-actions">
            <button type="button" :disabled="busy" @click="modal = ''">取消</button
            ><button class="primary" :disabled="busy">开始签发</button>
          </div>
        </form>
        <form
          v-if="modal === 'certificate-associate'"
          @submit.prevent="submitCertificateAssociation"
        >
          <p class="hint">
            只列出证书 SAN 覆盖全部域名的 HTTPS 证书终止规则。修改配置不会自动重启实例。
          </p>
          <div v-if="!certificateTargets.length" class="empty compact">
            <p>没有可关联的规则。请先创建 HTTPS 规则并选择“证书终止后访问本地 HTTP”。</p>
          </div>
          <label
            v-for="{ instance: item, rule } in certificateRules.filter(({ rule }) =>
              certificateCoversRule(certificateToAssociate, rule),
            )"
            :key="`${item.id}::${rule.id}`"
            class="check-row"
          >
            <input type="checkbox" :value="`${item.id}::${rule.id}`" v-model="certificateTargets" />
            <span>{{ item.name }} · {{ rule.name }} · {{ rule.domains.join('、') }}</span>
          </label>
          <div class="modal-actions">
            <button type="button" :disabled="busy" @click="modal = ''">取消</button
            ><button class="primary" :disabled="busy || !certificateTargets.length">
              关联所选规则
            </button>
          </div>
        </form>
        <template v-if="modal === 'backups'"
          ><p class="hint">先停止服务再恢复。程序与配置分别备份和校验，恢复后需明确启动。</p>
          <p v-if="!backups.length" class="muted">暂无备份。</p>
          <div v-for="backup in backups" :key="backup.path" class="installed-row">
            <div>
              <strong>{{ backup.kind === 'binary' ? '程序备份' : '配置备份' }}</strong
              ><small
                >{{ backup.path }} · {{ formatTime(new Date(backup.time).toISOString()) }}</small
              >
            </div>
            <button
              :disabled="busy"
              @click="act('server:restore', { id: selectedServer, path: backup.path })"
            >
              恢复
            </button>
          </div></template
        >
        <template v-if="modal === 'logs'">
          <pre class="log-view">{{ logText || '暂无日志。' }}</pre>
          <div class="modal-actions">
            <button class="danger-link" @click="clearLogs">清理日志</button>
            <button @click="act('clipboard', logText, '日志已复制。')">复制脱敏日志</button
            ><button @click="modal = ''">关闭</button>
          </div></template
        >
      </section>
    </div>
  </div>
</template>
