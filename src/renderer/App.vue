<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue';
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
  InstallRequest,
  ReverseProxy,
} from '../shared/types';
import logoUrl from '../../assets/brand/logo.svg';
import { accessAddress } from '../shared/address';

const api = window.desktop;
const state = ref<State>({
  servers: [],
  instances: [],
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
}>({ clients: {}, ssh: {}, services: {} });
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
const deployMode = ref('auto');
const backups = ref<Array<{ kind: 'binary' | 'config'; path: string; time: number }>>([]);
const proxyUrl = ref('');
const showGuide = ref(true);
const abandonRaw = ref(false);
const manual = reactive({ version: '', url: '', localPath: '', digest: '' });
const adoption = reactive<Deployment>({
  binary: '',
  config: '',
  log: '',
  pidFile: '',
  mode: 'process',
  service: 'frps.service',
  managed: false,
  version: '',
  versionKey: '',
});
const reverseProxyDraft = reactive({
  domain: '',
  provider: 'manual' as ReverseProxy['provider'],
  email: '',
  httpPort: 8080,
  httpsPort: 8443,
  certLocalPath: '',
  keyLocalPath: '',
  eabKid: '',
  eabHmac: '',
});
let timer: ReturnType<typeof setInterval>;
let unsubscribe: () => void;
const uid = () => crypto.randomUUID();
const server = computed(() => state.value.servers.find((s) => s.id === selectedServer.value));
const instance = computed(() => state.value.instances.find((s) => s.id === selectedInstance.value));
watch(
  selectedServer,
  (id) => {
    const selected = state.value.servers.find((value) => value.id === id);
    if (selected) {
      reverseProxyDraft.httpPort = selected.httpPort;
      reverseProxyDraft.httpsPort = selected.httpsPort;
    }
  },
  { immediate: true },
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
const navIcons: Record<string, string> = {
  servers: '▤',
  clients: '⇄',
  versions: '▦',
  settings: '⚙',
};
const modalTitles: Record<string, string> = {
  server: '服务器配置',
  instance: '客户端实例配置',
  manual: '手动安装与离线导入',
  adopt: '接管已有部署',
  logs: '运行日志',
  backups: '部署备份',
};
const titles: Record<string, string> = {
  servers: '服务器',
  clients: '客户端实例',
  versions: '版本库',
  settings: '设置与帮助',
};
const descriptions: Record<string, string> = {
  servers: '连接你的 Linux 服务器，部署或接管 FRP 服务。',
  clients: '将本机服务分享出去，多套配置可以同时运行。',
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
    reverseProxies: [],
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
    domain: '',
    tlsMode: 'passthrough',
    certPath: '',
    keyPath: '',
  });
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
async function addReverseProxy() {
  if (!server.value) return;
  const payload = {
    serverId: server.value.id,
    siteId: uid(),
    domain: reverseProxyDraft.domain.trim().replace(/\.$/, '').toLowerCase(),
    provider: reverseProxyDraft.provider,
    email: reverseProxyDraft.email || undefined,
    httpPort: reverseProxyDraft.httpPort,
    httpsPort: reverseProxyDraft.httpsPort,
    certLocalPath: reverseProxyDraft.certLocalPath.trim() || undefined,
    keyLocalPath: reverseProxyDraft.keyLocalPath.trim() || undefined,
    eabKid: reverseProxyDraft.eabKid.trim() || undefined,
    eabHmac: reverseProxyDraft.eabHmac.trim() || undefined,
  };
  const result = await act('server:reverse-proxy:add', payload);
  if (result) {
    reverseProxyDraft.domain = '';
    reverseProxyDraft.email = '';
    reverseProxyDraft.certLocalPath = '';
    reverseProxyDraft.keyLocalPath = '';
    reverseProxyDraft.eabKid = '';
    reverseProxyDraft.eabHmac = '';
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
function address(rule: ProxyRule, i: Instance) {
  const s = instanceServer(i);
  return s ? accessAddress(rule, s) : '';
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
});
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
          @click="page = key"
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
          <p>支持 SSH 密码或密钥登录，可安装新服务，也能接管已有 FRP。</p>
          <button class="primary" @click="newServer">添加第一台服务器</button>
        </div>
        <div v-else class="split">
          <div class="item-list">
            <button
              v-for="s in state.servers"
              :key="s.id"
              class="item"
              :class="{ selected: selectedServer === s.id }"
              @click="
                selectedServer = s.id;
                hostInfo = undefined;
                versionChoice = '';
              "
            >
              <strong>{{ s.name }}</strong
              ><small>{{ s.publicHost }}:{{ s.frpPort }}</small
              ><span class="badge" :class="runtime.ssh[s.id]"
                >SSH {{ statusLabel(runtime.ssh[s.id] ?? 'disconnected') }}</span
              ><small>{{
                s.deployment
                  ? `FRP ${s.deployment.version} · ${s.deployment.mode}`
                  : '尚未部署或接管'
              }}</small>
            </button>
          </div>
          <section v-if="server" class="panel">
            <div class="panel-heading">
              <div>
                <h2>{{ server.name }}</h2>
                <p>{{ server.username }}@{{ server.host }}:{{ server.sshPort }}</p>
              </div>
              <button class="secondary" :disabled="busy" @click="editServer">编辑配置</button>
            </div>
            <div class="actions">
              <button
                class="primary"
                :disabled="busy || runtime.ssh[server.id] === 'connected'"
                @click="act('server:connect', server.id, 'SSH 已连接。')"
              >
                连接 SSH</button
              ><button
                :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                @click="act('server:disconnect', server.id, 'SSH 已断开，远程服务继续运行。')"
              >
                断开</button
              ><button
                :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                @click="detectServer"
              >
                检测环境</button
              ><button
                class="danger-link"
                :disabled="busy"
                @click="act('server:delete', server.id)"
              >
                移除配置
              </button>
            </div>
            <div v-if="hostInfo" class="info-box">
              <strong>Linux / {{ hostInfo.arch }}</strong>
              <p>
                安装用户：{{ hostInfo.root ? 'root' : '普通用户' }} · systemd：{{
                  hostInfo.systemd ? '可用' : '不可用'
                }}
                · 用户服务：{{ hostInfo.userSystemd ? '可用' : '不可用' }} · sudo：{{
                  hostInfo.sudo ? '免交互可用' : '不可用'
                }}
              </p>
              <details>
                <summary>查看端口占用</summary>
                <pre>{{ hostInfo.ports }}</pre>
              </details>
            </div>
            <hr />
            <h3>服务端部署</h3>
            <template v-if="!server.deployment"
              ><p class="muted">先在版本库安装 Linux 包，再选择部署。已有服务可指定路径接管。</p>
              <div class="inline-fields">
                <select v-model="versionChoice">
                  <option value="">选择 Linux 安装包</option>
                  <option v-for="v in linuxVersions" :key="v.key" :value="v.key">
                    {{ versionLabel(v) }}
                  </option></select
                ><select v-model="deployMode">
                  <option value="auto">自动选择运行方式</option>
                  <option value="system">系统 systemd</option>
                  <option value="user">用户 systemd</option>
                  <option value="process">普通后台进程</option></select
                ><button
                  class="primary"
                  :disabled="busy || !versionChoice || runtime.ssh[server.id] !== 'connected'"
                  @click="
                    act('server:deploy', { id: server.id, key: versionChoice, mode: deployMode })
                  "
                >
                  安装服务端
                </button>
              </div>
              <button
                class="secondary"
                :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                @click="modal = 'adopt'"
              >
                接管已有部署
              </button></template
            >
            <template v-else
              ><div class="deployment-meta">
                <span class="badge connected">FRP {{ server.deployment.version }}</span
                ><span
                  class="badge"
                  :class="
                    ['active', 'running'].includes(runtime.services?.[server.id]) ? 'connected' : ''
                  "
                  >服务 {{ serviceLabel(server.id) }}</span
                ><span
                  >{{
                    server.deployment.mode === 'process'
                      ? '后台进程'
                      : `${server.deployment.mode} systemd`
                  }}
                  · {{ server.deployment.managed ? '工具安装' : '接管部署' }}</span
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
                  v-if="server.deployment.mode !== 'process'"
                  :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                  @click="act('server:control', { id: server.id, action: 'enable' })"
                >
                  开启开机启动</button
                ><button
                  v-if="server.deployment.mode !== 'process'"
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
              <div class="actions">
                <button
                  class="danger-link"
                  :disabled="busy"
                  @click="act('server:detach', server.id)"
                >
                  解除管理</button
                ><button
                  class="danger-link"
                  :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                  @click="act('server:uninstall', { id: server.id, deleteAdopted: false })"
                >
                  {{ server.deployment.managed ? '卸载服务' : '解除管理并保留文件' }}</button
                ><button
                  v-if="!server.deployment.managed"
                  class="danger-link"
                  :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                  @click="act('server:uninstall', { id: server.id, deleteAdopted: true })"
                >
                  停止并删除接管文件
                </button>
              </div></template
            >
            <template v-if="server.deployment">
              <hr />
              <h3>Nginx 域名反向代理与 SSL</h3>
              <p class="muted">
                由 Nginx 接收公网 80/443，再分别代理到 FRP 的 HTTP/HTTPS 入口。HTTPS 在 Nginx
                终止后通过 HTTPS 转发到 FRP 8443；请确保客户端 HTTPS 规则域名与此处一致。
              </p>
              <div v-if="server.reverseProxies.length" class="item-list compact-list">
                <div v-for="site in server.reverseProxies" :key="site.id" class="item">
                  <strong>{{ site.domain }}</strong>
                  <small>
                    HTTP :80 → 127.0.0.1:{{ site.httpPort }} · HTTPS :443 → 127.0.0.1:{{
                      site.httpsPort
                    }}
                  </small>
                  <small>
                    {{
                      site.provider === 'manual'
                        ? '手动证书'
                        : site.provider === 'litessl'
                          ? 'LiteSSL 自动续期'
                          : 'Let’s Encrypt 自动续期'
                    }}
                  </small>
                  <button
                    class="danger-link"
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                    @click="act('server:reverse-proxy:remove', { id: server.id, siteId: site.id })"
                  >
                    移除 Nginx 站点
                  </button>
                </div>
              </div>
              <form class="form-grid" @submit.prevent="addReverseProxy">
                <label
                  >域名<input
                    v-model="reverseProxyDraft.domain"
                    required
                    placeholder="demo.example.com"
                /></label>
                <label
                  >证书来源<select v-model="reverseProxyDraft.provider">
                    <option value="manual">手动证书</option>
                    <option value="letsencrypt">Let’s Encrypt 自动申请</option>
                    <option value="litessl">LiteSSL 自动申请</option>
                  </select></label
                >
                <label
                  >FRP HTTP 入口端口<input
                    v-model.number="reverseProxyDraft.httpPort"
                    type="number"
                    min="1"
                    max="65535"
                    required
                /></label>
                <label
                  >FRP HTTPS 入口端口<input
                    v-model.number="reverseProxyDraft.httpsPort"
                    type="number"
                    min="1"
                    max="65535"
                    required
                /></label>
                <template v-if="reverseProxyDraft.provider === 'manual'">
                  <label class="full"
                    >本机证书链文件
                    <div class="inline-fields">
                      <input
                        v-model="reverseProxyDraft.certLocalPath"
                        required
                        placeholder="选择 PEM 格式证书链"
                      />
                      <button
                        type="button"
                        @click="choose('certificate', (p) => (reverseProxyDraft.certLocalPath = p))"
                      >
                        选择文件
                      </button>
                    </div></label
                  >
                  <label class="full"
                    >本机未加密私钥文件
                    <div class="inline-fields">
                      <input
                        v-model="reverseProxyDraft.keyLocalPath"
                        required
                        placeholder="选择 PEM 格式私钥"
                      />
                      <button
                        type="button"
                        @click="choose('key', (p) => (reverseProxyDraft.keyLocalPath = p))"
                      >
                        选择文件
                      </button>
                    </div></label
                  >
                </template>
                <template v-else>
                  <label
                    >证书通知邮箱<input v-model="reverseProxyDraft.email" type="email" required
                  /></label>
                  <template v-if="reverseProxyDraft.provider === 'litessl'">
                    <label
                      >LiteSSL EAB KID<input
                        v-model="reverseProxyDraft.eabKid"
                        required
                        autocomplete="off"
                    /></label>
                    <label class="full"
                      >LiteSSL EAB HMAC 密钥<input
                        v-model="reverseProxyDraft.eabHmac"
                        type="password"
                        required
                        autocomplete="new-password"
                    /></label>
                  </template>
                </template>
                <div class="full hint">
                  自动签发要求域名已解析到此服务器、外网可访问 80 端口，并且服务器有 curl 或
                  wget。LiteSSL 还需在其 ACME 账户中创建 EAB 凭据。删除站点会保留证书和续期任务。
                </div>
                <div class="full actions">
                  <button
                    class="primary"
                    :disabled="busy || runtime.ssh[server.id] !== 'connected'"
                  >
                    添加并配置 Nginx
                  </button>
                </div>
              </form>
            </template>
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
                <div class="address">
                  <code>{{ address(rule, instance) }}</code
                  ><button @click="act('clipboard', address(rule, instance), '访问地址已复制。')">
                    复制</button
                  ><button
                    v-if="rule.type === 'http' || rule.type === 'https'"
                    @click="act('link:open', address(rule, instance))"
                  >
                    打开
                  </button>
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
            <summary>普通用户部署与 sudo</summary>
            <p>
              默认程序放在登录用户的 ~/.local/share/intranet-frp。具备免交互 sudo 或 root
              权限时管理系统服务；否则使用用户 systemd 或后台进程。sudo
              不可用时不会索取或保存提权密码。后台进程不提供开机启动，用户服务注销后的运行取决于
              linger。
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
            <summary>临时配置与备份</summary>
            <p>
              本机运行中的 FRP
              需要读取配置文件，文件使用当前用户权限，停止或退出时清理。服务端配置同样限制权限。服务端配置及版本替换会保留带时间戳的备份；在停止服务后，可通过
              SSH 将备份复制回原路径再启动。删除配置与卸载远程服务是不同操作。
            </p>
          </details>
        </section>
      </template>
    </main>

    <div v-if="modal" class="overlay" @click.self="!busy && (modal = '')">
      <section class="modal" :class="{ wide: modal === 'instance' || modal === 'logs' }">
        <div class="modal-heading">
          <h2>{{ modalTitles[modal] }}</h2>
          <button :disabled="busy" @click="modal = ''">×</button>
        </div>
        <div v-if="error" class="notice error">{{ error }}</div>
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
                  /><button type="button" @click="choose('key', (p) => (serverDraft!.keyPath = p))">
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
                /><button type="button" @click="generateToken">生成随机令牌</button>
              </div></label
            ><label class="full"
              >服务端配置模式<select v-model="serverDraft.configMode">
                <option value="form">常用表单</option>
                <option value="raw">高级原始配置</option>
              </select></label
            ><template v-if="serverDraft.configMode === 'raw'"
              ><div class="full notice warning">
                原始配置是唯一配置来源。切回表单将忽略原始内容，请确认没有需保留的高级字段。连接参数与令牌必须自行保持一致。
              </div>
              <label
                >配置格式<select v-model="serverDraft.rawFormat">
                  <option v-for="f in ['toml', 'ini', 'yaml', 'json']" :key="f">{{ f }}</option>
                </select></label
              ><button type="button" @click="importConfig('server')">导入配置文件</button
              ><textarea
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
                    required /></label
                ><label v-else
                  >公网域名<input
                    v-model="rule.domain"
                    required
                    placeholder="demo.example.com" /></label
                ><template v-if="rule.type === 'https'"
                  ><label
                    >HTTPS 方式<select v-model="rule.tlsMode">
                      <option value="passthrough">转发本地 HTTPS</option>
                      <option value="terminate">证书终止后访问本地 HTTP</option>
                    </select></label
                  ><template v-if="rule.tlsMode === 'terminate'"
                    ><label class="full"
                      >证书路径
                      <div class="inline-fields">
                        <input v-model="rule.certPath" required /><button
                          type="button"
                          @click="choose('certificate', (p) => (rule.certPath = p))"
                        >
                          选择文件
                        </button>
                      </div></label
                    ><label class="full"
                      >证书私钥路径
                      <div class="inline-fields">
                        <input v-model="rule.keyPath" required /><button
                          type="button"
                          @click="choose('key', (p) => (rule.keyPath = p))"
                        >
                          选择文件
                        </button>
                      </div></label
                    ></template
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
            <button type="button" @click="enterRaw">生成完整配置并进入高级模式</button
            ><button type="button" @click="instanceDraft.mode = 'raw'">
              直接编写高级配置
            </button></template
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
            <button type="button" :disabled="busy" @click="modal = ''">取消</button
            ><button class="primary" :disabled="busy">保存实例</button>
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
        <form
          v-if="modal === 'adopt'"
          @submit.prevent="
            act('server:adopt', { id: selectedServer, deployment: adoption }).then(() => {
              if (!error) modal = '';
            })
          "
        >
          <div class="form-grid">
            <label class="full"
              >程序绝对路径<input
                v-model="adoption.binary"
                required
                placeholder="/opt/frp/frps" /></label
            ><label class="full"
              >配置绝对路径<input
                v-model="adoption.config"
                required
                placeholder="/opt/frp/frps.toml" /></label
            ><label
              >管理方式<select v-model="adoption.mode">
                <option value="process">后台进程</option>
                <option value="system">系统 systemd</option>
                <option value="user">用户 systemd</option>
              </select></label
            ><label>服务单元名<input v-model="adoption.service" required /></label
            ><label class="full"
              >日志绝对路径<input
                v-model="adoption.log"
                required
                placeholder="/opt/frp/frps.log" /></label
            ><label class="full"
              >PID 文件绝对路径<input
                v-model="adoption.pidFile"
                required
                placeholder="后台进程模式需保存对应进程 PID"
            /></label>
          </div>
          <p class="hint">
            接管先检测程序、配置和服务。后台进程会检测匹配的运行实例并补记
            PID，仅操作二进制与配置都匹配的进程；接管默认保留文件。
          </p>
          <div class="modal-actions">
            <button type="button" @click="modal = ''">取消</button
            ><button class="primary" :disabled="busy">检测并接管</button>
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
