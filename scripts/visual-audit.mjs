import { _electron as electron } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// 定点修复后的实拍核对：覆盖用户标注的 9 处位置。独立数据目录，不触碰日常配置。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-audit-'));
const outDir = path.resolve('artifacts/audit');
await mkdir(outDir, { recursive: true });
const certPath = path.resolve('tests/fixtures/certificates-test-cert.pem');
const keyPath = path.resolve('tests/fixtures/certificates-test-key.pem');
const state = {
  schema: 4,
  servers: [
    {
      id: 's1',
      name: '锦赞',
      host: '8.147.235.205',
      sshPort: 22,
      username: 'root',
      auth: 'key',
      keyPath: '/tmp/demo',
      publicHost: '8.147.235.205',
      frpPort: 7000,
      httpPort: 80,
      httpsPort: 443,
      accessMode: 'managed',
      configMode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      deployment: {
        binary: '/root/.local/share/intranet-frp/bin/frps',
        config: '/root/.local/share/intranet-frp/frps.toml',
        log: '/var/log/frps.log',
        pidFile: '/run/frps.pid',
        mode: 'system',
        service: 'frps',
        managed: true,
        versionKey: '0.72.0_linux_amd64',
        version: '0.72.0',
      },
    },
    {
      id: 's2',
      name: '香港',
      host: '8.217.91.211',
      sshPort: 22,
      username: 'root',
      auth: 'key',
      keyPath: '/tmp/demo2',
      publicHost: '8.217.91.211',
      frpPort: 7000,
      httpPort: 80,
      httpsPort: 443,
      accessMode: 'managed',
      configMode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
    },
  ],
  instances: [
    {
      id: 'i1',
      name: '锦赞实例',
      serverId: 's1',
      versionKey: '0.72.0_darwin_arm64',
      mode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      proxies: [
        {
          id: 'r1',
          name: 'web-1',
          type: 'http',
          localIP: '127.0.0.1',
          localPort: 5188,
          domains: ['i9token.jinxianruanjian.com'],
          tlsMode: 'passthrough',
          certPath: '',
          keyPath: '',
          publicHttps: true,
        },
        {
          id: 'r2',
          name: 'db',
          type: 'tcp',
          localIP: '127.0.0.1',
          localPort: 3306,
          remotePort: 13306,
          domains: [],
          tlsMode: 'passthrough',
          certPath: '',
          keyPath: '',
        },
      ],
    },
    {
      id: 'i2',
      name: '香港实例',
      serverId: 's2',
      versionKey: '0.72.0_darwin_arm64',
      mode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      proxies: [],
    },
  ],
  versions: [],
  catalog: null,
  settings: {
    language: 'zh-CN',
    theme: 'system',
    confirmDangerous: true,
    proxyUrl: '',
    downloadConcurrency: 3,
  },
  certificates: [
    {
      id: 'cert-local',
      name: 'service-2',
      provider: 'letsencrypt',
      domains: ['i9token.jinxianruanjian.com'],
      certPath,
      keyPath,
      createdAt: Date.now(),
    },
  ],
  serverSites: [],
  serverCertificates: [
    {
      id: 'cert-srv',
      serverId: 's1',
      name: 'service-2',
      provider: 'letsencrypt',
      domains: ['i9token.jinxianruanjian.com'],
      location: 'local',
      localCertificateId: 'cert-local',
      certPath,
      keyPath,
      tlsPlan: 'local',
      deployState: 'deployed',
      instanceId: 'i1',
      ruleId: 'r1',
      createdAt: Date.now(),
    },
  ],
  dnsAccounts: [
    { id: 'dns-1', name: 'ali', provider: 'aliyun', createdAt: Date.now() },
    { id: 'dns-2', name: 'cf', provider: 'cloudflare', createdAt: Date.now() },
  ],
  terminalFavorites: [
    { id: 'f1', name: 'ffd', command: 'fd', order: 0, updatedAt: Date.now() },
    { id: 'f2', name: '列表', command: 'ls -al', order: 1, updatedAt: Date.now() },
  ],
  secrets: {},
  downloads: [],
  siteInspections: {},
  managedTls: null,
};
await writeFile(path.join(data, 'state.json'), JSON.stringify(state), 'utf8');
const childEnv = { ...process.env, INTRANET_TEST_DATA: data };
delete childEnv.ELECTRON_RUN_AS_NODE;
console.log('启动 Electron…');
const application = await electron.launch({
  executablePath: process.env.INTRANET_ELECTRON_PATH || electronPath,
  args: [
    ...(process.env.INTRANET_ELECTRON_PATH ? [] : ['.']),
    '--no-sandbox',
    '--disable-gpu-sandbox',
  ],
  env: childEnv,
  timeout: 20000,
});
application.process().stderr?.on('data', (chunk) => {
  const text = chunk.toString();
  if (/Error|error|throw|INTRANET_MAIN_ERROR|ZodError/i.test(text))
    console.log('[main]', text.trim().slice(0, 400));
});
console.log('已启动，取窗口…');
const shot = async (page, name) => {
  await page.waitForTimeout(180);
  await page.screenshot({ path: path.join(outDir, `${name}.png`) });
  console.log('✓', name);
};
const step = async (label, fn) => {
  try {
    await fn();
  } catch (e) {
    console.log('✗', label, String(e.message).split('\n')[0]);
  }
};
try {
  const page = await application.firstWindow();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.setDefaultTimeout(5000);
  await page.locator('.nav-item').first().waitFor();
  await page.setViewportSize({ width: 1440, height: 900 });
  const nav = (text) => page.locator('.nav-item').filter({ hasText: text }).click();

  // 1 服务器配置弹窗（需 deployment 才显示折叠的部署路径）
  await step('01 服务器弹窗', async () => {
    await page.getByRole('button', { name: '编辑配置' }).first().click();
    await shot(page, '01-server-modal');
    await page.locator('.modal__close').click();
  });
  // 2 服务器详情（按钮 / 分隔线）
  await step('02 服务器详情', () => shot(page, '02-server-detail'));
  // 3 客户端实例（标签 / 访问地址已移除）
  await step('03 客户端实例', async () => {
    await nav('客户端实例');
    await shot(page, '03-instances');
  });
  // 4 规则 SSL 面板
  await step('04 规则 SSL', async () => {
    await page.locator('.link-btn').filter({ hasText: 'web-1' }).first().click();
    await page.locator('.rule-side-tabs__item').filter({ hasText: 'SSL' }).click();
    await shot(page, '04-rule-ssl');
    await page.locator('.modal__close').click();
  });
  // 5 DNS 账户管理
  await step('05 DNS 账户', async () => {
    await nav('DNS 管理');
    await page.getByRole('tab', { name: '账户管理' }).click();
    await shot(page, '05-dns-accounts');
  });
  // 6 证书详情抽屉
  await step('06 证书抽屉', async () => {
    await nav('证书管理');
    await page.getByRole('button', { name: '查看详情' }).first().click();
    await shot(page, '06-cert-drawer');
    await page.getByRole('button', { name: '关闭抽屉' }).click();
  });
  // 7 终端
  await step('07 终端', async () => {
    await nav('终端');
    await shot(page, '07-terminal');
  });
  // 8 设置
  await step('08 设置', async () => {
    await nav('设置');
    await shot(page, '08-settings');
  });
  // 9 帮助
  await step('09 帮助', async () => {
    await nav('帮助');
    await shot(page, '09-help');
  });

  console.log('页面异常:', JSON.stringify(errors));
  console.log('截图目录:', outDir);
} finally {
  await application.close();
}
