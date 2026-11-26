import { _electron as electron, expect } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// 规则编辑改造的界面回归：独立数据目录，不触碰日常配置。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-rule-editor-'));
const state = {
  schema: 4,
  servers: [
    {
      id: 'rule-check-server',
      name: '规则回归服务器',
      host: '127.0.0.1',
      sshPort: 22,
      username: 'root',
      auth: 'key',
      keyPath: '/tmp/dummy-key',
      publicHost: '127.0.0.1',
      frpPort: 7000,
      httpPort: 80,
      httpsPort: 8443,
      accessMode: 'managed',
      configMode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      deployment: {
        binary: '/usr/local/bin/frps',
        config: '/etc/frps.toml',
        log: '/var/log/frps.log',
        pidFile: '/run/frps.pid',
        mode: 'system',
        service: 'frps',
        managed: true,
        versionKey: '0.65.0_linux_amd64',
        version: '0.65.0',
      },
    },
  ],
  instances: [
    {
      id: 'rule-check-instance',
      name: '规则回归实例',
      serverId: 'rule-check-server',
      versionKey: 'rule-check',
      mode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      proxies: [
        {
          id: 'rule-web',
          name: 'web-demo',
          type: 'http',
          localIP: '127.0.0.1',
          localPort: 8080,
          domains: ['demo.example.com'],
          tlsMode: 'passthrough',
          certPath: '',
          keyPath: '',
        },
        {
          id: 'rule-hidden-https',
          name: 'web-demo-https',
          type: 'https',
          localIP: '127.0.0.1',
          localPort: 8080,
          domains: ['demo.example.com'],
          tlsMode: 'terminate',
          certificateId: 'cert-hidden',
          certPath: '',
          keyPath: '',
          hidden: true,
          sourceRuleId: 'rule-web',
        },
        {
          id: 'rule-tcp',
          name: 'tcp-demo',
          type: 'tcp',
          localIP: '127.0.0.1',
          localPort: 3000,
          remotePort: 5678,
          domains: [],
          tlsMode: 'passthrough',
          certPath: '',
          keyPath: '',
        },
      ],
    },
  ],
  versions: [
    { key: 'rule-check', version: '0.65.0', platform: 'darwin', arch: 'arm64' },
    ...['arm64', 'amd64'].map((arch) => ({
      key: `0.65.0_darwin_${arch}`,
      version: '0.65.0',
      platform: 'darwin',
      arch,
      directory: `/tmp/intranet-rule-check-darwin-${arch}`,
      source: '回归测试桩',
      installedAt: new Date().toISOString(),
      verified: true,
      digest: '',
    })),
  ],
  catalog: {
    source: 'cache',
    updatedAt: new Date().toISOString(),
    cached: true,
    page: 1,
    hasMore: false,
    releases: [
      {
        version: '0.65.0',
        publishedAt: '2026-01-01T00:00:00.000Z',
        assets: ['arm64', 'amd64'].map((arch) => ({
          name: `frp_0.65.0_darwin_${arch}.tar.gz`,
          url: `https://example.invalid/frp_0.65.0_darwin_${arch}.tar.gz`,
          digest: '',
          size: 1,
        })),
      },
    ],
  },
  settings: {
    language: 'zh-CN',
    theme: 'system',
    confirmDangerous: true,
    proxyUrl: '',
    downloadConcurrency: 3,
  },
  certificates: [
    {
      id: 'cert-hidden',
      name: '回归本机证书',
      provider: 'letsencrypt',
      domains: ['demo.example.com'],
      certPath: path.resolve('tests/fixtures/certificates-test-cert.pem'),
      keyPath: path.resolve('tests/fixtures/certificates-test-key.pem'),
      createdAt: Date.now(),
    },
  ],
  serverSites: [],
  serverCertificates: [
    {
      id: 'cert-hidden',
      serverId: 'rule-check-server',
      name: '回归本机证书',
      provider: 'letsencrypt',
      domains: ['demo.example.com'],
      location: 'local',
      localCertificateId: 'cert-hidden',
      certPath: path.resolve('tests/fixtures/certificates-test-cert.pem'),
      keyPath: path.resolve('tests/fixtures/certificates-test-key.pem'),
      tlsPlan: 'local',
      deployState: 'deployed',
      instanceId: 'rule-check-instance',
      ruleId: 'rule-web',
      hiddenRuleId: 'rule-hidden-https',
      createdAt: Date.now(),
    },
    ...Array.from({ length: 9 }, (_, index) => ({
      id: `cert-extra-${index}`,
      serverId: 'rule-check-server',
      name: `回归证书 ${index + 1}`,
      provider: 'manual',
      domains: [`extra${index}.example.com`],
      location: 'local',
      localCertificateId: 'cert-hidden',
      certPath: path.resolve('tests/fixtures/certificates-test-cert.pem'),
      keyPath: path.resolve('tests/fixtures/certificates-test-key.pem'),
      tlsPlan: 'local',
      deployState: 'deployed',
      createdAt: Date.now(),
    })),
  ],
  dnsAccounts: [],
  terminalFavorites: [],
  secrets: {},
  downloads: [],
  siteInspections: {},
  managedTls: null,
};
await writeFile(path.join(data, 'state.json'), JSON.stringify(state), 'utf8');
const childEnv = { ...process.env, INTRANET_TEST_DATA: data };
delete childEnv.ELECTRON_RUN_AS_NODE;
// 避免沙箱代理干扰 Chromium network service（DevTools 通道会被代理劫持导致崩溃）。
for (const key of [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'http_proxy',
  'https_proxy',
  'ALL_PROXY',
  'all_proxy',
])
  delete childEnv[key];
const application = await electron.launch({
  executablePath: process.env.INTRANET_ELECTRON_PATH || electronPath,
  args: [
    ...(process.env.INTRANET_ELECTRON_PATH ? [] : ['.']),
    '--no-sandbox',
    '--disable-gpu-sandbox',
  ],
  env: childEnv,
});
let mainErrors = '';
application.process().stderr?.on('data', (chunk) => {
  mainErrors += chunk.toString();
});
try {
  const page = await application.firstWindow();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.setDefaultTimeout(8000);

  await page.locator('.nav-item').filter({ hasText: '客户端' }).click();
  await expect(
    page.locator('.item strong').filter({ hasText: '规则回归实例' }).first(),
  ).toBeVisible();
  await page.locator('.item strong').filter({ hasText: '规则回归实例' }).first().click();

  // 标签页与表格列
  await expect(page.locator('.tabs__item').filter({ hasText: '站点' })).toBeVisible();
  await expect(page.locator('.tabs__item').filter({ hasText: '服务' })).toBeVisible();
  await expect(page.locator('.data-table th').nth(0)).toHaveText('规则名称');
  await expect(page.locator('.data-table th').nth(1)).toHaveText('类型');
  await expect(page.locator('.data-table th').nth(2)).toHaveText('本地地址和端口');
  await expect(page.locator('.data-table th').nth(3)).toHaveText('操作');
  await expect(page.locator('.data-table tbody tr')).toHaveCount(1);
  await expect(page.locator('.data-table tbody tr').first()).toContainText('web-demo');
  // 方案 B 有隐藏 HTTPS 伴随规则时，列表仍一条且类型显示 Web · HTTPS。
  await expect(page.locator('.data-table tbody tr').first()).toContainText('Web · HTTPS');
  await expect(page.locator('.data-table')).not.toContainText('web-demo-https');
  await page.locator('.tabs__item').filter({ hasText: '服务' }).click();
  await expect(page.locator('.data-table tbody tr').first()).toContainText('tcp-demo');

  // 编辑 Web 规则：左侧标签、HTTPS 开关、类型下拉三项
  await page.locator('.tabs__item').filter({ hasText: '站点' }).click();
  await page.locator('.link-btn').filter({ hasText: 'web-demo' }).click();
  await expect(page.getByRole('heading', { name: '编辑规则' })).toBeVisible();
  // 编辑 Web 规则时类型下拉必须回显当前类型，而不是空值。
  await expect(
    page.locator('.field').filter({ hasText: '类型' }).locator('.ant-select-selection-item'),
  ).toHaveText('Web');
  await expect(page.locator('.rule-side-tabs__item').filter({ hasText: '基础' })).toBeVisible();
  await expect(page.locator('.rule-side-tabs__item').filter({ hasText: '配置文件' })).toBeVisible();
  await expect(page.locator('.rule-side-tabs__item').filter({ hasText: 'SSL' })).toBeVisible();
  await expect(page.getByText('启用 HTTPS', { exact: true })).toHaveCount(0);
  await expect(page.getByText('规则默认走 HTTP', { exact: false })).toBeVisible();

  // 配置文件标签：CodeMirror 编辑器、按 Web 软件生成的模板与保存入口。
  await page.locator('.rule-side-tabs__item').filter({ hasText: '配置文件' }).click();
  await expect(page.locator('.site-code-editor .cm-editor')).toBeVisible();
  await expect(page.getByRole('button', { name: '刷新检测' })).toBeVisible();
  await expect(page.getByRole('button', { name: '重新生成' })).toBeVisible();
  await expect(page.getByRole('button', { name: '保存配置' })).toBeVisible();
  await page.getByRole('button', { name: '重新生成' }).click();
  await expect(page.locator('.cm-content')).toContainText('server {');
  await expect(page.locator('.cm-content')).toContainText('127.0.0.1:80');
  await page.locator('.rule-side-tabs__item').filter({ hasText: 'SSL' }).click();
  // 方案 B 不再提供手动导入证书，只保留申请与移除；避免 PEM 粘贴框重新出现。
  await expect(page.getByRole('button', { name: '保存并启用证书' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '申请证书' })).toBeVisible();
  await expect(page.locator('.cert-panel .code-editor')).toHaveCount(0);
  // SSL 标签统一分区，并展示证书/私钥的实际存放位置。
  await expect(page.locator('.cert-panel__section h3').first()).toHaveText('当前方案');
  await expect(page.locator('.cert-location')).toContainText('证书存放位置');
  await expect(page.locator('.cert-location')).toContainText('cert-hidden/fullchain.pem');

  // 申请证书弹窗字段
  await page.getByRole('button', { name: '申请证书' }).click();
  await expect(page.getByRole('heading', { name: '申请证书' })).toBeVisible();
  await expect(page.getByText('Let’s Encrypt')).toBeVisible();
  await expect(page.getByText('LiteSSL', { exact: true })).toBeVisible();
  await expect(page.getByText('文件验证')).toBeVisible();
  await expect(page.getByText('DNS 验证')).toBeVisible();
  await expect(page.locator('.check-all')).toContainText('全选');
  await expect(page.locator('.check-option').filter({ hasText: 'demo.example.com' })).toBeVisible();
  // 方案判定面板：无注入记录的回归桩应判定为本机终止（方案 B）。
  await expect(page.locator('.tls-plan-panel')).toContainText('本机终止');
  await expect(page.locator('.tls-plan-panel__checks li')).toHaveCount(4);
  // 文件验证无需选择实例：目标服务器已由 Web 规则固定。
  await expect(page.getByLabel('验证实例')).toHaveCount(0);
  // 算法下拉三个 RSA 选项
  const keySizeSelect = page
    .locator('.field')
    .filter({ hasText: '证书算法' })
    .locator('.app-select');
  await keySizeSelect.click();
  const options = await page
    .locator('.ant-select-dropdown .ant-select-item-option')
    .allInnerTexts();
  expect(options.join('|')).toContain('RSA 2048');
  expect(options.join('|')).toContain('RSA 3072');
  expect(options.join('|')).toContain('RSA 4096');
  await page.locator('.ant-modal-wrap:visible .modal__close').click();
  await page.waitForTimeout(200);

  // 新增规则不显示左侧标签；保存后应立刻出现在列表里，无需重启应用。
  await page.getByRole('button', { name: '＋ 新增站点' }).click();
  await expect(page.getByRole('heading', { name: '新增规则' })).toBeVisible();
  await expect(page.locator('.rule-side-tabs')).toHaveCount(0);
  await page.locator('#form-rule textarea').fill('new.example.com');
  await page.getByRole('button', { name: '保存规则' }).click();
  await expect(page.getByRole('heading', { name: '新增规则' })).toHaveCount(0);
  await expect(page.locator('.data-table tbody tr')).toHaveCount(2);
  await expect(page.locator('.data-table')).toContainText('web-4');

  // 新建客户端实例后也应立刻出现在实例列表里。
  await page.getByRole('button', { name: '＋ 创建实例' }).click();
  await expect(page.getByRole('heading', { name: '客户端实例配置' })).toBeVisible();
  await page.locator('#form-instance input').first().fill('instant-instance');
  await page.locator('.ant-modal-wrap:visible').getByRole('button', { name: '保存实例' }).click();
  await expect(page.locator('.ant-modal-wrap:visible')).toHaveCount(0);
  await expect(
    page.locator('.item strong').filter({ hasText: 'instant-instance' }).first(),
  ).toBeVisible();

  // 实例配置弹窗里不再内嵌代理规则编辑
  await page.getByRole('button', { name: '编辑实例' }).click();
  await expect(page.locator('.rule-editor')).toHaveCount(0);
  await expect(page.getByText('代理规则已移到实例详情页')).toBeVisible();
  await page.locator('.ant-modal-wrap:visible .modal__close').click();
  await page.waitForTimeout(200);

  // 证书管理：简化卡片、搜索、分页与详情抽屉（含下载/删除入口）。
  await page.locator('.nav-item').filter({ hasText: '证书管理' }).click();
  await expect(page.getByRole('heading', { name: '证书管理', exact: true })).toBeVisible();
  await expect(page.locator('.cert-card')).toHaveCount(8);
  await expect(page.locator('.pager')).toContainText('1 / 2');
  await page.getByRole('button', { name: '下一页' }).click();
  await expect(page.locator('.cert-card')).toHaveCount(2);
  await page.locator('input[aria-label="搜索证书"]').fill('extra3');
  await expect(page.locator('.cert-card')).toHaveCount(1);
  await expect(page.locator('.cert-card')).toContainText('extra3.example.com');
  await page.locator('input[aria-label="搜索证书"]').fill('');
  await page.locator('.cert-card').first().getByRole('button', { name: '查看详情' }).click();
  await expect(page.locator('.drawer')).toBeVisible();
  await expect(page.locator('.drawer')).toContainText('存放位置');
  await expect(page.locator('.drawer')).toContainText('fullchain.pem');
  await expect(page.getByRole('button', { name: '下载证书' })).toBeVisible();
  await expect(page.getByRole('button', { name: '下载私钥' })).toBeVisible();
  await expect(page.getByRole('button', { name: '删除证书' })).toBeVisible();
  await page.getByRole('button', { name: '关闭抽屉' }).click();

  // DNS 管理：独立菜单 + 两个标签页；域名解析在前，账户管理需切换标签。
  await page.locator('.nav-item').filter({ hasText: 'DNS 管理' }).click();
  await expect(page.getByRole('heading', { name: 'DNS 管理' })).toBeVisible();
  await expect(page.getByRole('tab', { name: '域名解析管理' })).toBeVisible();
  await expect(page.getByRole('tab', { name: '域名解析管理' })).toHaveAttribute(
    'aria-selected',
    'true',
  );
  await expect(page.getByRole('button', { name: '新增记录' })).toBeDisabled();
  await page.getByRole('tab', { name: '账户管理' }).click();
  await expect(page.getByRole('tab', { name: '账户管理' })).toHaveAttribute(
    'aria-selected',
    'true',
  );
  await expect(page.getByText('还没有保存 DNS 账户')).toBeVisible();
  await expect(page.getByRole('button', { name: /新增账户/ })).toBeVisible();

  // 三档布局检查（含 DNS 管理页两个标签）
  for (const width of [1440, 1024, 900]) {
    await page.setViewportSize({ width, height: 800 });
    for (const tab of ['账户管理', '域名解析管理']) {
      await page.getByRole('tab', { name: tab }).click();
      await page.waitForTimeout(120);
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      );
      expect(overflow, `${width}px ${tab} 横向溢出`).toBe(false);
    }
  }

  expect(errors, `渲染层异常：${errors.join('; ')}`).toEqual([]);
  expect(mainErrors, `主进程异常：${mainErrors.slice(0, 600)}`).toBe('');
  console.log('规则编辑改造界面回归通过：标签页、表格、Web SSL 标签、证书申请弹窗、三档布局');
} finally {
  await application.close();
}
