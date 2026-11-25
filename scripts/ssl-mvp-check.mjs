import { _electron as electron, expect } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// 证书管理页 + Web 规则申请入口的界面回归：独立数据目录，不触碰日常配置。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-certs-check-'));
const state = {
  schema: 4,
  servers: [
    {
      id: 'certs-check-server',
      name: '证书回归服务器',
      host: '127.0.0.1',
      sshPort: 22,
      username: 'root',
      auth: 'key',
      keyPath: '/tmp/dummy-key',
      publicHost: '127.0.0.1',
      frpPort: 7000,
      httpPort: 8080,
      httpsPort: 8443,
      accessMode: 'managed',
      configMode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
    },
  ],
  instances: [
    {
      id: 'certs-check-instance',
      name: '证书回归实例',
      serverId: 'certs-check-server',
      versionKey: 'certs-check',
      mode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      proxies: [
        {
          id: 'certs-check-rule',
          name: 'web-demo',
          type: 'http',
          localIP: '127.0.0.1',
          localPort: 8080,
          domains: ['demo.example.com'],
          tlsMode: 'passthrough',
          certPath: '',
          keyPath: '',
        },
      ],
    },
  ],
  versions: [{ key: 'certs-check', version: '0.65.0', platform: 'darwin', arch: 'arm64' }],
  settings: {
    language: 'zh-CN',
    theme: 'system',
    confirmDangerous: true,
    proxyUrl: '',
    downloadConcurrency: 3,
  },
  certificates: [],
  serverSites: [],
  serverCertificates: [],
  dnsAccounts: [],
  terminalFavorites: [],
  secrets: {},
  catalog: null,
  downloads: [],
  siteInspections: {},
  managedTls: null,
};
await writeFile(path.join(data, 'state.json'), JSON.stringify(state), 'utf8');
const childEnv = { ...process.env, INTRANET_TEST_DATA: data };
delete childEnv.ELECTRON_RUN_AS_NODE;
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

  // 证书管理页只查看，不再提供申请入口；TLS 入口菜单已移除。
  await expect(page.locator('.nav-item').filter({ hasText: '证书管理' })).toBeVisible();
  await expect(page.locator('.nav-item').filter({ hasText: 'TLS 入口' })).toHaveCount(0);
  await page.locator('.nav-item').filter({ hasText: '证书管理' }).click();
  await expect(page.locator('h1.app-header__title')).toHaveText('证书管理');
  await expect(page.getByText('还没有证书')).toBeVisible();
  await expect(page.getByRole('button', { name: '申请并部署', exact: true })).toHaveCount(0);
  await expect(page.getByText('请到「客户端实例 → Web 规则 → SSL」中操作')).toBeVisible();

  // 申请入口只在 Web 规则的 SSL 面板里。
  await page.locator('.nav-item').filter({ hasText: '客户端' }).click();
  await page.locator('.item strong').filter({ hasText: '证书回归实例' }).first().click();
  await page.locator('.link-btn').filter({ hasText: 'web-demo' }).click();
  await page.locator('.rule-side-tabs__item').filter({ hasText: 'SSL' }).click();
  await page.getByRole('button', { name: '申请证书' }).click();
  await expect(page.getByRole('heading', { name: '申请证书' })).toBeVisible();
  await expect(page.locator('.tls-plan-panel')).toContainText('服务器终止（方案 A）');
  await expect(page.locator('.tls-plan-panel__checks li')).toHaveCount(4);
  await expect(page.locator('.tls-plan-panel')).toContainText('已阻止申请');
  await expect(page.getByLabel('验证实例')).toHaveCount(0);
  const submit = page.locator(
    '.ant-modal-wrap:visible button[type="submit"][form="form-cert-apply"]',
  );
  await expect(submit).toBeDisabled();

  // 文件验证不展示实例选择，只提示自动使用当前规则所属实例。
  await page.locator('.radio-option').filter({ hasText: '文件验证' }).locator('input').click();
  await expect(page.getByLabel('DNS 账户')).toHaveCount(0);
  await expect(page.getByLabel('验证实例')).toHaveCount(0);
  await expect(page.getByText('文件验证由当前 Web 规则所属的客户端实例自动承载')).toBeVisible();
  await page.locator('.ant-modal-wrap:visible .modal__close').click();
  await page.waitForTimeout(200);

  for (const [width, height] of [
    [1440, 900],
    [1024, 768],
    [900, 700],
  ]) {
    await page.setViewportSize({ width, height });
    await page.waitForTimeout(200);
    const overflow = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
    }));
    if (overflow.scrollWidth > overflow.innerWidth + 1)
      throw new Error(`${width}x${height} 横向溢出：${JSON.stringify(overflow)}`);
  }
  if (errors.length) throw new Error(`渲染层异常：${errors.join('; ')}`);
  if (/INTRANET_MAIN_ERROR/.test(mainErrors)) throw new Error('主进程异常');
  console.log('证书管理 / 方案 A 申请门槛 / 三档布局：界面回归通过。');
} finally {
  await application.close();
}
