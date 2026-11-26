import { _electron as electron, expect } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// 视觉巡检：三档视口截取关键页面，供人工核对布局与重构后的视觉。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-visual-'));
const outDir = path.resolve('artifacts/visual');
await mkdir(outDir, { recursive: true });
const fixture = {
  schema: 3,
  servers: [
    {
      id: 'demo-server',
      name: '生产服务器',
      host: '203.0.113.10',
      sshPort: 22,
      username: 'root',
      auth: 'key',
      keyPath: '/tmp/demo',
      publicHost: 'tunnel.example.com',
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
      id: 'demo-instance',
      name: '本机穿透',
      serverId: 'demo-server',
      versionKey: '0.65.0_darwin_arm64',
      mode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      proxies: [
        {
          id: 'r1',
          name: 'api.example.com',
          type: 'http',
          localIP: '127.0.0.1',
          localPort: 8080,
          domains: ['api.example.com'],
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
  ],
  versions: [],
  settings: {
    language: 'zh-CN',
    theme: 'light',
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
await writeFile(path.join(data, 'state.json'), JSON.stringify(fixture), 'utf8');
const childEnv = { ...process.env, INTRANET_TEST_DATA: data };
delete childEnv.ELECTRON_RUN_AS_NODE;
const application = await electron.launch({
  executablePath: process.env.INTRANET_ELECTRON_PATH || electronPath,
  args: [
    ...(process.env.INTRANET_ELECTRON_PATH ? [] : ['.']),
    '--no-sandbox',
    '--disable-gpu-sandbox',
  ],
  env: childEnv,
});
try {
  const page = await application.firstWindow();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await expect(page.locator('.nav-item').first()).toBeVisible();

  for (const [name, width] of [
    ['desktop', 1440],
    ['tablet', 1024],
    ['narrow', 900],
  ]) {
    await page.setViewportSize({ width, height: 900 });
    for (const [pageName, nav] of [
      ['servers', '服务器'],
      ['clients', '客户端实例'],
      ['dns', 'DNS 管理'],
      ['settings', '设置'],
    ]) {
      await page.locator('.nav-item').filter({ hasText: nav }).click();
      await page.waitForTimeout(120);
      await page.screenshot({ path: path.join(outDir, `${name}-${pageName}.png`) });
      // 横向溢出检测
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      );
      if (overflow) throw new Error(`${name}/${pageName} 出现横向溢出`);
    }
  }
  expect(errors).toEqual([]);
  console.log(`视觉巡检完成：三档 × 四页截图已保存到 ${outDir}，无横向溢出、无页面异常。`);
} finally {
  await application.close();
}
