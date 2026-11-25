import { _electron as electron, expect } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// 服务器面板改造的界面回归：独立数据目录，不触碰日常配置。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-server-panel-'));
const deployedServer = {
  schema: 3,
  servers: [
    {
      id: 'panel-check-server',
      name: '面板回归服务器',
      host: '127.0.0.1',
      sshPort: 22,
      username: 'root',
      auth: 'key',
      keyPath: '/tmp/dummy-key',
      publicHost: '127.0.0.1',
      frpPort: 7000,
      httpPort: 80,
      httpsPort: 443,
      accessMode: 'managed',
      configMode: 'form',
      rawConfig: '',
      rawFormat: 'toml',
      deployment: {
        binary: '/root/.local/share/intranet-frp/panel-check/frps',
        config: '/root/.local/share/intranet-frp/panel-check/frps.toml',
        log: '/root/.local/share/intranet-frp/panel-check/frps.log',
        pidFile: '/root/.local/share/intranet-frp/panel-check/frps.pid',
        mode: 'system',
        manager: 'systemd',
        service: 'intranet-frp-panel-check',
        managed: true,
        versionKey: 'panel-check',
        version: '0.65.0',
      },
    },
  ],
  instances: [],
  versions: [],
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
await writeFile(path.join(data, 'state.json'), JSON.stringify(deployedServer), 'utf8');
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
let mainErrors = '';
application.process().stderr?.on('data', (chunk) => {
  mainErrors += chunk.toString();
});
try {
  const page = await application.firstWindow();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await expect(page.locator('.nav-item').filter({ hasText: '服务器' })).toBeVisible();
  await page.locator('.nav-item').filter({ hasText: '服务器' }).click();
  await expect(page.locator('.item strong')).toHaveText('面板回归服务器');

  // 旧按钮与旧折叠页全部移除。
  await expect(page.getByText('查看端口占用')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '查看服务状态' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '应用已保存配置' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '停止后切换版本' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '开启开机启动' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '关闭开机启动' })).toHaveCount(0);
  // 新组件：版本徽标可点击、开机启动开关、状态驱动按钮。
  await expect(page.locator('button[title="切换服务端版本"]')).toBeVisible();
  await expect(page.locator('.ant-switch')).toBeVisible();
  await expect(page.getByRole('button', { name: '查看日志' })).toBeVisible();
  // SSH 未连接时只显示启动按钮，停止 / 重启不出现。
  await expect(page.getByRole('button', { name: '启动', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '停止', exact: true })).toHaveCount(0);

  // 编辑表单：保存即应用，路径在表单内展示。
  await page.getByRole('button', { name: '编辑配置' }).click();
  await expect(page.locator('.modal h2')).toHaveText('服务器配置');
  await expect(page.getByRole('button', { name: '保存并应用' })).toBeVisible();
  await expect(page.getByText('部署路径（只读）')).toBeVisible();
  await expect(
    page.getByText('/root/.local/share/intranet-frp/panel-check/frps', { exact: false }),
  ).toBeVisible();
  await page.locator('.modal .modal__close').click();

  for (const [width, height] of [
    [1440, 900],
    [1024, 768],
    [900, 700],
  ]) {
    await application.evaluate(
      ({ BrowserWindow }, size) =>
        BrowserWindow.getAllWindows()[0].setContentSize(size[0], size[1]),
      [width, height],
    );
    await page.waitForTimeout(350);
    const overflow = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
    }));
    if (overflow.scrollWidth > overflow.innerWidth + 1)
      throw new Error(`${width}x${height} 横向溢出：${JSON.stringify(overflow)}`);
  }
  if (errors.length) throw new Error(`渲染层异常：${errors.join('; ')}`);
  if (/INTRANET_MAIN_ERROR/.test(mainErrors)) throw new Error('主进程异常');
  console.log('服务器面板：旧按钮移除、新组件、保存并应用、三档布局均通过。');
} finally {
  await application.close();
}
