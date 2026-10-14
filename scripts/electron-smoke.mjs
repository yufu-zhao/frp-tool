import { _electron as electron, expect } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, mkdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

// 测试始终使用独立用户目录，不读取或改写日常使用的应用配置。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-ui-'));
const application = await electron.launch({
  executablePath: process.env.INTRANET_ELECTRON_PATH || electronPath,
  args: process.env.INTRANET_ELECTRON_PATH ? [] : ['.'],
  env: { ...process.env, INTRANET_TEST_DATA: data },
});
let mainErrors = '';
application.process().stderr?.on('data', (chunk) => {
  mainErrors += chunk.toString();
});
try {
  await application.evaluate(() => {
    process.on('uncaughtException', (error) =>
      console.error('INTRANET_MAIN_ERROR:', error.message),
    );
  });
  const page = await application.firstWindow();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await expect(page.locator('h1')).toHaveText('服务器');
  await expect(page.getByText('从一台服务器开始')).toBeVisible();
  await page.getByRole('button', { name: '添加第一台服务器' }).click();
  await expect(page.locator('.modal h2')).toHaveText('服务器配置');
  await page.getByLabel('名称', { exact: true }).fill('界面验证服务器');
  await page.getByLabel('SSH 管理地址').fill('127.0.0.1');
  await page.getByPlaceholder('支持直接输入绝对路径').fill('/tmp/test-key');
  await page.getByLabel('FRP 公网地址').fill('127.0.0.1');
  // 验证安全存储不可用的明确会话降级，不在测试中写入系统钥匙串。
  await application.evaluate(({ safeStorage }) => {
    safeStorage.isEncryptionAvailable = () => false;
  });
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(page.locator('.modal')).toHaveCount(0);
  await expect(page.locator('.item strong')).toHaveText('界面验证服务器');
  await page.locator('nav button').filter({ hasText: '客户端实例' }).click();
  await page.getByRole('button', { name: '创建第一个实例' }).click();
  await expect(page.locator('.rule-editor')).toHaveCount(1);
  await page.getByRole('button', { name: '添加规则' }).click();
  await expect(page.locator('.rule-editor')).toHaveCount(2);
  await page.getByRole('button', { name: '取消', exact: true }).click();
  await page.locator('nav button').filter({ hasText: '版本库' }).click();
  await expect(page.getByText('在线获取，离线也有入口')).toBeVisible();
  await page.getByRole('button', { name: '手动下载 / 离线导入' }).click();
  await expect(page.locator('.modal h2')).toHaveText('手动安装与离线导入');
  await page.getByRole('button', { name: '关闭', exact: true }).click();
  await page.locator('nav button').filter({ hasText: '设置与帮助' }).click();
  await expect(page.getByText('下载网络', { exact: true })).toBeVisible();
  await page.locator('nav button').filter({ hasText: '服务器' }).click();
  await mkdir('artifacts', { recursive: true });
  await page.screenshot({ path: 'artifacts/desktop-smoke.png', fullPage: true });
  await application.evaluate(({ BrowserWindow }) => {
    BrowserWindow.getAllWindows()[0].close();
  });
  await expect
    .poll(async () =>
      application.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].isVisible()),
    )
    .toBe(false);
  await application.evaluate(({ BrowserWindow }) => {
    BrowserWindow.getAllWindows()[0].show();
  });
  if (process.env.INTRANET_SMOKE_DATA) {
    const fixture = JSON.parse(
      await readFile(path.join(process.env.INTRANET_SMOKE_DATA, 'state.json'), 'utf8'),
    );
    const version = fixture.versions.find((item) => item.key === '0.71.0_darwin_amd64');
    if (!version) throw new Error('缺少实际 Electron 下载验证所需的可信测试包');
    const archive = await readFile(path.join(path.dirname(version.directory), 'archive'));
    const digest = createHash('sha256').update(archive).digest('hex');
    const install = await page.evaluate(
      (request) => window.desktop.call('version:install', request),
      {
        version: '0.71.0',
        platform: 'darwin',
        arch: 'amd64',
        digest,
        url: 'https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_darwin_amd64.tar.gz',
      },
    );
    if (!install.ok || install.data.version !== '0.71.0')
      throw new Error(install.error || 'Electron 真实下载失败');
    console.log('实际交付包 net.fetch 下载、流式写入、校验、解压与 FRP 执行检测通过。');
  }
  if (process.env.INTRANET_TEST_HOST && process.env.INTRANET_TEST_KEY) {
    const host = process.env.INTRANET_TEST_HOST;
    const trusted = execFileSync('ssh-keygen', ['-F', host], { encoding: 'utf8' })
      .split('\n')
      .filter((line) => line && !line.startsWith('#'))
      .map((line) =>
        createHash('sha256')
          .update(Buffer.from(line.split(/\s+/)[2], 'base64'))
          .digest('hex'),
      );
    await application.evaluate(({ dialog }, fingerprints) => {
      // 仅在独立 known_hosts 指纹匹配时通过测试确认，不自动信任任意主机。
      dialog.showMessageBox = async (...args) => {
        const options = args.at(-1);
        const accepted =
          options.title === '确认 SSH 服务器身份' &&
          fingerprints.some((hash) => options.detail.includes(hash));
        return { response: accepted ? 1 : 0, checkboxChecked: false };
      };
    }, trusted);
    const payload = {
      id: 'packaged-ssh',
      name: '打包程序 SSH 验证',
      host,
      sshPort: 22,
      username: 'root',
      auth: 'key',
      keyPath: process.env.INTRANET_TEST_KEY,
      publicHost: host,
      frpPort: 7000,
    };
    const save = await page.evaluate((p) => window.desktop.call('server:save', p), payload);
    if (!save.ok) throw new Error(save.error);
    const connect = await page.evaluate(() =>
      window.desktop.call('server:connect', 'packaged-ssh'),
    );
    if (!connect.ok) throw new Error(connect.error);
    const detect = await page.evaluate(() => window.desktop.call('server:detect', 'packaged-ssh'));
    if (!detect.ok || detect.data.arch !== 'amd64')
      throw new Error('打包程序 SSH 真实环境检测失败');
    // 保持 SSH 连接直到退出，覆盖此前漏掉的真实退出场景。
    console.log('打包程序真实 SSH 密钥认证与环境检测通过（只读），可选原生模块已排除。');
  }
  if (process.env.INTRANET_TEST_FORCE_RATE_LIMIT) {
    await application.evaluate(({ session }) => {
      const network = session.fromPartition('intranet-downloads');
      const fetch = network.fetch.bind(network);
      network.fetch = (url, options) =>
        String(url).startsWith('https://api.github.com/')
          ? Promise.resolve(
              new Response('', { status: 429, headers: { 'x-ratelimit-remaining': '0' } }),
            )
          : fetch(url, options);
    });
  }
  const catalog = await page.evaluate(() => window.desktop.call('version:catalog', 1));
  if (
    process.env.INTRANET_TEST_FORCE_RATE_LIMIT &&
    catalog.ok &&
    catalog.data.source !== 'github-web'
  )
    throw new Error('未触发官方网页兜底');
  if (!catalog.ok || !catalog.data.releases.some((release) => release.assets.length))
    throw new Error(catalog.error || '实际版本列表为空');
  console.log(`实际版本查询通过：${catalog.data.source}，${catalog.data.releases.length} 个版本。`);
  if (errors.length) throw new Error(errors.join('\n'));
  console.log('Electron 界面验证通过：服务器编辑、多规则、版本导入、设置、托盘隐藏；无页面异常。');
} finally {
  const exited = new Promise((resolve) => application.process().once('close', resolve));
  await application.evaluate(({ app }) => app.quit()).catch(() => {});
  let timeout;
  try {
    await Promise.race([
      exited,
      new Promise((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error('应用未在十秒内正常退出')), 10000);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
    await application.close().catch(() => {});
  }
  if (/INTRANET_MAIN_ERROR|Object has been destroyed|Uncaught Exception/.test(mainErrors))
    throw new Error(mainErrors);
  console.log('保留 SSH 连接后直接退出：正常退出，无主进程异常。');
}
