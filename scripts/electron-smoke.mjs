import { _electron as electron, expect } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, mkdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

// 测试始终使用独立用户目录，不读取或改写日常使用的应用配置。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-ui-'));
// 受限 / 容器化环境中 Chromium 沙箱不可用，测试进程显式关闭它；
// 同时清掉宿主可能注入的 ELECTRON_RUN_AS_NODE，避免以纯 Node 模式启动主进程。
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
  // 组件库 UI：状态徽标不应呈现按钮边框，表单下拉由 Ant Design Vue 承载。
  const badgeStyle = await page.locator('.app-header__status').evaluate((el) => {
    const style = getComputedStyle(el);
    return {
      border: style.borderTopWidth,
      background: style.backgroundColor,
      shadow: style.boxShadow,
    };
  });
  if (
    badgeStyle.border !== '0px' ||
    badgeStyle.background !== 'rgba(0, 0, 0, 0)' ||
    badgeStyle.shadow !== 'none'
  )
    throw new Error(`服务器状态徽标仍带按钮外观：${JSON.stringify(badgeStyle)}`);
  await expect(page.locator('.modal .app-select.ant-select').first()).toBeVisible();
  await expect(page.locator('.modal select')).toHaveCount(0);
  await page.getByLabel('名称', { exact: true }).fill('界面验证服务器');
  await page.getByLabel('SSH 管理地址').fill('127.0.0.1');
  await page.getByPlaceholder('支持直接输入绝对路径').fill('/tmp/test-key');
  await page.getByLabel('FRP 公网地址').fill('127.0.0.1');
  // 回归：80/443 必须能直接保存（旧版渲染层曾硬拦截，导致保存不了）。
  await page.getByLabel('HTTP 入口端口').fill('80');
  await page.getByLabel('HTTPS 入口端口').fill('443');
  // 验证安全存储不可用的明确会话降级，不在测试中写入系统钥匙串。
  await application.evaluate(({ safeStorage }) => {
    safeStorage.isEncryptionAvailable = () => false;
  });
  await page.getByRole('button', { name: '保存并应用', exact: true }).click();
  await expect(page.locator('.modal')).toHaveCount(0);
  await expect(page.locator('.item strong')).toHaveText('界面验证服务器');
  const savedPorts = JSON.parse(await readFile(path.join(data, 'state.json'), 'utf8')).servers[0];
  if (savedPorts.httpPort !== 80 || savedPorts.httpsPort !== 443)
    throw new Error('服务器 HTTP/HTTPS 入口端口 80/443 未能保存');
  console.log('服务器入口端口 80 / 443 保存验证通过。');
  // 检索服务已内置到安装流程，页面不再保留独立的检索功能块。
  await expect(page.getByRole('heading', { name: '检索已有 FRP 服务' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '安装服务端' })).toBeVisible();
  await page.locator('.nav-item').filter({ hasText: '客户端实例' }).click();
  await page.getByRole('button', { name: '创建第一个实例' }).click();
  // 规则 CRUD 已从实例表单抽出：实例弹窗只保留基础配置，规则在详情页独立管理。
  await expect(page.locator('.rule-editor')).toHaveCount(0);
  await expect(page.getByText('代理规则已移到实例详情页')).toBeVisible();
  await page.getByRole('button', { name: '取消', exact: true }).click();
  await page.locator('.nav-item').filter({ hasText: '版本库' }).click();
  await expect(page.getByText('官方发布版本')).toBeVisible();
  await page.getByRole('button', { name: '手动 / 离线导入' }).click();
  await expect(page.locator('.modal h2')).toHaveText('手动下载 / 离线导入');
  await page.getByRole('button', { name: '关闭', exact: true }).click();
  await page.locator('.nav-item').filter({ hasText: '设置' }).click();
  await expect(page.getByText('下载网络', { exact: true })).toBeVisible();
  // DNS 账户已从设置迁到独立的「DNS 管理」页。
  await page.locator('.nav-item').filter({ hasText: 'DNS 管理' }).click();
  await expect(page.getByRole('heading', { name: 'DNS 管理' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '账户管理' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '域名解析管理' })).toBeVisible();
  // 回归：新增/编辑 DNS 账户都走弹窗；空 ID/Key 点测试必须显示真实失败原因。
  await expect(page.getByRole('button', { name: '新增账户', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '新增账户', exact: true }).click();
  await expect(page.locator('.modal h2')).toHaveText('新增 DNS 账户');
  await page.locator('.modal .app-select').first().click();
  const providerOptions = await page
    .locator('.ant-select-dropdown .ant-select-item-option')
    .allInnerTexts();
  expect(providerOptions).toEqual(['DNSPod', '阿里云 DNS', 'Cloudflare']);
  await page.locator('.modal h2').click();
  await page.getByRole('button', { name: '测试并保存凭据' }).click();
  await expect(page.locator('.modal .hint--error')).toContainText('缺少 DNSPod ID/Token');
  await expect(page.getByText('DNS 账户凭据验证通过。')).toHaveCount(0);
  await expect(page.getByText('凭据验证通过并已安全保存。')).toHaveCount(0);
  await page.locator('.modal .modal__close').click();
  await page.locator('.nav-item').first().click();
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
