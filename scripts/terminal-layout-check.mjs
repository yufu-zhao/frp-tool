import { _electron as electron, expect } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// 终端布局回归：验证记录/快捷命令/输出区有高度上限，内容再多也不撑高容器。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-terminal-layout-'));
const fixture = {
  schema: 3,
  servers: [],
  instances: [],
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
  await expect(page.locator('.nav-item').filter({ hasText: '终端' })).toBeVisible();
  await page.locator('.nav-item').filter({ hasText: '终端' }).click();

  // 终端页在无服务器时展示空态；布局规则挂在工作区容器上，注入一个模拟工作区来测 CSS 约束。
  const layout = await page.evaluate(() => {
    const host = document.querySelector('.page-body');
    const probe = document.createElement('section');
    probe.className = 'terminal-workspace';
    probe.innerHTML = `
      <div class="terminal-toolbar"></div>
      <div class="terminal-layout">
        <aside class="terminal-shortcuts">
          <div class="shortcut-list">
            ${Array.from({ length: 400 }, (_, i) => `<div class="shortcut-row"><button class="shortcut-command">cmd ${i} ${'x'.repeat(80)}</button></div>`).join('')}
          </div>
        </aside>
        <div class="terminal-main"></div>
      </div>`;
    host.appendChild(probe);
    const ws = probe;
    const sc = probe.querySelector('.terminal-shortcuts');
    const list = probe.querySelector('.shortcut-list');
    const style = getComputedStyle(ws);
    const listStyle = getComputedStyle(list);
    const viewport = window.innerHeight;
    const result = {
      viewport,
      wsHeight: ws.getBoundingClientRect().height,
      wsHeightStyle: style.height,
      wsOverflow: style.overflow,
      scOverflowY: getComputedStyle(sc).overflowY,
      listMaxHeight: listStyle.maxHeight,
      listOverflowY: listStyle.overflowY,
      listScrollHeight: list.scrollHeight,
      listClientHeight: list.clientHeight,
    };
    probe.remove();
    return result;
  });
  console.log('终端布局测量：', JSON.stringify(layout));

  expect(layout.wsHeight).toBeLessThanOrEqual(layout.viewport);
  expect(layout.wsOverflow).toBe('hidden');
  expect(layout.wsHeightStyle).not.toBe('auto');
  expect(layout.scOverflowY).toBe('auto');
  expect(layout.listOverflowY).toBe('auto');
  expect(parseFloat(layout.listMaxHeight)).toBeGreaterThan(0);
  // 内容远超容器时应出现列表内部滚动，而不是把容器撑高。
  expect(layout.listScrollHeight).toBeGreaterThan(layout.listClientHeight);
  expect(errors).toEqual([]);
  console.log('终端布局回归通过：记录/快捷命令区限高并内部滚动，工作区不随内容无限增高。');
} finally {
  await application.close();
}
