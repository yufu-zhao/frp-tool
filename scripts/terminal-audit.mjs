import { _electron as electron } from '@playwright/test';
import electronPath from 'electron';
import { mkdtemp, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// 终端三处 CSS 的实拍核对：真实 SSH 会话不可用，注入等效 DOM 到终端页验证样式。
const data = await mkdtemp(path.join(tmpdir(), 'intranet-term-audit-'));
const outDir = path.resolve('artifacts/audit');
await mkdir(outDir, { recursive: true });
const env = { ...process.env, INTRANET_TEST_DATA: data };
delete env.ELECTRON_RUN_AS_NODE;
const application = await electron.launch({
  executablePath: electronPath,
  args: ['.', '--no-sandbox', '--disable-gpu-sandbox'],
  env,
  timeout: 20000,
});
try {
  const page = await application.firstWindow();
  await page.locator('.nav-item').first().waitFor();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator('.nav-item').filter({ hasText: '终端' }).click();
  await page.waitForTimeout(150);

  const metrics = await page.evaluate(() => {
    // 终端空态会占满页面，探针追加在后面会落到视口外；先清空再注入，实拍才看得到。
    const host = document.querySelector('.page-body');
    host.innerHTML = '';
    const probe = document.createElement('section');
    probe.className = 'terminal-workspace terminal-workspace--audit';
    probe.innerHTML = `
      <div class="terminal-toolbar">
        <div class="terminal-tabs" role="tablist">
          <button class="terminal-tab">锦赞 · 8 <span>×</span></button>
          <button class="terminal-tab">锦赞 · 9 <span>×</span></button>
          <button class="terminal-tab active">香港 · 1 <span>×</span></button>
          <button class="terminal-tab">香港 · 2 <span>×</span></button>
        </div>
        <div class="inline-fields">
          <button class="ui-btn ui-btn--primary" type="button">＋ 新终端</button>
        </div>
      </div>
      <div class="terminal-layout">
        <aside class="terminal-shortcuts">
          <div class="shortcut-header"><strong>快捷命令</strong>
            <button class="ui-btn ui-btn--sm" type="button">收起</button></div>
          <div class="shortcut-section">
            <button class="shortcut-heading" type="button">常用 <span>−</span></button>
            <div class="shortcut-list">
              <div class="shortcut-row">
                <button class="shortcut-command" type="button">ffd</button>
                <div class="shortcut-actions">
                  <button type="button">↑</button><button type="button">↓</button>
                  <button type="button">✎</button><button type="button">×</button>
                </div>
              </div>
              <div class="shortcut-row">
                <button class="shortcut-command" type="button">列表</button>
                <div class="shortcut-actions">
                  <button type="button">↑</button><button type="button">↓</button>
                  <button type="button">✎</button><button type="button">×</button>
                </div>
              </div>
              <button class="add-favorite" type="button">＋ 添加常用命令</button>
            </div>
          </div>
          <div class="shortcut-section history-section">
            <button class="shortcut-heading" type="button">记录 <span>−</span></button>
            <div class="shortcut-list">
              ${Array.from({ length: 120 }, (_, i) => `<div class="history-command">命令 ${i} · echo something-long-${i}</div>`).join('')}
              <div class="shortcut-footnote">双击执行 · 右键添加到常用</div>
            </div>
          </div>
        </aside>
        <div class="terminal-main">
          <div class="terminal-screen" style="background:#10182b;height:100%"></div>
        </div>
      </div>`;
    host.appendChild(probe);

    const tabs = [...probe.querySelectorAll('.terminal-tab')].map((el) => ({
      h: el.getBoundingClientRect().height,
      top: Math.round(el.getBoundingClientRect().top),
    }));
    const actionBtn = probe.querySelector('.shortcut-actions button').getBoundingClientRect();
    const list = probe.querySelector('.history-section .shortcut-list');
    const aside = probe.querySelector('.terminal-shortcuts');
    const asideRect = aside.getBoundingClientRect();
    const listRect = list.getBoundingClientRect();
    const result = {
      tabHeights: tabs.map((t) => t.h),
      tabTops: tabs.map((t) => t.top),
      actionButtonSize: [actionBtn.width, actionBtn.height],
      listOverflowY: getComputedStyle(list).overflowY,
      listMaxHeight: getComputedStyle(list).maxHeight,
      listScrollHeight: list.scrollHeight,
      listClientHeight: list.clientHeight,
      // 列表底部与侧栏底部的差距（应接近 0，表示没有留白）
      bottomGap: Math.round(asideRect.bottom - listRect.bottom),
    };
    return result;
  });
  console.log('终端测量:', JSON.stringify(metrics));
  await page.screenshot({ path: path.join(outDir, '07b-terminal-filled.png') });
  console.log('截图:', path.join(outDir, '07b-terminal-filled.png'));
} finally {
  await application.close();
}
