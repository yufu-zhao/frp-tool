import { writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import { Store } from '../src/main/store';
import { Remote, quote } from '../src/main/remote';
import { serverSchema } from '../src/shared/types';

async function main() {
  const host = process.env.INTRANET_TEST_HOST;
  const keyPath = process.env.INTRANET_TEST_KEY;
  if (!host || !keyPath) throw new Error('需要显式提供测试服务器与密钥路径。');
  const root = process.env.INTRANET_SMOKE_DATA || '/private/tmp/intranet-frp-real-smoke';
  const store = new Store(root, {
    available: () => false,
    encrypt: () => Buffer.alloc(0),
    decrypt: () => '',
  });
  await store.load();
  const trusted = execFileSync('ssh-keygen', ['-F', host], { encoding: 'utf8' })
    .split('\n')
    .filter((line) => line && !line.startsWith('#'))
    .map((line) =>
      createHash('sha256')
        .update(Buffer.from(line.split(/\s+/)[2], 'base64'))
        .digest('hex'),
    );
  const remote = new Remote(
    store,
    async (_server, hash) => trusted.includes(hash),
    () => {},
  );
  const user = `frptest${Date.now().toString().slice(-8)}`;
  const admin = serverSchema.parse({
    id: 'process-admin',
    name: '测试管理连接',
    host,
    username: 'root',
    sshPort: 22,
    auth: 'key',
    keyPath,
    publicHost: host,
    frpPort: 7000,
  });
  await store.saveServer(admin);
  await remote.connect(admin.id);
  const checks: Record<string, unknown> = { startedAt: new Date().toISOString(), user };
  let created = false;
  const id = `process-user-${user}`;
  try {
    const publicKey = execFileSync('ssh-keygen', ['-y', '-f', keyPath], {
      encoding: 'utf8',
    }).trim();
    await remote.exec(
      admin.id,
      `useradd --create-home --shell /bin/sh ${quote(user)} && install -d -m 700 -o ${quote(user)} -g ${quote(user)} ${quote(`/home/${user}/.ssh`)} && printf '%s\\n' ${quote(publicKey)} > ${quote(`/home/${user}/.ssh/authorized_keys`)} && chmod 600 ${quote(`/home/${user}/.ssh/authorized_keys`)} && chown ${quote(`${user}:${user}`)} ${quote(`/home/${user}/.ssh/authorized_keys`)}`,
    );
    created = true;
    const server = serverSchema.parse({
      ...admin,
      id,
      username: user,
      name: '普通用户验证',
      frpPort: 17000,
      httpPort: 18082,
      httpsPort: 18444,
      token: randomBytes(24).toString('hex'),
    });
    await store.saveServer(server);
    await remote.connect(id);
    checks.environment = await remote.detect(id);
    store.server(id).configMode = 'raw';
    store.putSecret(`server:${id}:rawConfig`, 'this is invalid TOML = [');
    try {
      await remote.deploy(id, '0.71.0_linux_amd64', 'process');
      throw new Error('无效配置未被拒绝');
    } catch (error) {
      if ((error as Error).message === '无效配置未被拒绝') throw error;
      checks.failedDeployRolledBack = await remote.exec(
        id,
        `test ! -e ${quote(`/home/${user}/.local/share/intranet-frp/${id}/frps`)} && echo cleaned`,
      );
    }
    store.server(id).configMode = 'form';
    checks.autoDeployment = await remote.deploy(id, '0.71.0_linux_amd64');
    checks.userServiceStart = await remote.control(id, 'start');
    if (checks.userServiceStart !== 'active' && checks.userServiceStart !== 'running')
      throw new Error('普通用户自动运行模式启动失败');
    await remote.control(id, 'stop');
    await remote.uninstall(id, false);
    checks.deploy = await remote.deploy(id, '0.71.0_linux_amd64', 'process');
    if (store.server(id).deployment?.mode !== 'process')
      throw new Error('测试用户环境未进入预期后台进程模式');
    checks.start = await remote.control(id, 'start');
    if (checks.start !== 'running') throw new Error('后台进程未运行');
    remote.disconnect(id);
    await remote.connect(id);
    checks.disconnectKeptService = await remote.status(id);
    checks.logs = (await remote.logs(id)).includes('frps started successfully');
    // 接管错误 PID 不能误停同一用户的其他进程。
    const d = store.server(id).deployment!;
    await remote.exec(
      id,
      `cp ${quote(d.pidFile)} ${quote(`${d.pidFile}.original`)}; sleep 120 >/dev/null 2>&1 < /dev/null & echo $! > ${quote(d.pidFile)}`,
    );
    try {
      await remote.control(id, 'stop');
      throw new Error('错误 PID 未被阻止');
    } catch (error) {
      if (!(error as Error).message.includes('其他进程')) throw error;
      checks.wrongPidBlocked = true;
    }
    await remote.exec(
      id,
      `kill "$(cat ${quote(d.pidFile)})"; mv ${quote(`${d.pidFile}.original`)} ${quote(d.pidFile)}`,
    );
    checks.stop = await remote.control(id, 'stop');
    checks.restart = await remote.control(id, 'restart');
    if (checks.restart !== 'running') throw new Error('后台重启失败');
    const adopted = { ...store.server(id).deployment! };
    await remote.detach(id);
    await remote.exec(id, `rm -f -- ${quote(adopted.pidFile)}`);
    await remote.adopt(id, adopted);
    checks.pidRecoveredOnAdopt = await remote.status(id);
    if (checks.pidRecoveredOnAdopt !== 'running') throw new Error('进程接管没有恢复正确 PID');
    await remote.control(id, 'stop');
    await remote.uninstall(id, true);
    checks.uninstalled = true;
    checks.result = 'passed';
  } catch (error) {
    checks.result = 'failed';
    checks.error = (error as Error).message;
    throw error;
  } finally {
    if (remote.connected(id)) {
      await remote.control(id, 'stop').catch(() => {});
      remote.disconnect(id);
    }
    if (created)
      await remote
        .exec(admin.id, `pkill -u ${quote(user)} || true; userdel -r ${quote(user)}`)
        .catch(() => {});
    remote.closeAll();
    checks.finishedAt = new Date().toISOString();
    await writeFile(path.join(root, 'process-result.json'), JSON.stringify(checks, null, 2));
    console.log(JSON.stringify(checks, null, 2));
  }
}
void main().catch((error) => {
  console.error((error as Error).message);
  process.exitCode = 1;
});
