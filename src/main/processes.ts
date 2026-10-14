import { spawn, type ChildProcess } from 'node:child_process';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { Store } from './store';
import { AppError, redact } from '../shared/errors';
import type { Runtime, Instance } from '../shared/types';
import { clientConfig, frpAdapter } from './frp';

// 不经过 shell 执行本地程序，路径含空格时也无需拼接命令。
export function execute(file: string, args: string[], timeout = 15000): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { windowsHide: true });
    let output = '';
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      error ? reject(error) : resolve(output.trim());
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new AppError('程序执行超时，请检查安装包或配置。'));
    }, timeout);
    for (const stream of [child.stdout, child.stderr])
      stream?.on('data', (chunk) => {
        output = (output + String(chunk)).slice(-65536);
      });
    child.on('error', (error) => finish(error));
    child.on('close', (code) =>
      finish(code === 0 ? undefined : new AppError(output || `程序退出（${code}）。`)),
    );
  });
}
export class Processes {
  private children = new Map<string, ChildProcess>();
  private runtimes = new Map<string, Runtime>();
  private logs = new Map<string, string[]>();
  private busy = new Set<string>();
  private closing = false;
  constructor(
    private store: Store,
    private changed: () => void,
  ) {}
  status(id: string): Runtime {
    return this.runtimes.get(id) ?? { status: 'stopped', message: '未启动', proxies: {} };
  }
  allStatus() {
    return Object.fromEntries(this.store.data.instances.map((i) => [i.id, this.status(i.id)]));
  }
  log(id: string) {
    return (this.logs.get(id) ?? []).join('\n');
  }
  running(id: string) {
    return this.children.has(id) || this.busy.has(id);
  }
  private append(id: string, content: string) {
    const items = this.logs.get(id) ?? [];
    items.push(redact(content, this.store.allSecrets()).slice(0, 16384));
    this.logs.set(id, items.slice(-500));
    this.changed();
  }
  async preview(instance: Instance) {
    const server = this.store.server(instance.serverId);
    return instance.mode === 'raw'
      ? instance.rawConfig
      : clientConfig(instance, server, this.store.secret(`server:${server.id}:token`));
  }
  async start(id: string) {
    if (this.closing) throw new AppError('应用正在退出，不能启动新实例。');
    if (this.running(id)) throw new AppError('实例正在运行或正在启动。');
    this.busy.add(id);
    try {
      const instance = this.store.instance(id);
      const server = this.store.server(instance.serverId);
      const version = this.store.version(instance.versionKey);
      const platform = process.platform === 'win32' ? 'windows' : process.platform;
      const arch = process.arch === 'x64' ? 'amd64' : process.arch;
      if (version.platform !== platform || version.arch !== arch)
        throw new AppError('所选安装包与本机平台或架构不匹配。');
      if (instance.mode === 'form' && !frpAdapter.supportsForm(version.version))
        throw new AppError('此旧版本不支持表单配置，请使用高级原始配置。');
      const config =
        instance.mode === 'raw'
          ? this.store.secret(`instance:${id}:rawConfig`)
          : clientConfig(instance, server, this.store.secret(`server:${server.id}:token`));
      if (!config.trim()) throw new AppError('配置内容为空。');
      const folder = path.join(this.store.root, 'runtime', id);
      await mkdir(folder, { recursive: true, mode: 0o700 });
      const configPath = path.join(
        folder,
        `frpc.${instance.mode === 'raw' ? instance.rawFormat : 'toml'}`,
      );
      await writeFile(configPath, config, { mode: 0o600 });
      const binary = path.join(version.directory, frpAdapter.binary('client', platform));
      const runtime: Runtime = {
        status: 'starting',
        message: '正在校验配置',
        proxies: Object.fromEntries(instance.proxies.map((p) => [p.id, '等待注册'])),
      };
      this.runtimes.set(id, runtime);
      this.changed();
      if (frpAdapter.supportsForm(version.version)) {
        try {
          await execute(binary, ['verify', '-c', configPath]);
        } catch (error) {
          await rm(folder, { recursive: true, force: true });
          throw error;
        }
      } else this.append(id, '旧版本未提供已验证的预校验能力，将由 FRP 启动检查原始配置。');
      if (version.version !== server.deployment?.version && server.deployment)
        this.append(
          id,
          `版本提示：客户端 ${version.version} / 服务端 ${server.deployment.version}，连接兼容性以运行结果为准。`,
        );
      if (this.closing) {
        await rm(folder, { recursive: true, force: true });
        throw new AppError('应用正在退出，已取消启动。');
      }
      const child = spawn(binary, ['-c', configPath], { windowsHide: true, cwd: folder });
      this.children.set(id, child);
      runtime.status = 'running';
      runtime.message = '进程已运行，等待 FRP 登录与代理注册';
      const pending: Record<string, string> = { stdout: '', stderr: '' };
      const consume = (key: string, chunk: Buffer) => {
        pending[key] += chunk.toString();
        const lines = pending[key].split(/\r?\n/);
        pending[key] = lines.pop()!.slice(-16384);
        for (const line of lines) {
          this.append(id, line);
          if (/login to server success/i.test(line)) {
            runtime.status = 'connected';
            runtime.message = 'FRP 已连接，代理状态见各规则';
          }
          if (
            /login.*(fail|error)|connect to server error|reconnect.*error|try to connect to server|session.*closed|connection.*closed/i.test(
              line,
            )
          ) {
            runtime.status = 'running';
            runtime.message = '连接失败，FRP 正在重试；请检查日志、令牌和端口';
            for (const p of instance.proxies) runtime.proxies[p.id] = '等待重新连接';
          }
          for (const p of instance.proxies)
            if (line.includes(`[${id}_${p.name}]`)) {
              if (/start proxy success/i.test(line)) runtime.proxies[p.id] = '已注册';
              else if (/start error|start proxy error|start proxy fail/i.test(line))
                runtime.proxies[p.id] = '注册失败，请查看日志';
            }
        }
        this.changed();
      };
      child.stdout?.on('data', (chunk) => consume('stdout', chunk));
      child.stderr?.on('data', (chunk) => consume('stderr', chunk));
      child.on('error', (error) => {
        this.append(id, error.message);
        runtime.status = 'error';
        runtime.message = '客户端启动失败，请查看日志';
        this.changed();
      });
      child.on('close', (code) => {
        this.children.delete(id);
        runtime.status = code === 0 || code === null ? 'stopped' : 'error';
        runtime.message = `进程已退出（${code ?? '终止'}）`;
        for (const p of instance.proxies) runtime.proxies[p.id] = '已停止';
        void rm(folder, { recursive: true, force: true }).catch(() => {});
        this.changed();
      });
      this.changed();
    } catch (error) {
      this.runtimes.set(id, {
        status: 'error',
        message: redact(
          error instanceof Error ? error.message : String(error),
          this.store.allSecrets(),
        ),
        proxies: {},
      });
      this.changed();
      throw error;
    } finally {
      this.busy.delete(id);
    }
  }
  async stop(id: string) {
    if (this.busy.has(id)) throw new AppError('实例正在启动，请稍后停止。');
    const child = this.children.get(id);
    if (!child) return;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
      child.once('close', () => {
        clearTimeout(timer);
        resolve();
      });
      child.kill('SIGTERM');
    });
  }
  async shutdown() {
    this.closing = true;
    // 等待正在校验的启动任务结束，防止退出期间产生新的子进程。
    while (this.busy.size) await new Promise((resolve) => setTimeout(resolve, 50));
    await Promise.all([...this.children.keys()].map((id) => this.stop(id)));
  }
}
