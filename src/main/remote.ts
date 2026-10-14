import { Client, type SFTPWrapper } from 'ssh2';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { Store } from './store';
import { AppError, redact } from '../shared/errors';
import type { Server, Deployment, HostInfo } from '../shared/types';
import { serverConfig, frpAdapter } from './frp';

// 所有远程命令参数都按 POSIX shell 单引号规则转义。
export const quote = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;
export function remotePath(value: string): string {
  if (
    !value.startsWith('/') ||
    value === '/' ||
    /[\n\r\0%]/.test(value) ||
    value.split('/').includes('..')
  )
    throw new AppError('远程路径必须为绝对路径，不得包含换行、百分号或上级目录。');
  return value;
}
export class Remote {
  private connections = new Map<string, Client>();
  private serviceStates = new Map<string, { value: string; at: number }>();
  private rootUsers = new Set<string>();
  private connecting = new Set<string>();
  private busy = new Set<string>();
  constructor(
    private store: Store,
    private confirmHost: (server: Server, fingerprint: string) => Promise<boolean>,
    private changed: () => void,
  ) {}
  connected(id: string) {
    return this.connections.has(id);
  }
  allStatus() {
    return Object.fromEntries(
      this.store.data.servers.map((s) => [
        s.id,
        this.connected(s.id)
          ? 'connected'
          : this.connecting.has(s.id)
            ? 'connecting'
            : 'disconnected',
      ]),
    );
  }
  async connect(id: string) {
    if (this.connected(id)) return;
    if (this.connecting.has(id)) throw new AppError('SSH 正在连接。');
    this.connecting.add(id);
    this.changed();
    const server = this.store.server(id);
    const client = new Client();
    let fingerprint = '';
    try {
      const key = server.auth === 'key' ? await readFile(server.keyPath) : undefined;
      await new Promise<void>((resolve, reject) => {
        client.once('ready', resolve);
        client.once('error', reject);
        client.once('close', () => reject(new AppError('SSH 连接在认证完成前关闭。')));
        client.connect({
          host: server.host,
          port: server.sshPort,
          username: server.username,
          password:
            server.auth === 'password' ? this.store.secret(`server:${id}:password`) : undefined,
          privateKey: key,
          passphrase: key ? this.store.secret(`server:${id}:passphrase`) || undefined : undefined,
          readyTimeout: 25000,
          keepaliveInterval: 15000,
          keepaliveCountMax: 3,
          hostVerifier: (key: Buffer, callback: (valid: boolean) => void) => {
            const hash = createHash('sha256').update(key).digest('hex');
            fingerprint = hash;
            if (server.fingerprint && server.fingerprint !== hash) {
              callback(false);
              reject(
                new AppError(
                  'SSH 主机指纹变化，已阻止连接。请独立核实服务器身份后重新添加服务器。',
                  'HOST_CHANGED',
                ),
              );
            } else if (server.fingerprint) callback(true);
            else this.confirmHost(server, hash).then(callback, () => callback(false));
          },
        });
      });
      server.fingerprint = fingerprint;
      await this.store.persist();
      this.connections.set(id, client);
      if ((await this.exec(id, 'id -u')) === '0') this.rootUsers.add(id);
      else this.rootUsers.delete(id);
      client.on('error', () => {
        if (this.connections.get(id) === client) this.connections.delete(id);
        this.changed();
      });
      client.on('close', () => {
        if (this.connections.get(id) === client) this.connections.delete(id);
        this.changed();
      });
    } catch (error) {
      this.connections.delete(id);
      client.end();
      throw error;
    } finally {
      this.connecting.delete(id);
      this.changed();
    }
  }
  async runtimeServices() {
    for (const server of this.store.data.servers) {
      if (
        server.deployment &&
        this.connected(server.id) &&
        Date.now() - (this.serviceStates.get(server.id)?.at ?? 0) > 5000
      ) {
        await this.status(server.id).catch(() => {
          this.serviceStates.set(server.id, { value: 'unknown', at: Date.now() });
        });
      }
    }
    return Object.fromEntries(
      this.store.data.servers.map((s) => [
        s.id,
        this.connected(s.id) ? (this.serviceStates.get(s.id)?.value ?? 'unknown') : 'unknown',
      ]),
    );
  }
  disconnect(id: string) {
    if (this.busy.has(id)) throw new AppError('服务器正在执行操作，请完成后断开。');
    this.connections.get(id)?.end();
    this.connections.delete(id);
    this.changed();
  }
  closeAll() {
    for (const client of this.connections.values()) client.end();
    this.connections.clear();
  }
  private connection(id: string) {
    const c = this.connections.get(id);
    if (!c) throw new AppError('请先连接服务器 SSH。');
    return c;
  }
  async locked<T>(id: string, operation: () => Promise<T>): Promise<T> {
    if (this.busy.has(id)) throw new AppError('此服务器正在执行其他操作，请等待完成。');
    this.busy.add(id);
    try {
      return await operation();
    } finally {
      this.busy.delete(id);
    }
  }
  exec(id: string, command: string, timeout = 30000): Promise<string> {
    return new Promise((resolve, reject) => {
      const client = this.connection(id);
      let output = '';
      let done = false;
      let active: { close(): void } | undefined;
      const finish = (error?: Error) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        error ? reject(error) : resolve(output.trim());
      };
      const timer = setTimeout(() => {
        active?.close();
        finish(new AppError('远程操作超时，服务状态可能已改变，请刷新状态后再操作。'));
      }, timeout);
      client.exec(command, (error, stream) => {
        if (error) return finish(error);
        active = stream;
        if (done) {
          stream.close();
          return;
        }
        stream.on('data', (chunk: Buffer) => {
          output = (output + chunk.toString()).slice(-131072);
        });
        stream.stderr.on('data', (chunk: Buffer) => {
          output = (output + chunk.toString()).slice(-131072);
        });
        stream.on('error', finish);
        stream.on('close', (code: number | undefined) =>
          finish(
            code === 0
              ? undefined
              : new AppError(
                  redact(output, this.store.allSecrets()) || `远程命令退出（${code}）。`,
                ),
          ),
        );
      });
    });
  }
  async detect(id: string): Promise<HostInfo> {
    const out = await this.exec(
      id,
      `test "$(uname -s)" = Linux || { echo '仅支持 Linux 服务器'; exit 1; }; printf '%s\\n' "$HOME" "$(uname -m)" "$(id -u)"; if test -d /run/systemd/system; then echo yes; else echo no; fi; if systemctl --user show-environment >/dev/null 2>&1; then echo yes; else echo no; fi; if sudo -n true >/dev/null 2>&1; then echo yes; else echo no; fi; ss -lntu 2>/dev/null || true`,
    );
    const [home, machine, uid, systemd, userSystemd, sudo, ...ports] = out.split('\n');
    const arch =
      machine === 'x86_64'
        ? 'amd64'
        : machine === 'aarch64' || machine === 'arm64'
          ? 'arm64'
          : machine;
    return {
      home: remotePath(home),
      arch,
      root: uid === '0',
      systemd: systemd === 'yes',
      userSystemd: userSystemd === 'yes',
      sudo: sudo === 'yes',
      ports: ports.join('\n'),
    };
  }
  private sftp(id: string) {
    return new Promise<SFTPWrapper>((resolve, reject) =>
      this.connection(id).sftp((e, sftp) => (e ? reject(e) : resolve(sftp))),
    );
  }
  private async upload(id: string, local: string, destination: string) {
    const sftp = await this.sftp(id);
    try {
      await new Promise<void>((resolve, reject) =>
        sftp.fastPut(local, remotePath(destination), (e) => (e ? reject(e) : resolve())),
      );
    } finally {
      sftp.end();
    }
  }
  private async write(id: string, destination: string, content: string) {
    const sftp = await this.sftp(id);
    const temporary = `${remotePath(destination)}.tmp-${randomUUID()}`;
    try {
      await new Promise<void>((resolve, reject) => {
        const stream = sftp.createWriteStream(temporary, { mode: 0o600 });
        stream.on('error', reject);
        stream.on('close', resolve);
        stream.end(content);
      });
      await this.exec(id, `mv -- ${quote(temporary)} ${quote(destination)}`);
    } finally {
      sftp.end();
      await this.exec(id, `rm -f -- ${quote(temporary)}`).catch(() => {});
    }
  }
  private deployment(id: string) {
    const d = this.store.server(id).deployment;
    if (!d) throw new AppError('请先安装或接管服务端。');
    return d;
  }
  private serviceCommand(id: string, d: Deployment, verb: string) {
    return `${d.mode === 'system' ? `${this.rootUsers.has(id) ? '' : 'sudo -n '}systemctl` : 'systemctl --user'} ${verb} ${quote(d.service)}`;
  }
  private checkedPid(d: Deployment) {
    // 只允许操作与记录的二进制及配置同时匹配的 Linux 进程。
    return `pid=$(cat ${quote(d.pidFile)} 2>/dev/null || true); case "$pid" in ''|*[!0-9]*) exit 1;; esac; test "$pid" -gt 1 || exit 1; kill -0 "$pid" 2>/dev/null || exit 1; test "$(readlink -f /proc/"$pid"/exe)" = "$(readlink -f ${quote(d.binary)})" || exit 1; tr '\\0' '\\n' < /proc/"$pid"/cmdline | grep -Fx -- ${quote(d.config)} >/dev/null || exit 1;`;
  }
  async status(id: string) {
    const d = this.deployment(id);
    let value: string;
    if (d.mode !== 'process')
      value = await this.exec(
        id,
        `${d.mode === 'system' ? 'systemctl' : 'systemctl --user'} is-active ${quote(d.service)} || true`,
      );
    else {
      try {
        await this.exec(id, this.checkedPid(d) + ' echo running');
        value = 'running';
      } catch {
        value = await this.exec(
          id,
          `if test -s ${quote(d.pidFile)}; then pid=$(cat ${quote(d.pidFile)}); case \"$pid\" in ''|*[!0-9]*) echo pid-mismatch;; *) if kill -0 \"$pid\" 2>/dev/null; then echo pid-mismatch; else echo stopped; fi;; esac; else echo stopped; fi`,
        );
      }
    }
    this.serviceStates.set(id, { value, at: Date.now() });
    return value;
  }
  private config(id: string) {
    const server = this.store.server(id);
    const value =
      server.configMode === 'raw'
        ? this.store.secret(`server:${id}:rawConfig`)
        : serverConfig(server, this.store.secret(`server:${id}:token`));
    if (!value.trim()) throw new AppError('服务端配置为空。');
    return value;
  }
  async deploy(
    id: string,
    key: string,
    requestedMode: 'auto' | 'system' | 'user' | 'process' = 'auto',
  ) {
    return this.locked(id, async () => {
      const server = this.store.server(id);
      if (server.deployment) throw new AppError('已有部署，请使用切换版本或先解除管理。');
      const info = await this.detect(id);
      const version = this.store.version(key);
      if (version.platform !== 'linux' || version.arch !== info.arch)
        throw new AppError(`请选择 Linux/${info.arch} 安装包。`);
      if (server.configMode === 'form' && !frpAdapter.supportsForm(version.version))
        throw new AppError('此版本只能使用原始配置部署。');
      if (requestedMode === 'system' && (!info.systemd || (!info.root && !info.sudo)))
        throw new AppError('系统服务模式需要 systemd 和 root 或免交互 sudo 权限。');
      if (requestedMode === 'user' && !info.userSystemd)
        throw new AppError('此 SSH 会话无法访问用户 systemd，请选择后台进程模式。');
      const folder = remotePath(`${info.home}/.local/share/intranet-frp/${id}`);
      const d: Deployment = {
        binary: `${folder}/frps`,
        config: `${folder}/frps.${server.configMode === 'raw' ? server.rawFormat : 'toml'}`,
        log: `${folder}/frps.log`,
        pidFile: `${folder}/frps.pid`,
        mode:
          requestedMode === 'auto'
            ? info.systemd && (info.root || info.sudo)
              ? 'system'
              : info.userSystemd
                ? 'user'
                : 'process'
            : requestedMode,
        service: `intranet-frps-${id}.service`,
        managed: true,
        version: version.version,
        versionKey: key,
      };
      const content = this.config(id);
      if (server.configMode === 'form') {
        for (const port of [server.frpPort, server.httpPort, server.httpsPort]) {
          if (info.ports.split('\n').some((line) => new RegExp(`:${port}(?:\\s|$)`).test(line)))
            throw new AppError(`服务器端口 ${port} 已占用，请更换端口或接管已有服务。`);
        }
      }
      const privilege = d.mode === 'system' && !info.root ? 'sudo -n ' : '';
      // 检查现有目录，避免覆盖先前失败部署或其他安装。
      await this.exec(
        id,
        `test ! -e ${quote(d.binary)} || { echo '安装目录已有程序，请接管已有部署或选择其他服务器配置'; exit 1; }; mkdir -p -- ${quote(folder)}; chmod 700 -- ${quote(folder)}`,
      );
      let installedUnit = '';
      try {
        await this.upload(id, path.join(version.directory, 'frps'), d.binary);
        await this.exec(id, `chmod 700 -- ${quote(d.binary)}`);
        const actual = await this.exec(id, `${quote(d.binary)} -v`);
        if (actual.trim().replace(/^v/, '') !== version.version)
          throw new AppError('服务端实际版本不匹配，部署已暂停，请检查安装目录。');
        await this.write(id, d.config, content);
        if (frpAdapter.supportsForm(version.version))
          await this.exec(id, `${quote(d.binary)} verify -c ${quote(d.config)}`);
        if (d.mode !== 'process') {
          const unitPath = `${folder}/${d.service}`;
          const escapeUnit = (p: string) => p.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
          const unit = `[Unit]\nDescription=Intranet FRP Server\nAfter=network.target\n\n[Service]\nType=simple\n${d.mode === 'system' ? `User=${await this.exec(id, 'id -un')}\n` : ''}ExecStart="${escapeUnit(d.binary)}" -c "${escapeUnit(d.config)}"\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=${d.mode === 'system' ? 'multi-user.target' : 'default.target'}\n`;
          await this.write(id, unitPath, unit);
          const units =
            d.mode === 'system' ? '/etc/systemd/system' : `${info.home}/.config/systemd/user`;
          const targetUnit = `${units}/${d.service}`;
          await this.exec(
            id,
            `${privilege}test ! -e ${quote(targetUnit)} || { echo '服务单元已存在，未覆盖'; exit 1; }`,
          );
          installedUnit = targetUnit;
          await this.exec(
            id,
            `${privilege}mkdir -p -- ${quote(units)} && ${privilege}cp -- ${quote(unitPath)} ${quote(`${units}/${d.service}`)} && ${privilege}systemctl ${d.mode === 'user' ? '--user ' : ''}daemon-reload`,
          );
        }
        server.deployment = d;
        await this.store.persist();
        this.changed();
        return {
          deployment: d,
          note:
            d.mode === 'process'
              ? '普通后台进程模式，不保证开机启动；低于 1024 的端口可能需要额外权限。'
              : d.mode === 'user'
                ? '用户 systemd 服务，注销后运行取决于服务器 linger 配置。'
                : 'systemd 服务已安装，可通过启用开机启动单独设置。',
        };
      } catch (error) {
        server.deployment = undefined;
        if (installedUnit)
          await this.exec(
            id,
            `${privilege}rm -f -- ${quote(installedUnit)} && ${privilege}systemctl ${d.mode === 'user' ? '--user ' : ''}daemon-reload`,
          ).catch(() => {});
        await this.exec(
          id,
          `rm -f -- ${[d.binary, d.config, `${folder}/${d.service}`].map(quote).join(' ')}`,
        ).catch(() => {});
        throw error;
      }
    });
  }
  private async checkUnit(id: string, d: Deployment) {
    if (d.mode === 'process') return;
    const command = `${d.mode === 'system' ? 'systemctl' : 'systemctl --user'} show ${quote(d.service)} -p ExecStart --value`;
    const start = await this.exec(id, command);
    if (!start.includes(`path=${d.binary} ;`) || !start.includes(`-c ${d.config} `))
      throw new AppError(
        '服务单元的程序或配置与部署记录不一致，已阻止操作。仅支持直接运行 frps -c 配置路径的服务。',
      );
  }
  async adopt(id: string, input: Deployment) {
    return this.locked(id, async () => {
      const server = this.store.server(id);
      if (server.deployment) throw new AppError('请先解除当前部署的管理。');
      for (const field of ['binary', 'config', 'log', 'pidFile'] as const) remotePath(input[field]);
      const version = await this.exec(id, `${quote(input.binary)} -v`);
      if (!/^v?\d+\.\d+\.\d+/.test(version)) throw new AppError('此程序未返回有效的 FRP 版本。');
      await this.exec(id, `test -r ${quote(input.config)} || { echo '配置文件不可读'; exit 1; }`);
      if (input.mode !== 'process') await this.checkUnit(id, input);
      if (input.mode === 'process') {
        const matches = await this.exec(
          id,
          `for entry in /proc/[0-9]*/exe; do test \"$(readlink -f \"$entry\" 2>/dev/null)\" = \"$(readlink -f ${quote(input.binary)})\" || continue; procdir=\"\${entry%/exe}\"; tr '\\0' '\\n' < \"$procdir/cmdline\" 2>/dev/null | grep -Fx -- ${quote(input.config)} >/dev/null && echo \"\${procdir##*/}\"; done; true`,
        );
        const pids = matches.split('\n').filter(Boolean);
        if (pids.length > 1)
          throw new AppError('多个进程使用同一程序和配置，请先保留一个进程再接管。');
        if (pids.length === 1) {
          const previous = await this.exec(
            id,
            `cat -- ${quote(input.pidFile)} 2>/dev/null || true`,
          );
          if (previous && previous !== pids[0])
            throw new AppError('PID 文件与实际进程不一致，已阻止接管。');
          if (!previous) await this.write(id, input.pidFile, `${pids[0]}\n`);
        }
      }
      server.deployment = {
        ...input,
        managed: false,
        version: version.trim().replace(/^v/, ''),
        versionKey: '',
      };
      await this.store.persist();
      this.changed();
      return server.deployment;
    });
  }
  async apply(id: string) {
    return this.locked(id, async () => {
      const d = this.deployment(id);
      const content = this.config(id);
      const server = this.store.server(id);
      const format = server.configMode === 'raw' ? server.rawFormat : 'toml';
      if (path.posix.extname(d.config) !== `.${format}`)
        throw new AppError('配置格式与当前部署的文件扩展名不同，请保持原格式或重新部署。');
      const candidate = `${d.config}.candidate-${randomUUID()}${path.posix.extname(d.config)}`;
      await this.write(id, candidate, content);
      try {
        if (frpAdapter.supportsForm(d.version))
          await this.exec(id, `${quote(d.binary)} verify -c ${quote(candidate)}`);
        await this.exec(
          id,
          `cp -p -- ${quote(d.config)} ${quote(`${d.config}.bak-${Date.now()}`)} && mv -- ${quote(candidate)} ${quote(d.config)}`,
        );
      } finally {
        await this.exec(id, `rm -f -- ${quote(candidate)}`).catch(() => {});
      }
      return '配置已应用并备份；正在运行的服务保持原配置，请明确点击重启。';
    });
  }
  async changeVersion(id: string, key: string) {
    return this.locked(id, async () => {
      const d = this.deployment(id);
      const version = this.store.version(key);
      const info = await this.detect(id);
      if (version.platform !== 'linux' || version.arch !== info.arch)
        throw new AppError('版本平台或架构不匹配。');
      if (/^(running|active)/.test(await this.status(id)))
        throw new AppError('请先停止服务再切换版本。');
      const candidate = `${d.binary}.candidate-${randomUUID()}`;
      try {
        await this.upload(id, path.join(version.directory, 'frps'), candidate);
        await this.exec(id, `chmod 700 -- ${quote(candidate)}`);
        const actual = await this.exec(id, `${quote(candidate)} -v`);
        if (actual.trim().replace(/^v/, '') !== version.version)
          throw new AppError('实际版本不匹配。');
        if (frpAdapter.supportsForm(version.version))
          await this.exec(id, `${quote(candidate)} verify -c ${quote(d.config)}`);
        await this.exec(
          id,
          `cp -p -- ${quote(d.binary)} ${quote(`${d.binary}.bak-${Date.now()}`)} && cp -p -- ${quote(d.config)} ${quote(`${d.config}.bak-${Date.now()}`)} && mv -- ${quote(candidate)} ${quote(d.binary)}`,
        );
        d.version = version.version;
        d.versionKey = key;
        await this.store.persist();
        this.changed();
        return '版本已切换，原配置未转换；请明确启动服务。';
      } finally {
        await this.exec(id, `rm -f -- ${quote(candidate)}`).catch(() => {});
      }
    });
  }
  async control(id: string, action: 'start' | 'stop' | 'restart' | 'enable' | 'disable') {
    return this.locked(id, async () => {
      const d = this.deployment(id);
      if (d.mode !== 'process') {
        await this.checkUnit(id, d);
        await this.exec(id, this.serviceCommand(id, d, action));
        return this.status(id);
      }
      if (action === 'enable' || action === 'disable')
        throw new AppError('普通进程模式不提供开机启动。');
      const running = (await this.status(id)) === 'running';
      if (!running) {
        await this.exec(
          id,
          `if test -s ${quote(d.pidFile)}; then pid=$(cat ${quote(d.pidFile)}); case \"$pid\" in ''|*[!0-9]*) echo 'PID 文件无效，请人工检查'; exit 1;; esac; if kill -0 \"$pid\" 2>/dev/null; then echo 'PID 属于其他进程，已阻止操作'; exit 1; fi; fi`,
        );
      }
      if ((action === 'stop' || action === 'restart') && running) {
        await this.exec(
          id,
          `${this.checkedPid(d)} kill "$pid"; n=0; while kill -0 "$pid" 2>/dev/null && test "$n" -lt 10; do sleep 1; n=$((n+1)); done; if kill -0 "$pid" 2>/dev/null; then echo '进程未退出，请人工检查'; exit 1; fi; rm -f -- ${quote(d.pidFile)}`,
        );
      }
      if (action === 'start' && running) return 'running';
      if (action === 'start' || action === 'restart') {
        await this.exec(
          id,
          `umask 077; nohup ${quote(d.binary)} -c ${quote(d.config)} >> ${quote(d.log)} 2>&1 < /dev/null & echo $! > ${quote(d.pidFile)}; sleep 1`,
        );
      }
      return this.status(id);
    });
  }
  async logs(id: string) {
    const d = this.deployment(id);
    const out =
      d.mode === 'process'
        ? await this.exec(id, `tail -n 300 -- ${quote(d.log)}`)
        : await this.exec(
            id,
            `${d.mode === 'system' ? `${this.rootUsers.has(id) ? '' : 'sudo -n '}journalctl` : 'journalctl --user'} -u ${quote(d.service)} -n 300 --no-pager`,
          );
    return redact(out, this.store.allSecrets());
  }
  async readConfig(id: string) {
    const sftp = await this.sftp(id);
    try {
      return await new Promise<string>((resolve, reject) => {
        const chunks: Buffer[] = [];
        let size = 0;
        const stream = sftp.createReadStream(this.deployment(id).config);
        stream.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > 1048576) {
            stream.destroy();
            reject(new AppError('配置文件超过 1MB，未导入。'));
          } else chunks.push(chunk);
        });
        stream.on('error', reject);
        stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      });
    } finally {
      sftp.end();
    }
  }
  async backups(id: string) {
    const d = this.deployment(id);
    const sftp = await this.sftp(id);
    try {
      const result: { kind: 'binary' | 'config'; path: string; time: number }[] = [];
      for (const [kind, file] of [
        ['binary', d.binary],
        ['config', d.config],
      ] as const) {
        const entries = await new Promise<import('ssh2').FileEntryWithStats[]>((resolve, reject) =>
          sftp.readdir(path.posix.dirname(file), (error, list) =>
            error ? reject(error) : resolve(list),
          ),
        );
        const prefix = `${path.posix.basename(file)}.bak-`;
        for (const entry of entries)
          if (
            entry.attrs.isFile() &&
            entry.filename.startsWith(prefix) &&
            /^\d+$/.test(entry.filename.slice(prefix.length))
          )
            result.push({
              kind,
              path: path.posix.join(path.posix.dirname(file), entry.filename),
              time: Number(entry.filename.slice(prefix.length)),
            });
      }
      return result.sort((a, b) => b.time - a.time);
    } finally {
      sftp.end();
    }
  }
  async restore(id: string, backup: string) {
    return this.locked(id, async () => {
      const d = this.deployment(id);
      const match = (await this.backups(id)).find((item) => item.path === backup);
      if (!match) throw new AppError('备份不在当前部署的备份列表中。');
      if (/^(running|active)/.test(await this.status(id)))
        throw new AppError('请先停止服务再恢复备份。');
      const target = match.kind === 'binary' ? d.binary : d.config;
      const candidate = `${target}.restore-${randomUUID()}${match.kind === 'config' ? path.posix.extname(d.config) : ''}`;
      try {
        await this.exec(id, `cp -p -- ${quote(backup)} ${quote(candidate)}`);
        let restoredVersion = d.version;
        if (match.kind === 'binary') {
          restoredVersion = (await this.exec(id, `${quote(candidate)} -v`)).replace(/^v/, '');
          if (!/^\d+\.\d+\.\d+/.test(restoredVersion))
            throw new AppError('备份程序未返回有效版本。');
          if (frpAdapter.supportsForm(restoredVersion))
            await this.exec(id, `${quote(candidate)} verify -c ${quote(d.config)}`);
        } else if (frpAdapter.supportsForm(d.version))
          await this.exec(id, `${quote(d.binary)} verify -c ${quote(candidate)}`);
        await this.exec(
          id,
          `cp -p -- ${quote(target)} ${quote(`${target}.bak-${Date.now()}`)} && mv -- ${quote(candidate)} ${quote(target)}`,
        );
        if (match.kind === 'binary') {
          const info = await this.detect(id);
          d.version = restoredVersion;
          d.versionKey =
            this.store.data.versions.find(
              (v) =>
                v.version === restoredVersion && v.platform === 'linux' && v.arch === info.arch,
            )?.key ?? '';
          await this.store.persist();
          this.changed();
        }
        return '备份已校验并恢复，恢复前的文件已另存备份；请明确启动服务。';
      } finally {
        await this.exec(id, `rm -f -- ${quote(candidate)}`).catch(() => {});
      }
    });
  }
  async detach(id: string) {
    await this.locked(id, async () => {
      this.store.server(id).deployment = undefined;
      await this.store.persist();
      this.changed();
    });
  }
  async uninstall(id: string, deleteAdopted: boolean) {
    const d = this.deployment(id);
    if (!d.managed && !deleteAdopted) {
      await this.detach(id);
      return '已解除管理，远程服务和文件保留。';
    }
    await this.control(id, 'stop');
    return this.locked(id, async () => {
      if (d.mode !== 'process') {
        await this.exec(id, this.serviceCommand(id, d, 'disable'));
        const info = await this.detect(id);
        const unit = `${d.mode === 'system' ? '/etc/systemd/system' : `${info.home}/.config/systemd/user`}/${d.service}`;
        await this.exec(
          id,
          `${d.mode === 'system' && !info.root ? 'sudo -n ' : ''}rm -f -- ${quote(unit)} && ${d.mode === 'system' ? `${this.rootUsers.has(id) ? '' : 'sudo -n '}systemctl` : 'systemctl --user'} daemon-reload`,
        );
      }
      // 不递归删除目录，接管部署也只删除用户明确提供的几个文件。
      await this.exec(
        id,
        `rm -f -- ${[d.binary, d.config, d.log, d.pidFile].map((p) => quote(remotePath(p))).join(' ')}`,
      );
      this.store.server(id).deployment = undefined;
      await this.store.persist();
      this.changed();
      return '服务已卸载；历史备份保留在原目录。';
    });
  }
}
