import { Client, type SFTPWrapper } from 'ssh2';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { Store } from './store';
import { AppError, redact } from '../shared/errors';
import { type Server, type Deployment, type HostInfo } from '../shared/types';
import { serverConfig, frpAdapter } from './frp';
import { hostInfoCommand, parseHostInfo } from './host-info';
import { deploymentManager, openrcScript, selectServiceMode, sysvScript } from './service-manager';

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

// systemd 240 起支持 StandardOutput=append:；版本无法识别时保守使用 journal。
export function supportsSystemdAppend(versionOutput: string): boolean {
  const major = /^systemd\s+(\d+)/i.exec(versionOutput.trim())?.[1];
  return major !== undefined && Number(major) >= 240;
}

// CentOS 7 的 systemctl 支持属性名输出，但部分状态会让 is-active 返回 unknown。
export function parseSystemdState(output: string): string | undefined {
  const fields = new Map<string, string>();
  for (const line of output.split(/\r?\n/)) {
    const separator = line.indexOf('=');
    if (separator > 0) fields.set(line.slice(0, separator), line.slice(separator + 1).trim());
  }
  const active = fields.get('ActiveState');
  if (
    active &&
    ['active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'].includes(active)
  )
    return active;
  return undefined;
}

export class Remote {
  private connections = new Map<string, Client>();
  private serviceStates = new Map<string, { value: string; at: number; message?: string }>();
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
    if (this.connected(id)) return this.detect(id);
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
      this.serviceStates.delete(id);
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
      return await this.detect(id);
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
        await this.status(server.id).catch((error: unknown) => {
          const message = error instanceof Error ? error.message : String(error);
          this.serviceStates.set(server.id, {
            value: 'unknown',
            at: Date.now(),
            message: redact(message, this.store.allSecrets()).slice(0, 500),
          });
        });
      }
    }
    const services = Object.fromEntries(
      this.store.data.servers.map((server) => [
        server.id,
        this.connected(server.id)
          ? (this.serviceStates.get(server.id)?.value ?? 'unknown')
          : 'unknown',
      ]),
    );
    const serviceErrors = Object.fromEntries(
      [...this.serviceStates.entries()]
        .filter(([id, state]) => this.connected(id) && !!state.message)
        .map(([id, state]) => [id, state.message]),
    );
    return { services, serviceErrors };
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
    const info = parseHostInfo(await this.exec(id, hostInfoCommand));
    if (!info.supported) return { ...info, home: info.home.startsWith('/') ? info.home : '/' };
    if (!info.home.startsWith('/')) throw new AppError('无法识别服务器用户家目录，部署已暂停。');
    return { ...info, home: remotePath(info.home) };
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
    const manager = deploymentManager(d);
    const privilege = d.mode === 'system' && !this.rootUsers.has(id) ? 'sudo -n ' : '';
    if (manager === 'openrc') {
      if (verb === 'enable') return `${privilege}rc-update add ${quote(d.service)} default`;
      if (verb === 'disable') return `${privilege}rc-update del ${quote(d.service)} default`;
      return `${privilege}rc-service ${quote(d.service)} ${quote(verb)}`;
    }
    if (manager === 'sysv') {
      if (verb === 'enable') return this.sysvAutostartCommand(d, true, privilege);
      if (verb === 'disable') return this.sysvAutostartCommand(d, false, privilege);
      const script = d.servicePath ?? `/etc/init.d/${d.service}`;
      return `${privilege}${quote(script)} ${quote(verb)}`;
    }
    return `${d.mode === 'system' ? `${privilege}systemctl` : 'systemctl --user'} ${verb} ${quote(d.service)}`;
  }
  private sysvAutostartCommand(d: Deployment, enable: boolean, privilege: string) {
    const command = enable
      ? `if command -v update-rc.d >/dev/null 2>&1; then update-rc.d ${quote(d.service)} defaults; elif command -v chkconfig >/dev/null 2>&1; then chkconfig --add ${quote(d.service)} && chkconfig ${quote(d.service)} on; else for dir in /etc/rc*.d; do test -d "$dir" || continue; case "$dir" in /etc/rc0.d|/etc/rc6.d) ln -sf -- ${quote(`../init.d/${d.service}`)} "$dir/K01${d.service}";; *) ln -sf -- ${quote(`../init.d/${d.service}`)} "$dir/S99${d.service}";; esac; done; fi`
      : `if command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f ${quote(d.service)} remove; elif command -v chkconfig >/dev/null 2>&1; then chkconfig --del ${quote(d.service)}; else for dir in /etc/rc*.d; do test -d "$dir" || continue; rm -f -- "$dir"/S??${d.service} "$dir"/K??${d.service}; done; fi`;
    return privilege ? `${privilege}sh -c ${quote(command)}` : command;
  }
  private checkedPid(d: Deployment) {
    // 只允许操作与记录的二进制及配置同时匹配的 Linux 进程。
    return `pid=$(cat ${quote(d.pidFile)} 2>/dev/null || true); case "$pid" in ''|*[!0-9]*) exit 1;; esac; test "$pid" -gt 1 || exit 1; kill -0 "$pid" 2>/dev/null || exit 1; test "$(readlink -f /proc/"$pid"/exe)" = "$(readlink -f ${quote(d.binary)})" || exit 1; tr '\\0' '\\n' < /proc/"$pid"/cmdline | grep -Fx -- ${quote(d.config)} >/dev/null || exit 1;`;
  }
  async status(id: string) {
    const d = this.deployment(id);
    const manager = deploymentManager(d);
    let value: string;
    if (manager === 'systemd') {
      const systemctl = d.mode === 'system' ? 'systemctl' : 'systemctl --user';
      const output = await this.exec(
        id,
        `${systemctl} show ${quote(d.service)} -p ActiveState -p SubState -p Result 2>&1 || true`,
      );
      value = parseSystemdState(output) ?? '';
      if (!value) {
        const fallback = await this.exec(
          id,
          `${systemctl} is-active ${quote(d.service)} 2>&1 || true`,
        );
        const normalized = fallback.trim().split('\n').at(-1)?.trim() ?? '';
        if (
          ['active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'].includes(
            normalized,
          )
        )
          value = normalized;
        else
          throw new AppError(
            `systemd 状态查询失败：${[output, fallback].filter(Boolean).join('\n').trim().slice(-500) || '没有返回状态。'}`,
          );
      }
    } else if (manager === 'openrc' || manager === 'sysv') {
      value = await this.exec(
        id,
        `output=$(${this.serviceCommand(id, d, 'status')} 2>&1); code=$?; case "$output" in *stopped*|*inactive*|*not\\ running*) echo inactive;; *) if test "$code" -eq 0; then echo active; elif test "$code" -eq 3; then echo inactive; else printf '%s\\n' "$output"; exit 1; fi;; esac`,
      );
    } else {
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
  async deploy(id: string, key: string) {
    return this.locked(id, async () => {
      const server = this.store.server(id);
      if (server.deployment) throw new AppError('已有部署，请使用切换版本或先解除管理。');
      const info = await this.detect(id);
      if (!info.supported)
        throw new AppError(`暂不支持此服务器系统：${info.distribution}。目前仅支持 Linux。`);
      const version = this.store.version(key);
      if (version.platform !== 'linux' || version.arch !== info.arch)
        throw new AppError(`请选择 Linux/${info.arch} 安装包。`);
      if (server.configMode === 'form' && !frpAdapter.supportsForm(version.version))
        throw new AppError('此版本只能使用原始配置部署。');
      const selection = selectServiceMode(info);
      const folder = remotePath(`${info.home}/.local/share/intranet-frp/${id}`);
      const service =
        selection.manager === 'systemd' ? `intranet-frps-${id}.service` : `intranet-frps-${id}`;
      const d: Deployment = {
        binary: `${folder}/frps`,
        config: `${folder}/frps.${server.configMode === 'raw' ? server.rawFormat : 'toml'}`,
        log: `${folder}/frps.log`,
        pidFile: `${folder}/frps.pid`,
        manager: selection.manager,
        mode: selection.mode,
        service,
        servicePath:
          selection.manager === 'openrc' || selection.manager === 'sysv'
            ? `/etc/init.d/${service}`
            : undefined,
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
        if (d.manager === 'systemd') {
          const unitPath = `${folder}/${d.service}`;
          const escapeUnit = (p: string) => p.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
          const serviceUser = d.mode === 'system' ? await this.exec(id, 'id -un') : '';
          const makeUnit = (fileLogs: boolean) =>
            `[Unit]\nDescription=Intranet FRP Server\nAfter=network.target\n\n[Service]\nType=simple\n${d.mode === 'system' ? `User=${serviceUser}\n` : ''}ExecStart="${escapeUnit(d.binary)}" -c "${escapeUnit(d.config)}"\n${fileLogs ? `StandardOutput=append:${escapeUnit(d.log).replace(/ /g, '\\x20')}\nStandardError=append:${escapeUnit(d.log).replace(/ /g, '\\x20')}\n` : ''}Restart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=${d.mode === 'system' ? 'multi-user.target' : 'default.target'}\n`;
          // CentOS 7 的 systemd-analyze verify 不会发现 manager 不支持 append:，先按版本能力判断。
          const systemdVersion = await this.exec(
            id,
            `${d.mode === 'user' ? 'systemctl --user' : 'systemctl'} --version | head -n 1`,
          ).catch(() => '');
          d.logMode = supportsSystemdAppend(systemdVersion) ? 'file' : 'journal';
          if (d.logMode === 'file') {
            await this.write(id, unitPath, makeUnit(true));
            const verified = await this.exec(
              id,
              `if command -v systemd-analyze >/dev/null 2>&1 && systemd-analyze verify ${quote(unitPath)} >/dev/null 2>&1; then echo yes; else echo no; fi`,
            );
            if (verified !== 'yes') {
              d.logMode = 'journal';
              await this.write(id, unitPath, makeUnit(false));
            }
          } else {
            await this.write(id, unitPath, makeUnit(false));
          }
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
        } else if (d.manager === 'openrc' || d.manager === 'sysv') {
          const scriptPath = `${folder}/${d.service}.init`;
          const script = d.manager === 'openrc' ? openrcScript(d) : sysvScript(d);
          await this.write(id, scriptPath, script);
          await this.exec(
            id,
            `chmod 755 -- ${quote(scriptPath)} && ${privilege}test ! -e ${quote(d.servicePath!)} && ${privilege}ln -s -- ${quote(scriptPath)} ${quote(d.servicePath!)}`,
          );
          installedUnit = d.servicePath!;
          d.logMode = 'file';
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
                : d.manager === 'openrc' || d.manager === 'sysv'
                  ? `${d.manager === 'openrc' ? 'OpenRC' : 'SysV'} 服务已安装，日志写入独立文件；服务保持停止，可单独开启开机启动。`
                  : `systemd 服务已安装，日志写入${d.logMode === 'file' ? '可单独清理的文件' : '系统 journal（不能单独清理此服务日志）'}；可通过启用开机启动单独设置。`,
        };
      } catch (error) {
        server.deployment = undefined;
        if (installedUnit) {
          if (d.manager === 'systemd')
            await this.exec(
              id,
              `${privilege}rm -f -- ${quote(installedUnit)} && ${privilege}systemctl ${d.mode === 'user' ? '--user ' : ''}daemon-reload`,
            ).catch(() => {});
          else {
            if (d.manager === 'openrc')
              await this.exec(id, this.serviceCommand(id, d, 'disable')).catch(() => {});
            if (d.manager === 'sysv')
              await this.exec(id, this.serviceCommand(id, d, 'disable')).catch(() => {});
            await this.exec(id, `${privilege}rm -f -- ${quote(installedUnit)}`).catch(() => {});
          }
        }
        await this.exec(
          id,
          `rm -f -- ${[d.binary, d.config, `${folder}/${d.service}`, `${folder}/${d.service}.init`].map(quote).join(' ')}`,
        ).catch(() => {});
        throw error;
      }
    });
  }
  private async checkUnit(id: string, d: Deployment) {
    const manager = deploymentManager(d);
    if (manager === 'process') return;
    if (manager === 'systemd') {
      // CentOS 7 的 systemd 不支持 --value，保留属性名的输出可跨版本解析。
      const command = `${d.mode === 'system' ? 'systemctl' : 'systemctl --user'} show ${quote(d.service)} -p ExecStart`;
      const start = await this.exec(id, command);
      if (!start.includes(`path=${d.binary} ;`) || !start.includes(`-c ${d.config} `))
        throw new AppError('systemd 服务单元与部署记录不一致，已阻止操作。');
      return;
    }
    const script = remotePath(d.servicePath ?? `/etc/init.d/${d.service}`);
    const contents = await this.exec(id, `cat -- ${quote(script)}`);
    if (!contents.includes(d.binary) || !contents.includes(d.config))
      throw new AppError('服务器服务脚本与部署记录不一致，已阻止操作。');
  }
  async adopt(id: string, input: Deployment) {
    return this.locked(id, async () => {
      const server = this.store.server(id);
      if (server.deployment) throw new AppError('请先解除当前部署的管理。');
      for (const field of ['binary', 'config', 'log', 'pidFile'] as const) remotePath(input[field]);
      const version = await this.exec(id, `${quote(input.binary)} -v`);
      if (!/^v?\d+\.\d+\.\d+/.test(version)) throw new AppError('此程序未返回有效的 FRP 版本。');
      await this.exec(id, `test -r ${quote(input.config)} || { echo '配置文件不可读'; exit 1; }`);
      const info = await this.detect(id);
      if (!info.supported) throw new AppError(`暂不支持接管此系统：${info.distribution}。`);
      const selection = selectServiceMode(info);
      input.manager = selection.manager;
      input.mode = selection.mode;
      input.servicePath =
        selection.manager === 'openrc' || selection.manager === 'sysv'
          ? `/etc/init.d/${input.service}`
          : undefined;
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
      const manager = deploymentManager(d);
      if (manager !== 'process') {
        await this.checkUnit(id, d);
        await this.exec(id, this.serviceCommand(id, d, action));
        try {
          return await this.status(id);
        } catch (error) {
          const message = redact(
            error instanceof Error ? error.message : String(error),
            this.store.allSecrets(),
          ).slice(0, 500);
          this.serviceStates.set(id, { value: 'unknown', at: Date.now(), message });
          this.changed();
          return `服务操作命令已执行，但状态未确认：${message}`;
        }
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
    const manager = deploymentManager(d);
    const journal =
      `${d.mode === 'system' ? `${this.rootUsers.has(id) ? '' : 'sudo -n '}journalctl` : 'journalctl --user'}` +
      ` -u ${quote(d.service)} -n 300 --no-pager`;
    let out: string;
    if (
      manager === 'process' ||
      manager === 'openrc' ||
      manager === 'sysv' ||
      d.logMode === 'file'
    ) {
      out = await this.exec(
        id,
        `if test -r ${quote(d.log)}; then tail -n 300 -- ${quote(d.log)}; else ${manager === 'systemd' ? `printf '%s\\n' '日志文件不存在，改为读取 systemd journal：'; ${journal}` : `echo '日志文件尚未生成，服务可能尚未启动。'`}; fi`,
      );
    } else {
      out = await this.exec(id, journal);
    }
    return redact(out, this.store.allSecrets());
  }
  async clearLogs(id: string) {
    return this.locked(id, async () => {
      const d = this.deployment(id);
      const manager = deploymentManager(d);
      if (manager === 'systemd' && d.logMode !== 'file')
        throw new AppError(
          '此 systemd 服务的日志保存在系统 journal 中，无法安全地只清理该服务而不影响其他服务。工具管理的新部署会使用独立日志文件；接管部署请先将服务输出配置到日志文件。',
        );
      const log = remotePath(d.log);
      const privilege = d.mode === 'system' && !this.rootUsers.has(id) ? 'sudo -n ' : '';
      const result = await this.exec(
        id,
        `if test -L ${quote(log)}; then echo '日志路径是符号链接，已拒绝清理'; exit 1; elif test -e ${quote(log)} && ! test -f ${quote(log)}; then echo '日志路径不是普通文件，已拒绝清理'; exit 1; elif test -f ${quote(log)}; then ${privilege}truncate -s 0 -- ${quote(log)} && echo '服务端日志已清理'; else echo '日志文件不存在，当前没有可清理内容'; fi`,
      );
      return `${result}；服务不会停止。`;
    });
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
  async uninstall(id: string) {
    const d = this.deployment(id);
    await this.control(id, 'stop');
    return this.locked(id, async () => {
      const manager = deploymentManager(d);
      if (manager !== 'process') {
        await this.exec(id, this.serviceCommand(id, d, 'disable'));
        if (manager === 'systemd') {
          const unit = `${d.mode === 'system' ? '/etc/systemd/system' : `${(await this.detect(id)).home}/.config/systemd/user`}/${d.service}`;
          await this.exec(
            id,
            `${d.mode === 'system' && !this.rootUsers.has(id) ? 'sudo -n ' : ''}rm -f -- ${quote(unit)} && ${d.mode === 'system' ? `${this.rootUsers.has(id) ? '' : 'sudo -n '}systemctl` : 'systemctl --user'} daemon-reload`,
          );
        } else if (manager === 'openrc' || manager === 'sysv') {
          const script = remotePath(d.servicePath ?? `/etc/init.d/${d.service}`);
          await this.exec(
            id,
            `${d.mode === 'system' && !this.rootUsers.has(id) ? 'sudo -n ' : ''}rm -f -- ${quote(script)}`,
          );
        }
      }
      // 不递归删除目录，接管部署也只删除用户明确提供的几个文件。
      await this.exec(
        id,
        `rm -f -- ${[
          d.binary,
          d.config,
          d.log,
          d.pidFile,
          d.managed && (manager === 'openrc' || manager === 'sysv')
            ? `${path.posix.dirname(d.binary)}/${d.service}.init`
            : '',
        ]
          .filter(Boolean)
          .map((p) => quote(remotePath(p)))
          .join(' ')}`,
      );
      this.store.server(id).deployment = undefined;
      await this.store.persist();
      this.changed();
      return '服务已卸载；历史备份保留在原目录。';
    });
  }
}
