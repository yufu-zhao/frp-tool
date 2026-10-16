import type { Deployment, HostInfo } from '../shared/types';

export type ServiceManager = 'systemd' | 'openrc' | 'sysv' | 'process';

// 将主机能力转换为唯一运行方式，权限不足时保守回退到后台进程。
export function selectServiceMode(info: HostInfo): {
  manager: ServiceManager;
  mode: Deployment['mode'];
} {
  if (info.serviceManager === 'systemd') {
    if (info.root || info.sudo) return { manager: 'systemd', mode: 'system' };
    if (info.userSystemd) return { manager: 'systemd', mode: 'user' };
  }
  if (
    (info.serviceManager === 'openrc' || info.serviceManager === 'sysv') &&
    (info.root || info.sudo)
  )
    return { manager: info.serviceManager, mode: 'system' };
  return { manager: 'process', mode: 'process' };
}

// 旧部署记录没有 manager 字段，按历史 mode 推导其原有 systemd/进程行为。
export function deploymentManager(deployment: Deployment): ServiceManager {
  return deployment.manager ?? (deployment.mode === 'process' ? 'process' : 'systemd');
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

// OpenRC 使用自身守护管理能力启动 FRP，并将输出写入应用日志文件。
export function openrcScript(deployment: Deployment): string {
  return [
    '#!/sbin/openrc-run',
    `description=${shellQuote(`Intranet FRP ${deployment.service}`)}`,
    `command=${shellQuote(deployment.binary)}`,
    `command_args="-c ${deployment.config.replace(/(["\\\x24\x60])/g, '\\$1')}"`,
    'command_background=true',
    `pidfile=${shellQuote(deployment.pidFile)}`,
    `output_log=${shellQuote(deployment.log)}`,
    `error_log=${shellQuote(deployment.log)}`,
    'depend() {',
    '  need net',
    '}',
    '',
  ].join('\n');
}

// SysV 服务脚本只操作与部署记录中的程序和配置匹配的 FRP 进程。
export function sysvScript(deployment: Deployment): string {
  const binary = shellQuote(deployment.binary);
  const config = shellQuote(deployment.config);
  const log = shellQuote(deployment.log);
  const pidFile = shellQuote(deployment.pidFile);
  return `#!/bin/sh
BIN=${binary}
CONFIG=${config}
LOG=${log}
PIDFILE=${pidFile}
is_running() {
  test -s "$PIDFILE" || return 1
  PID=$(cat "$PIDFILE" 2>/dev/null) || return 1
  case "$PID" in ''|*[!0-9]*) return 1;; esac
  test "$PID" -gt 1 && kill -0 "$PID" 2>/dev/null || return 1
  test "$(readlink -f /proc/"$PID"/exe 2>/dev/null)" = "$(readlink -f "$BIN" 2>/dev/null)" || return 1
  tr '\\000' '\\n' < /proc/"$PID"/cmdline 2>/dev/null | grep -Fx -- "$CONFIG" >/dev/null
}
start_service() {
  is_running && return 0
  umask 077
  nohup "$BIN" -c "$CONFIG" >> "$LOG" 2>&1 < /dev/null &
  echo $! > "$PIDFILE"
  sleep 1
  is_running
}
stop_service() {
  is_running || { rm -f -- "$PIDFILE"; return 0; }
  kill "$PID" || return 1
  n=0
  while kill -0 "$PID" 2>/dev/null && test "$n" -lt 10; do sleep 1; n=$((n+1)); done
  kill -0 "$PID" 2>/dev/null && return 1
  rm -f -- "$PIDFILE"
}
case "$1" in
  start) start_service ;;
  stop) stop_service ;;
  restart) stop_service && start_service ;;
  status) is_running && exit 0; exit 3 ;;
  *) echo "用法：$0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
`;
}
