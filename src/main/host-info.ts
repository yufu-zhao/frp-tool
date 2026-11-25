import type { HostInfo, HostPortStatus, HostWebService } from '../shared/types';

// 用 POSIX 命令采集主机信息，尽量不依赖发行版额外安装的软件包。
export const hostInfoCommand = String.raw`platform=$(uname -s 2>/dev/null || echo unknown)
printf 'platform=%s\n' "$platform"
printf 'kernel=%s\n' "$(uname -r 2>/dev/null || true)"
printf 'arch=%s\n' "$(uname -m 2>/dev/null || true)"
home=$HOME
test -n "$home" || home=/
printf 'home=%s\n' "$home"
printf 'distribution=%s\n' "$(awk -F= '$1=="PRETTY_NAME"{sub(/^[^=]*=/,"");gsub(/^\"|\"$/,"");print;exit}' /etc/os-release 2>/dev/null)"
printf 'version=%s\n' "$(awk -F= '$1=="VERSION_ID"{sub(/^[^=]*=/,"");gsub(/^\"|\"$/,"");print;exit}' /etc/os-release 2>/dev/null)"
printf 'cpuModel=%s\n' "$(awk -F: '/^(model name|Hardware|Processor)[[:space:]]*:/{sub(/^[^:]*:[[:space:]]*/,"");print;exit}' /proc/cpuinfo 2>/dev/null)"
printf 'cpuCores=%s\n' "$(getconf _NPROCESSORS_ONLN 2>/dev/null || awk '/^processor[[:space:]]*:/{n++} END{print n+0}' /proc/cpuinfo 2>/dev/null)"
printf 'memoryTotalKB=%s\n' "$(awk '/^MemTotal:/{print $2;exit}' /proc/meminfo 2>/dev/null)"
printf 'memoryAvailableKB=%s\n' "$(awk '/^MemAvailable:/{print $2;seen=1;exit} /^MemFree:/{fallback=$2} END{if(!seen && fallback) print fallback}' /proc/meminfo 2>/dev/null)"
disk=$(df -Pk "$home" 2>/dev/null | awk 'NR==2{print $2 ":" $4}')
printf 'disk=%s\n' "$disk"
init=$(cat /proc/1/comm 2>/dev/null)
manager=unknown
if [ "$platform" = Linux ]; then
  if [ "$init" = systemd ] && command -v systemctl >/dev/null 2>&1; then manager=systemd
  elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1 && { [ -d /run/openrc ] || [ -f /run/openrc/softlevel ] || [ "$init" = openrc-init ]; }; then manager=openrc
  elif [ -d /etc/init.d ] && { command -v service >/dev/null 2>&1 || command -v start-stop-daemon >/dev/null 2>&1 || [ "$init" = init ]; }; then manager=sysv
  fi
fi
printf 'serviceManager=%s\n' "$manager"
if [ "$manager" = systemd ] && systemctl --user show-environment >/dev/null 2>&1; then userSystemd=yes; else userSystemd=no; fi
if [ "$(id -u 2>/dev/null)" = 0 ]; then root=yes; else root=no; fi
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then sudo=yes; else sudo=no; fi
printf 'userSystemd=%s\nroot=%s\nsudo=%s\n' "$userSystemd" "$root" "$sudo"
printf '__PORTS_BEGIN__\n'
if command -v ss >/dev/null 2>&1; then ss -lntu 2>/dev/null || true
elif command -v netstat >/dev/null 2>&1; then netstat -lntu 2>/dev/null || true
else echo '无法读取端口占用：ss/netstat 均不可用'; fi
printf '__PORTS_END__\n'
printf '__WEB_BEGIN__\n'
listen_out=''
if command -v ss >/dev/null 2>&1; then listen_out=$(ss -lntp 2>/dev/null)
elif command -v netstat >/dev/null 2>&1; then listen_out=$(netstat -lntp 2>/dev/null)
fi
if [ -n "$listen_out" ]; then
  for p in 80 443; do
    line=$(printf '%s\n' "$listen_out" | awk -v p="$p" 'NR>1 {n=split($4,a,":"); if (a[n]==p) {print; exit}}')
    if [ -z "$line" ]; then line=$(printf '%s\n' "$listen_out" | awk -v p="$p" '$4 ~ ":"p"$" {print; exit}'); fi
    if [ -z "$line" ]; then
      printf 'port%s=free|\n' "$p"
    else
      owner=$(printf '%s\n' "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1)
      if [ -z "$owner" ]; then owner=$(printf '%s\n' "$line" | awk '{print $NF}' | sed 's#.*/##'); fi
      case "$owner" in ''|*:*|'*'|'-') owner=unknown;; esac
      printf 'port%s=occupied|%s\n' "$p" "$owner"
    fi
  done
else
  printf 'port80=unknown|\nport443=unknown|\n'
fi
for svc in nginx openresty apache2 httpd caddy lighttpd; do
  installed=no
  running=no
  command -v "$svc" >/dev/null 2>&1 && installed=yes
  if command -v systemctl >/dev/null 2>&1; then
    if [ "$(systemctl is-active "$svc.service" 2>/dev/null)" = active ]; then running=yes; fi
    if [ "$installed" = no ] && systemctl list-unit-files "$svc.service" 2>/dev/null | grep -q "$svc.service"; then installed=yes; fi
  elif command -v rc-service >/dev/null 2>&1; then
    if rc-service "$svc" status >/dev/null 2>&1; then running=yes; installed=yes; fi
  fi
  if [ "$installed" = no ] && [ -x "/etc/init.d/$svc" ]; then installed=yes; fi
  if [ "$installed" = yes ] || [ "$running" = yes ]; then
    printf 'service=%s|%s|%s\n' "$svc" "$installed" "$running"
  fi
done
printf '__WEB_END__\n'`;

function nonNegativeInteger(value: string | undefined): number | null {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

function positiveInteger(value: string | undefined): number | null {
  const number = nonNegativeInteger(value);
  return number !== null && number > 0 ? number : null;
}

function betweenMarkers(output: string, startMarker: string, endMarker: string): string {
  const start = output.indexOf(startMarker);
  const end = output.indexOf(endMarker, start + startMarker.length);
  return start >= 0 && end > start ? output.slice(start + startMarker.length, end).trim() : '';
}

// 允许缺失单项指标，不能因为精简系统缺工具而影响 SSH 连接。
export function parseHostInfo(output: string): HostInfo {
  const ports = betweenMarkers(output, '__PORTS_BEGIN__', '__PORTS_END__');
  const web = betweenMarkers(output, '__WEB_BEGIN__', '__WEB_END__');
  const fields = new Map<string, string>();
  const fieldText = output
    .replace(/__WEB_BEGIN__[\s\S]*?__WEB_END__/, '')
    .replace(/__PORTS_BEGIN__[\s\S]*?__PORTS_END__/, '');
  for (const line of fieldText.split('\n')) {
    if (line.startsWith('__')) continue;
    const separator = line.indexOf('=');
    if (separator > 0) fields.set(line.slice(0, separator), line.slice(separator + 1).trim());
  }
  const webLines = web.split('\n');
  const parsePort = (key: 'port80' | 'port443'): HostPortStatus => {
    const line = webLines.find((item) => item.startsWith(`${key}=`));
    const raw = line?.slice(key.length + 1) ?? '';
    const [state, owner] = raw.split('|');
    return {
      state: state === 'free' || state === 'occupied' ? state : 'unknown',
      owner: owner || '',
    };
  };
  const webServices: HostWebService[] = webLines
    .filter((line) => line.startsWith('service='))
    .map((line) => {
      const [name, installed, running] = line.slice('service='.length).split('|');
      return { name, installed: installed === 'yes', running: running === 'yes' };
    })
    .filter((item) => !!item.name);
  const platform = fields.get('platform') ?? '';
  const machine = fields.get('arch') ?? '';
  const disk = fields.get('disk')?.split(':') ?? [];
  const manager = fields.get('serviceManager');
  const serviceManager =
    manager === 'systemd' || manager === 'openrc' || manager === 'sysv' ? manager : 'unknown';
  const supported = platform === 'Linux';
  const missing: string[] = [];
  if (!fields.get('distribution')) missing.push('发行版');
  if (!fields.get('cpuModel')) missing.push('CPU 型号');
  if (!positiveInteger(fields.get('cpuCores'))) missing.push('CPU 核心数');
  if (
    !positiveInteger(fields.get('memoryTotalKB')) ||
    nonNegativeInteger(fields.get('memoryAvailableKB')) === null
  )
    missing.push('内存');
  if (!positiveInteger(disk[0]) || nonNegativeInteger(disk[1]) === null) missing.push('磁盘');
  return {
    home: fields.get('home') || '/',
    supported,
    distribution:
      fields.get('distribution') || (supported ? '未知 Linux 发行版' : platform || '未知系统'),
    version: fields.get('version') || '',
    kernel: fields.get('kernel') || '',
    arch:
      machine === 'x86_64'
        ? 'amd64'
        : machine === 'aarch64' || machine === 'arm64'
          ? 'arm64'
          : machine,
    cpuModel: fields.get('cpuModel') || '',
    cpuCores: positiveInteger(fields.get('cpuCores')),
    memoryTotalKB: positiveInteger(fields.get('memoryTotalKB')),
    memoryAvailableKB: nonNegativeInteger(fields.get('memoryAvailableKB')),
    diskTotalKB: positiveInteger(disk[0]),
    diskAvailableKB: nonNegativeInteger(disk[1]),
    serviceManager,
    systemd: serviceManager === 'systemd',
    userSystemd: fields.get('userSystemd') === 'yes',
    root: fields.get('root') === 'yes',
    sudo: fields.get('sudo') === 'yes',
    ports,
    port80: parsePort('port80'),
    port443: parsePort('port443'),
    webServices,
    warning: missing.length ? `部分主机信息不可用：${missing.join('、')}` : undefined,
  };
}
