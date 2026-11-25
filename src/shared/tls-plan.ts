import type { HostInfo, WebIncludeRecord, WebIncludeProbe } from './types';

export type TlsPlanMode = 'server' | 'local';

export interface TlsPlanCheck {
  label: string;
  ok: boolean;
  note: string;
  /** 该检查项是否阻止申请；方案 B 下的环境探测仅作参考。 */
  required?: boolean;
}

export interface TlsPlan {
  mode: TlsPlanMode;
  checks: TlsPlanCheck[];
  warnings: string[];
  reason: string;
  /** 方案 A 的前置条件全部满足时才允许申请；方案 B 无前置条件。 */
  canIssue: boolean;
  blockers: string[];
}

const WEB_SERVICE_NAMES = ['nginx', 'openresty', 'apache2', 'httpd'];

export interface TlsPlanInput {
  /** 服务端 frps 配置的 vhostHTTPPort；80 走方案 B，非标端口走方案 A。 */
  httpPort?: number;
  hostInfo?: HostInfo;
  webInclude?: WebIncludeRecord;
  probe?: WebIncludeProbe;
}

/**
 * TLS 终止方案只由服务端 vhostHTTPPort 决定：
 * - 标准 80 端口 → 方案 B，证书保存在本机，由 frpc https2http 终止；
 * - 非标端口 → 方案 A，由服务器 Web 服务终止 TLS。
 *
 * Web 服务、include 注入记录、default.conf 探针不参与方案选择，只作为方案 A 的申请门槛；
 * 任一失败即阻止申请，不自动降级为方案 B。443 占用 / 权限等因素仅提示。
 */
export function decideTlsPlan(input: TlsPlanInput): TlsPlan {
  const portKnown = Number.isInteger(input.httpPort);
  const standardPort = input.httpPort === 80;
  // 端口未知时按方案 A 处理并阻止申请，避免误把证书签发到错误的终止位置。
  const mode: TlsPlanMode = standardPort ? 'local' : 'server';
  const services = (input.hostInfo?.webServices ?? []).filter(
    (item) => (item.installed || item.running) && WEB_SERVICE_NAMES.includes(item.name),
  );
  const hasWeb = services.length > 0;
  // 实时 probe 优先；未提供时回退到注入记录里的快照。
  const activeProbe = input.probe ?? input.webInclude?.probe;
  const probing = !!activeProbe?.token;
  const probeOk = activeProbe?.ok === true;
  const injected = !!input.webInclude;
  const required = mode === 'server';

  const checks: TlsPlanCheck[] = [
    {
      label: 'vhostHTTPPort',
      ok: portKnown,
      required: true,
      note: !portKnown
        ? '未读取到服务端 vhostHTTPPort，无法判定终止位置'
        : standardPort
          ? '标准 80 端口，使用方案 B'
          : `${input.httpPort} 为非标端口，使用方案 A`,
    },
    {
      label: '服务器 Web 服务',
      ok: hasWeb,
      required,
      note: hasWeb
        ? `检测到 ${services.map((item) => item.name).join('、')}`
        : !input.hostInfo
          ? '未能读取服务器 Web 服务信息，请确认 SSH 连接后重新检测'
          : '未检测到 Nginx / Apache，方案 A 无法在服务器终止 TLS',
    },
    {
      label: 'include 注入记录',
      ok: injected,
      required,
      note: injected ? '服务器已写入托管 include' : '尚未在服务器注入 include',
    },
    {
      label: 'default.conf 探针',
      ok: probeOk,
      required,
      note: probing
        ? probeOk
          ? '探针已在 Web 服务配置中生效'
          : '探针未生效，注入可能未真正加载'
        : '注入记录缺少探针，无法确认生效',
    },
  ];

  const blockers = required
    ? checks
        .filter((check) => check.required && !check.ok)
        .map((check) => `${check.label}：${check.note}`)
    : [];
  const warnings: string[] = [];
  if (!portKnown)
    warnings.push('服务端配置缺少有效的 vhostHTTPPort；请先在服务器表单中确认 HTTP 入口端口。');
  if (input.hostInfo?.port443?.state === 'occupied' && mode === 'server')
    warnings.push(
      `服务器 443 已被 ${input.hostInfo.port443.owner || '其它进程'} 占用，请确认该进程为上述 Web 服务，否则方案 A 会冲突。`,
    );
  if (input.webInclude && input.webInclude.flavor !== 'nginx' && mode === 'server')
    warnings.push('当前注入的是 Apache，方案 A 的 server 块模板仅覆盖 Nginx；Apache 需手动适配。');
  if (mode === 'server') {
    // 探测缺失/失败 ≠ 用户没有权限，不能断言“非 root 且无免密 sudo”误导用户。
    if (!input.hostInfo) {
      warnings.push(
        '尚未读取到服务器 SSH 探测结果，无法确认 root / 免密 sudo 权限，写证书与注入可能失败。',
      );
    } else if (!input.hostInfo.root && !input.hostInfo.sudo) {
      warnings.push('当前 SSH 用户非 root 且无免密 sudo，写证书与注入可能失败。');
    }
  }
  if (mode === 'local')
    warnings.push('标准 80 端口下 frps 直接持有 80；HTTP-01 需域名已解析到该服务器且公网可达。');

  const canIssue = blockers.length === 0;
  const modeLabel =
    mode === 'server'
      ? `服务端 vhostHTTPPort 为 ${portKnown ? input.httpPort : '未知'}（非标端口），TLS 由服务器 Web 服务终止。`
      : '服务端 vhostHTTPPort 为标准 80 端口，TLS 由本机 frpc 终止。';
  return {
    mode,
    checks,
    warnings,
    canIssue,
    blockers,
    reason: canIssue ? modeLabel : `${modeLabel}申请前置条件未满足，已阻止签发。`,
  };
}
