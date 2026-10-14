export class AppError extends Error {
  constructor(
    message: string,
    public code = 'FAILED',
  ) {
    super(message);
  }
}
// 不把密码、认证令牌或完整私钥写入界面日志和错误消息。
export function redact(value: string, secrets: string[] = []): string {
  let result = value.replace(
    /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g,
    '[私钥已隐藏]',
  );
  for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length))
    result = result.split(secret).join('[已隐藏]');
  return result.replace(
    /((?:token|password|passphrase|secretKey)\s*[=:]\s*)[^\s,]+/gi,
    '$1[已隐藏]',
  );
}
export function friendlyError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/ENOTFOUND|EAI_AGAIN/.test(message))
    return '无法解析地址，请检查网络、服务器地址或代理设置。';
  if (/ECONNREFUSED/.test(message))
    return '连接被拒绝，请检查服务是否启动、端口和防火墙/云安全组。';
  if (/timed?\s*out|ETIMEDOUT|AbortError/i.test(message))
    return '操作超时，请检查网络和端口放行情况后重试。';
  if (/All configured authentication methods failed/.test(message))
    return 'SSH 认证失败，请检查用户名、密码、密钥及密钥口令。';
  if (/Permission denied|EACCES/.test(message))
    return '权限不足，请检查目录权限，或选择普通用户可写的安装目录。';
  return redact(message).slice(0, 4000);
}
