// 把常见服务端安装错误翻译成可操作的下一步，避免用户只看到一句错误就卡住。
// 放在 shared 下的纯函数，主进程与单测都能直接调用。
export function deployFailureHint(error: string): string {
  if (/已有部署|已有程序|服务单元已存在|已有 FRP/i.test(error))
    return '安装目录已有 FRP 程序或服务单元。请在安装预检中选择「覆盖上传」或「移除并重新安装」；若要保留现有服务，可选择保存为只读连接。';
  if (/端口.*占用|已占用|address already in use|bind/i.test(error))
    return '入口端口被占用，安装已在预检阶段终止。请到服务器配置更换 FRP / HTTP / HTTPS 入口端口后重试。';
  if (/Permission denied|sudo|权限|operation not permitted|EACCES/i.test(error))
    return '权限不足。请用 root 登录，或为当前用户配置免密 sudo（工具不会交互输入 sudo 密码）；也可在服务器配置改用普通后台进程模式。';
  if (/主机信息采集|暂不支持|distribution|仅支持 Linux/i.test(error))
    return '架构或系统探测未通过。请确认 SSH 能连接、目标是 Linux（amd64 / arm64），必要时先点「连接 SSH」和「刷新主机信息」。';
  if (/版本不匹配|版本.*不一致|安装包|verify|校验/i.test(error))
    return '安装包与目标不匹配或损坏。请在「版本库」重新获取列表或手动离线导入对应架构的安装包后再试。';
  if (/SSH|连接|connect|ECONN|ETIMEDOUT|认证/i.test(error))
    return 'SSH 连接或认证失败。请检查服务器地址、端口、密钥/密码与网络连通性，先在服务器页点「连接 SSH」验证。';
  return '安装未完成。可查看下方各阶段定位失败点；修正后点「重试」重新执行，失败时不会留下指向不存在程序的配置。';
}
