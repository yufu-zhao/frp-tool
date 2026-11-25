# tls-proxy

穿透工作台「服务器托管 TLS 实例」的单文件静态反向代理，仅使用 Go 标准库。

## 作用

在全新、未装任何软件的服务器上临时持有 80/443：

- **443**：TLS 终止 + HTTP/1.1 反向代理到本机高端口的 frps vhost（如
  `127.0.0.1:8080`）；保留 `Host`，设置 `X-Real-IP` / `X-Forwarded-For`
  （由 `httputil.ReverseProxy` 自动追加）/ `X-Forwarded-Proto: https`；
  WebSocket `Upgrade` 由 `httputil.ReverseProxy` 原生 101 隧道透传。
- **80**：`/.well-known/acme-challenge/<token>` 从 `challengeDir` 读取同名
  文件返回 `text/plain`，其余请求 301 跳 `https`。token 限定为 base64url
  字符，杜绝路径穿越。
- 证书/私钥 `mtime`/`size` 变化时热重载（定时 `stat`，无需重启，续期友好）。
- SIGTERM/SIGINT 优雅关闭；结构化 JSON 行日志同时写指定文件与 stdout。
- 配置缺失、证书/私钥不存在或无效时明确报错退出（退出码 1）。

## 配置（JSON，由 TlsProxyManager 写入）

```json
{
  "httpAddr": ":80",
  "httpsAddr": ":443",
  "certFile": "/home/u/.local/share/intranet-frp/certs/default/fullchain.pem",
  "keyFile": "/home/u/.local/share/intranet-frp/certs/default/privkey.pem",
  "upstream": "http://127.0.0.1:8080",
  "challengeDir": "/home/u/.local/share/intranet-frp/tls-proxy/vhost/challenge",
  "logFile": "/home/u/.local/share/intranet-frp/tls-proxy/logs/tls-proxy.log"
}
```

## 构建

```bash
node scripts/build-tls-proxy.mjs
# 等价于（分别在 amd64 / arm64 执行）：
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o assets/bin/tls-proxy-linux-amd64 .
```

两个产物为纯静态二进制，不含 cgo 依赖；低端口绑定由安装侧的
`setcap cap_net_bind_service=+ep` 提供（或以 root 运行）。

## 隔离边界

程序只读取上述配置里给出的路径，不写 `/etc/nginx`、`/usr/sbin/nginx`、
`nginx.service`、包数据库、`/var/log/nginx`、`/etc/letsencrypt` 等任何系统
路径，也不碰系统用户/组、PATH、sudoers、持久防火墙规则。
