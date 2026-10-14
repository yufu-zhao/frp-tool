import type { ReverseProxy } from '../shared/types';

// 为 FRP vhost 入口生成独立 Nginx 站点，不改写用户已有站点文件。
export function nginxProxyConfig(site: ReverseProxy, withHttps: boolean): string {
  const http = `server {
    listen 80;
    server_name ${site.domain};

    location ^~ /.well-known/acme-challenge/ {
        root ${site.webRoot};
        default_type text/plain;
    }

    location / {
        proxy_pass http://127.0.0.1:${site.httpPort};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`;
  if (!withHttps) return http;
  return `${http}
server {
    listen 443 ssl;
    server_name ${site.domain};
    ssl_certificate ${site.certPath};
    ssl_certificate_key ${site.keyPath};

    location / {
        proxy_pass https://127.0.0.1:${site.httpsPort};
        proxy_ssl_server_name on;
        proxy_ssl_name $host;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`;
}
