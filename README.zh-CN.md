# Caddy Telegram WEB Proxy

[English](README.md) · **简体中文**

为支持 **WEB 代理**的 Telegram 客户端提供服务的 Caddy 模块。WEB 中继、MTProxy 后端和 Telegram 路由更新都在 Caddy 进程内运行。普通网页请求继续交给站点现有的处理器。

## 快速开始

### 1. 构建 Caddy

使用 Go 1.26 或更新版本安装 `xcaddy`，并确保它在 `PATH` 中。然后构建包含本模块的 Caddy。[xcaddy 文档](https://github.com/caddyserver/xcaddy)

```sh
go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7
xcaddy build v2.11.9 --with github.com/love4taylor/caddy-tproxy
./caddy list-modules | grep '^http.handlers.tproxy$'
```

### 2. 配置 HTTPS 站点

将你控制的小写域名指向 Caddy。用运行 Caddy 的账号在其可写目录中创建新的密钥文件。示例使用 `/etc/caddy/tproxy.secret`。

```sh
umask 077
openssl rand -hex 16 > /etc/caddy/tproxy.secret
```

在 HTTPS 站点中添加 `tproxy`。示例为普通请求返回一条简单响应。已有网站可以保留原来的处理器。

```caddyfile
proxy.example.com {
	tproxy {
		secret_file /etc/caddy/tproxy.secret
	}

	respond "OK"
}
```

```sh
./caddy validate --config Caddyfile --adapter caddyfile
./caddy run --config Caddyfile --adapter caddyfile
```

### 3. 连接 Telegram

在支持此功能的 Telegram 客户端中选择 **WEB 代理**。服务器填 `proxy.example.com`，密钥填文件中的十六进制值。也可以用以下格式分享链接。

```text
tg://webproxy?server=proxy.example.com&secret=<hex-secret>
```

## 配置

`tproxy` 默认在站点及指令路由匹配的每个具体域名上提供代理。用 `tproxy <hostname>` 可将代理限制在一个公开域名。可以配置一个 `secret_file`，也可以配置一个或多个 `profile`。

原生 Caddy JSON 按相同规则从所在路由及外层路由的 `host` 匹配器取域名。命名路由、错误路由，以及只有通配符或端口等无法确定具体域名的路由，需要显式填写 `hostname`。

| 配置项 | 含义 |
| --- | --- |
| `secret_file <path>` | Caddy 可读的普通文件，仅所有者可访问，例如权限为 `0600` 或 `0400`。支持十六进制或 Base64URL 编码的 16 字节密钥，解码后的字节可带 `dd` 前缀。 |
| `carrier <mode>` | 单密钥模式下的传输方式。可选 `https`（默认）、`https-lanes`、`websocket` 和 `websocket-lanes`。 |
| `profile <name> <secret-file> [<carrier>]` | 可重复配置，每项使用独立密钥，可指定传输方式和配额。配置 profile 时省略顶层的 `secret_file` 和 `carrier`。 |
| `limits { … }` | 配额按服务域名分别计算。数值使用整数，大小以字节计。profile 继承省略项，同一域名下的 profile 共用该域名的配额。参见[上游容量参数](https://github.com/telegramdesktop/tproxy-server/blob/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8/README.md#capacity-limits)。 |
| `base_path <path>` | 将中继挂载到指定路径，例如 `/telegram`。客户端填 `proxy.example.com/telegram`。默认挂载在站点根路径。 |
| `public_ip <IPv4>` | Caddy 经 NAT 出站时，填写 Telegram 看到的公网 IPv4。主机直接使用公网 IPv4 出站时可省略。 |
| `token_key_file <path>` | 可选的 32 字节二进制签名密钥。默认按域名和挂载路径生成并保存在 Caddy 存储中。配置 Telegram 时填写客户端密钥。 |
| `reconnect_grace <duration>` | 中继会话在无活动后仍可重连的时间，默认 `2m`。Caddy 重载会替换中继会话，客户端会重新建立会话。 |

### 分享带路径的代理

可以直接使用 Telegram 的分享功能。手写链接时，对完整的 `server` 值做百分号编码。生成 `secret` 时，在解码后的密钥字节前加 `0x70`，再用无填充的 Base64URL 编码。原密钥带 `dd` 字节时一并保留。服务端的 `secret_file` 填原始密钥。[上游分享链接格式](https://github.com/telegramdesktop/tproxy-server/blob/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8/BASE_PATH.md)

```text
tg://webproxy?server=proxy.example.com%2Ftelegram&secret=<marked-secret>
```

### 多个 profile

通过 profile 在同一域名提供不同的传输方式。客户端使用对应 profile 的密钥。

```caddyfile
proxy.example.com {
	tproxy {
		limits {
			max_sessions_global 64
			max_streams_global 1024
			max_backend_dials_in_flight 64
		}
		profile default /etc/caddy/tproxy/default.secret
		profile ws /etc/caddy/tproxy/ws.secret websocket {
			max_sessions 16
			max_streams 128
		}
	}

	respond "OK"
}
```

### HTTP 超时和压缩

设置 HTTP 或负载均衡超时时，为默认长轮询预留超过 25 秒。请求头大小由 Caddy 的 `servers` → `max_header_size` 限制。文件数据通过请求体和响应体传输，受 `max_body_bytes`、`carrier_batch_bytes` 等参数约束。[Caddy 服务器选项](https://caddyserver.com/docs/caddyfile/options#servers)

桥接页会按 `max_frame_payload` 和 `carrier_batch_bytes` 切分较大的上行 DATA 帧。`max_frame_payload` 至少为 4 字节，以容纳流量控制使用的 WINDOW 帧。

需要压缩桥接 HTML 时，在显式的 `route` 块中把 `encode zstd gzip` 放在 `tproxy` 前面。WebView 声明支持相应编码时，Caddy 可压缩该 HTML。默认响应匹配规则会跳过二进制中继流量。块内的 URI 改写和直接返回响应的处理器应放在 `tproxy` 之后。[Caddy encode 指令](https://caddyserver.com/docs/caddyfile/directives/encode)

## 部署

> [!IMPORTANT]
> 如果主站运行的脚本或 Service Worker 与代理属于不同的信任范围，请给代理使用独立的 HTTPS 子域名。`base_path` 只改变同一浏览器源内的 URL 路径。

- **日志。** 模块接管的请求会跳过 Caddy 访问日志。CDN 和负载均衡器的日志也应脱敏，尤其是 `bridge` 查询参数、`Authorization` 和 `Sec-WebSocket-Protocol`。
- **Telegram 出站。** 允许 Caddy 通过 HTTPS 访问 `core.telegram.org` 获取路由和密钥，并通过 IPv4 TCP 连接路由列出的数据中心。验证后的配置缓存在 Caddy 存储中，每天刷新。刷新失败时每分钟重试，有可用缓存时继续使用上一次通过验证的路由。[Telegram 路由配置](https://core.telegram.org/getProxyConfig)
- **重放保护。** 中继对 TLS 早期数据返回 HTTP 425。MTProxy 后端按密钥维护 2 分钟的 Obfuscated2 重放窗口，最多记录 16,384 条。常规 Caddy 重载保留该窗口，进程重启后重新建立。
- **严格 FIPS 模式。** `GODEBUG=fips140=only` 下模块会在加载配置时失败，因为 Telegram 数据中心 RPC 需要 MD5 和 SHA-1 派生密钥。该 RPC 协议使用 AES-CBC 和带 CRC 的帧格式，缺少加密认证。[Telegram RPC 实现](https://github.com/TelegramMessenger/MTProxy/tree/f36d8af769ffaeac36978d38c2c0f6d1104c2137)

### PROXY protocol

使用四层负载均衡器时，将 HTTPS 站点绑定到 Caddy 的私有地址，并通过防火墙仅允许负载均衡器访问监听端口。示例中 `10.20.0.10` 是 Caddy 地址，`10.20.0.2` 是负载均衡器地址。在 HTTPS 站点中添加 `bind 10.20.0.10`，再将下列配置合并到全局选项。[Caddy PROXY protocol 监听器](https://caddyserver.com/docs/caddyfile/options#proxy-protocol)

```caddyfile
{
	servers 10.20.0.10:443 {
		protocols h1 h2
		listener_wrappers {
			proxy_protocol {
				timeout 2s
				allow 10.20.0.2/32
				fallback_policy reject
			}
			tls
		}
	}
}
```

Caddy 在 TLS 握手前解析 PROXY 头，并使用传入的客户端地址计算 IP 配额。`fallback_policy reject` 拒绝未列入允许范围的来源发送的 PROXY 头。直接访问由防火墙限制。如果同时使用 `trusted_proxies`，它的规则匹配的是 PROXY protocol 处理后的客户端地址。

### 监控和容量

在 Caddy 全局选项中启用 `metrics`，然后抓取管理端点，或在内网监控站点添加 `metrics /metrics`。可关注 `caddy_tproxy_*` 指标中的 `sessions`、`streams`、`pending_bytes`、`limit_hits_total` 和 `rpc_dial_failures_total`。`handshakes_rejected_total` 同时统计重复握手和窗口满额时被拒绝的握手。[Caddy 监控文档](https://caddyserver.com/docs/caddyfile/directives/metrics)

`max_pending_global` 覆盖中继队列、正在读取的载体请求体和后端数据包缓冲。后端缓冲另有 64 MiB 上限。进程共用的空闲请求体缓冲缓存最多占用 7 MiB，空闲后端大包缓存另占最多 4 MiB + 2 KiB。进程实际内存还包括 TLS、套接字和 Go 运行时开销。调低队列上限时，要为控制帧、一个上行批次和下行 DATA 帧留出空间。Caddy 会拒绝没有为下行 DATA 帧留空间的配置。在 x86-64 主机上，后端对 AES-256-CTR 和 RPC 的 AES-256-CBC 解密优先使用 512 位 VAES，其次在支持 AVX2 和 VAES 时使用 256 位 VAES，否则使用 Go 标准库的 AES 实现。

## 开发

```sh
go test ./...
```

测试覆盖路由刷新与缓存、MTProto 传输，以及四种 WEB 载体到模拟数据中心的往返。有 Node.js 时还会运行桥接页面的生命周期测试。

WEB 中继实现 Telegram Desktop 的 WEB 代理协议。内嵌 Go 后端遵循官方 MTProxy 的线上格式。[WEB 中继协议](https://github.com/telegramdesktop/tproxy-server/blob/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8/PROTOCOL.md)、[官方 MTProxy 实现](https://github.com/TelegramMessenger/MTProxy/tree/f36d8af769ffaeac36978d38c2c0f6d1104c2137)

本项目的原创贡献采用 GNU 通用公共许可证第 3 版，或由你选择任何更新版本（`GPL-3.0-or-later`）。第三方声明记录了上游参考资料、授权条款和来源核查的范围。[GPL 许可证](LICENSE)、[第三方声明](THIRD_PARTY_NOTICES.md)
