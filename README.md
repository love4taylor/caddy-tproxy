# Caddy Telegram WEB Proxy

**English** · [简体中文](README.zh-CN.md)

A Caddy module for Telegram clients that support **WEB Proxy**. The WEB relay, MTProxy backend, and Telegram route updates all run inside Caddy. Ordinary web requests continue through your site's existing handlers.

## Quick start

### 1. Build Caddy

With Go 1.26 or later, install `xcaddy` and make sure it is on your `PATH`. Then build Caddy with the module. [xcaddy documentation](https://github.com/caddyserver/xcaddy)

```sh
go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7
xcaddy build v2.11.9 --with github.com/love4taylor/caddy-tproxy
./caddy list-modules | grep '^http.handlers.tproxy$'
```

### 2. Configure an HTTPS site

Point a lowercase hostname you control at Caddy. With the account that runs Caddy, create a new secret file in a directory that account can write to. This example uses `/etc/caddy/tproxy.secret`.

```sh
umask 077
openssl rand -hex 16 > /etc/caddy/tproxy.secret
```

Add `tproxy` to the HTTPS site. The example uses a simple response for ordinary traffic. If you already serve a website there, keep its existing handlers.

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

### 3. Connect Telegram

Choose **WEB Proxy** in a compatible Telegram client. Enter `proxy.example.com` as the server and paste the hex value from the secret file. You can also share a link in this format.

```text
tg://webproxy?server=proxy.example.com&secret=<hex-secret>
```

## Configuration

By default, `tproxy` serves every concrete DNS hostname matched by the site and the directive's route. Use `tproxy <hostname>` to restrict the relay to one public hostname. Configure either a single `secret_file` or one or more `profile` entries.

Native Caddy JSON follows the same rule using the enclosing routes' `host` matchers. Specify a hostname explicitly for named routes, error routes, and routes with no concrete DNS names, such as wildcard-only or port-only sites.

| Option | Meaning |
| --- | --- |
| `secret_file <path>` | Path to a regular file readable by Caddy with owner-only permissions, such as `0600` or `0400`. Accepts a 16-byte key in hex or Base64URL, with an optional `dd` prefix in the decoded bytes. |
| `carrier <mode>` | Transport in single-key mode. Choices are `https` (default), `https-lanes`, `websocket`, and `websocket-lanes`. |
| `profile <name> <secret-file> [<carrier>]` | Repeatable entry with a distinct key, an optional carrier and optional per-profile limits. Use these entries in place of the top-level `secret_file` and `carrier`. |
| `limits { … }` | Limits apply separately to each served hostname. Use integers and specify sizes in bytes. Profiles inherit omitted limits and share the quotas for their hostname. See the [upstream capacity reference](https://github.com/telegramdesktop/tproxy-server/blob/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8/README.md#capacity-limits). |
| `base_path <path>` | Mount the relay under a path such as `/telegram`. Enter `proxy.example.com/telegram` in the client. The default is the site root. |
| `public_ip <IPv4>` | If Caddy connects through NAT, set this to the public IPv4 address Telegram sees. You can omit it when the host connects directly from its public IPv4 address. |
| `token_key_file <path>` | Optional 32-byte binary signing key. By default, Caddy storage holds a generated key for each hostname and base path. Use the client secret when configuring Telegram. |
| `reconnect_grace <duration>` | How long an inactive relay session remains available to reconnect. Defaults to `2m`. A Caddy reload replaces relay sessions, so clients establish new ones. |

### Sharing a proxy under a path

Use Telegram's share action, or percent-encode the full `server` value and encode the `secret` as unpadded Base64URL of `0x70` followed by the decoded secret bytes. Keep the `dd` byte if the secret uses it. The server's `secret_file` takes the original secret. [Upstream share link format](https://github.com/telegramdesktop/tproxy-server/blob/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8/BASE_PATH.md)

```text
tg://webproxy?server=proxy.example.com%2Ftelegram&secret=<marked-secret>
```

### Multiple profiles

Use profiles to offer different transports on the same hostname. Each client uses the secret for its profile.

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

### HTTP timeouts and compression

Allow more than 25 seconds for the default long poll when setting HTTP or load balancer timeouts. Set request header limits with Caddy's `servers` → `max_header_size`. File transfers send data in request and response bodies, where limits such as `max_body_bytes` and `carrier_batch_bytes` apply. [Caddy server options](https://caddyserver.com/docs/caddyfile/options#servers)

The bridge splits large uplink DATA frames to fit `max_frame_payload` and `carrier_batch_bytes`. Set `max_frame_payload` to at least 4 bytes to accommodate WINDOW frames used for flow control.

For bridge HTML compression, use an explicit `route` block with `encode zstd gzip` above `tproxy`. When the WebView advertises a supported encoding, Caddy can compress the HTML. The default response matcher leaves binary relay traffic uncompressed. Keep `tproxy` ahead of URI rewrites and terminal handlers in that block. [Caddy encode directive](https://caddyserver.com/docs/caddyfile/directives/encode)

## Deployment

> [!IMPORTANT]
> Use a dedicated HTTPS subdomain if the main site runs scripts or service workers outside the proxy's trust boundary. `base_path` changes the URL path within the same browser origin.

- **Logs.** The module skips Caddy access logging for the requests it handles. Apply redaction at any CDN or load balancer, especially for the `bridge` query parameter, `Authorization`, and `Sec-WebSocket-Protocol`.
- **Telegram connectivity.** Allow outbound HTTPS to `core.telegram.org` for route and key updates, and IPv4 TCP to the data centers listed in those routes. The module caches validated routes in Caddy storage, refreshes them daily, and retries failed refreshes every minute using the last valid routes when available. [Telegram routing configuration](https://core.telegram.org/getProxyConfig)
- **Replay protection.** The relay responds with HTTP 425 to early data. The MTProxy backend keeps a two-minute Obfuscated2 replay window per key, with up to 16,384 entries. A normal Caddy reload preserves the window, and a process restart starts a new one.
- **Strict FIPS mode.** Configuration fails under `GODEBUG=fips140=only` because the Telegram data center RPC protocol requires MD5 and SHA-1 for key derivation. That RPC protocol uses AES-CBC and CRC for framing and lacks cryptographic authentication. [Telegram RPC implementation](https://github.com/TelegramMessenger/MTProxy/tree/f36d8af769ffaeac36978d38c2c0f6d1104c2137)

### PROXY protocol

For a layer 4 load balancer, bind the HTTPS site to Caddy's private address and restrict the listener to the load balancer with a firewall. The example uses `10.20.0.10` for Caddy and `10.20.0.2` for the load balancer. Add `bind 10.20.0.10` to the HTTPS site and merge this into the global options. [Caddy PROXY protocol wrapper](https://caddyserver.com/docs/caddyfile/options#proxy-protocol)

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

Caddy reads the PROXY header before TLS and uses the forwarded address for client IP limits. With `fallback_policy reject`, Caddy rejects PROXY headers from unlisted peers. The firewall restricts direct access. If you also use `trusted_proxies`, its rules see the client address after PROXY protocol processing.

### Monitoring and capacity

Enable `metrics` in Caddy's global options. You can scrape the admin endpoint or add `metrics /metrics` to an internal monitoring site. Useful `caddy_tproxy_*` metrics include `sessions`, `streams`, `pending_bytes`, `limit_hits_total`, and `rpc_dial_failures_total`. `handshakes_rejected_total` counts both duplicate handshakes and those refused when the replay window is full. [Caddy metrics documentation](https://caddyserver.com/docs/caddyfile/directives/metrics)

`max_pending_global` covers relay queues, active carrier request bodies, and backend packet buffers. The backend buffers also have a 64 MiB limit. The process-wide idle request buffer cache uses up to 7 MiB. Idle large backend packet buffers can occupy up to another 4 MiB + 2 KiB. TLS, sockets, and Go runtime memory contribute separately to total process memory. When lowering the queue limits, leave space for control frames and one uplink batch as well as downlink DATA. Caddy rejects a configuration that leaves no room for downlink DATA. On x86-64, the backend accelerates AES-256-CTR and RPC AES-256-CBC decryption with 512-bit VAES when available, then 256-bit VAES when AVX2 and VAES are available, and otherwise uses Go’s standard AES implementation.

## Development

```sh
go test ./...
```

The tests cover route refresh and caching, MTProto transports, and round trips from all four WEB carriers to a test data center. The bridge lifecycle test runs when Node.js is available.

The WEB relay implements Telegram Desktop's WEB proxy protocol. The embedded Go backend follows the official MTProxy wire format. [WEB relay protocol](https://github.com/telegramdesktop/tproxy-server/blob/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8/PROTOCOL.md), [official MTProxy implementation](https://github.com/TelegramMessenger/MTProxy/tree/f36d8af769ffaeac36978d38c2c0f6d1104c2137)

Original contributions are licensed under the GNU General Public License, version 3 or, at your option, any later version (`GPL-3.0-or-later`). The third-party notices record the upstream references, their licenses, and the scope of the provenance review. [GPL license](LICENSE), [third-party notices](THIRD_PARTY_NOTICES.md)
