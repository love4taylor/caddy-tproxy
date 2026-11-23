# Third-party notices

Copyright (c) 2026 caddy-tproxy contributors.

Original contributions to this repository are licensed under the GNU General
Public License, version 3 or, at your option, any later version
(`GPL-3.0-or-later`). Third-party material is subject to its own licensing
terms. [GPL license](LICENSE)

## Telegram Desktop WEB proxy relay

The module implements the documented WEB relay protocol. Endpoint names, wire
values, credential formats, and capacity settings follow the protocol and
configuration references where needed for compatibility. The referenced
upstream revision contains no general license grant. [tproxy-server at commit c8adb8b](https://github.com/telegramdesktop/tproxy-server/tree/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8), [WEB relay protocol](https://github.com/telegramdesktop/tproxy-server/blob/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8/PROTOCOL.md)

An earlier local working tree used parts of the upstream implementation. The
bridge, HTTP request handling, credential scanner, and session and stream
handling were rewritten. The standalone server tests and fixtures were
replaced by tests for the embedded module. The source review compared the
current Go and JavaScript against the upstream tree, including the JavaScript
inside the upstream Go template and the test fixtures. The review identified
no remaining copied implementation code or fixtures from that WEB relay in
the current source tree.

## Telegram MTProxy

The Go backend implements the obfuscated client transport and the IPv4
middle-end RPC protocol. The table records which upstream files were consulted
and the licensing statements in those files.

| Local code | Compatibility reference and upstream license |
| --- | --- |
| `transport.go`, `replay.go` | Obfuscation header and packet formats follow the [MTProto transport specification](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation). The C transport reference carries an LGPL version 2 or later header. Replay bookkeeping is module-specific. [net-tcp-rpc-ext-server.c](https://github.com/TelegramMessenger/MTProxy/blob/f36d8af769ffaeac36978d38c2c0f6d1104c2137/net/net-tcp-rpc-ext-server.c) |
| `rpc.go`, `middle_keys.go` | RPC handshake, framing, and key derivation use the legacy middle-end wire formats. The C references carry LGPL version 2 or later headers. [net-tcp-rpc-client.c](https://github.com/TelegramMessenger/MTProxy/blob/f36d8af769ffaeac36978d38c2c0f6d1104c2137/net/net-tcp-rpc-client.c), [net-tcp-rpc-common.c](https://github.com/TelegramMessenger/MTProxy/blob/f36d8af769ffaeac36978d38c2c0f6d1104c2137/net/net-tcp-rpc-common.c), [net-crypto-aes.c](https://github.com/TelegramMessenger/MTProxy/blob/f36d8af769ffaeac36978d38c2c0f6d1104c2137/net/net-crypto-aes.c) |
| `forward.go`, `middlepool.go`, `middlewrite.go` | Proxy messages match the C application's wire layout. The Go pool, stream queues, and writer use Go synchronization and buffer accounting. The C application carries a GPL version 2 or later header. [mtproto-proxy.c](https://github.com/TelegramMessenger/MTProxy/blob/f36d8af769ffaeac36978d38c2c0f6d1104c2137/mtproto/mtproto-proxy.c) |
| `routes.go` | Route file format and download endpoints match Telegram's deployment. The C parser carries a GPL version 2 or later header. The WEB relay's refresh script is in the tree described above. Download validation, Caddy storage, and refresh run in Go. [mtproto-config.c](https://github.com/TelegramMessenger/MTProxy/blob/f36d8af769ffaeac36978d38c2c0f6d1104c2137/mtproto/mtproto-config.c), [refresh-mtproxy-config.sh](https://github.com/telegramdesktop/tproxy-server/blob/c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8/deploy/refresh-mtproxy-config.sh) |
| `crypto.go`, `vaes_amd64.go`, `vaes_amd64.s` | Go's standard crypto is the fallback. The amd64 path uses VAES for CTR and CBC decryption. Its assembly has no dependencies on Telegram C or third-party assembly sources. |

The module builds the MTProxy backend from Go and assembly sources in this
repository. The upstream C files were consulted as interoperability references.
Third-party Go dependencies retain their own licenses.
