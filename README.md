# hy — Hysteria 2 Rust rewrite

Protocol-compatible rewrite of [apernet/hysteria](https://github.com/apernet/hysteria) (v4 / Hysteria 2).

**使用说明（参数、场景示例）：[USAGE.md](USAGE.md)**

**不支持：**
- `tls.ech`（客户端）和 `ech` / `tls.ech.key`（服务端）。写了会拒绝启动，不会假装已藏 SNI。
- ACME `type: dns`（Cloudflare / DuckDNS / Porkbun 等 DNS-01）。写了会明确报错。HTTP-01 / TLS-ALPN-01 和自备 `tls.cert`/`key` 可用。

| Crate | Role |
|---|---|
| `hy-core` | Protocol, QUIC, Client/Server |
| `hy-extras` | Auth / ACL / outbound / sniff / masq / obfs / realm |
| `hy-app` | CLI `hy` + YAML + inbounds |

Dependency: `hy-app` → `hy-extras` → `hy-core`.

```
hy client -c client.yaml
hy server -c server.yaml
hy version
```

Release binaries: [v0.3.7](https://github.com/wusir27/hy/releases/tag/v0.3.7)（Linux 五套 + Darwin 两套）。

---

## 沙箱性能（hy 0.2.0 vs 官方 Go v2.8.1）

环境：8 vCPU / 16G，全部 `127.0.0.1`（CPU/用户态上限，不是网卡）。  
对比：`hy-linux-amd64` `6fa6a40`（SHA `ecc62dd2…`）vs hysteria v2.8.1。路径：TLS + Salamander + `udpForwarding`。

### 限速阶梯（刚重测）

![udp-ladder](docs/perf/udp-ladder.svg)

| 目标 Mbps | hy rx | Go rx | hy 丢包 | Go 丢包 | hy CPU sv+cl | Go CPU sv+cl |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 20.0 | 20.0 | 0 | 0 | 20% | 42% |
| 50 | 50.0 | 50.0 | 0 | 0 | 32% | 59% |
| 100 | 99.9 | 99.9 | 0 | 0 | 46% | 83% |
| 200 | 200.2 | 200.3 | 0 | 0 | 70% | 131% |
| 400 | 398.5 | 398.7 | 0 | 0 | **118%** | **248%** |
| 800 | **796** | 711 | 1.2% | 11.7% | 219% | 389% |
| 不限速 | **1162** | 903 | 48% | 70% | 391% | 387% |

400 Mbps 及以下两边都不丢。800 和不限速 hy 更高、更不丢。

### 顶峰

![peak](docs/perf/peak.svg)

### 相同 400 Mbps 资源

![cpu-400](docs/perf/cpu-400.svg)

![rss-400](docs/perf/rss-400.svg)

| | hy | Go |
|---|---:|---:|
| rx | 399 Mbps | 399 Mbps |
| server CPU | 79% | 127% |
| client CPU | 39% | 121% |
| **server+client CPU** | **118%** | **248%** |
| server / client RSS | 11 / 12 MB | 23 / 23 MB |

同速 hy CPU 约 Go 的一半，RSS 约一半。数字只代表本沙箱 loopback。
