# hy — Hysteria 2 Rust rewrite

Protocol-compatible rewrite of [apernet/hysteria](https://github.com/apernet/hysteria) (v4 / Hysteria 2).

**使用说明（参数、场景示例）：[USAGE.md](USAGE.md)**

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

Release binaries: [v0.2.0](https://github.com/wusir27/hy/releases/tag/v0.2.0)（Linux 五套 + Darwin 两套）。

---

## 沙箱性能（hy 0.2.0 vs 官方 Go v2.8.1）

环境：8 vCPU / 16G，全部 `127.0.0.1`（CPU/用户态上限，不是网卡）。  
对比：`hy-linux-amd64` `6fa6a40`（SHA `ecc62dd2…`）vs hysteria v2.8.1。路径：TLS + `udpForwarding`。

### 顶峰吞吐

![peak](docs/perf/peak.svg)

| 场景 | hy rx | Go rx |
|---|---:|---:|
| TLS+Salamander 400 Mbps（限速） | 398 | 398 |
| TLS+Salamander **不限速** | **1050** | 811 |
| 无 Salamander 不限速（上一闸） | 1040 | 716 |

Salamander 热路径修好后，不限速顶峰从 **560 → 1050 Mbps**，高于 Go。

限速阶梯（`f2dec24`，修好持续流之后）：

![udp-ladder](docs/perf/udp-ladder.svg)

| 目标 Mbps | hy rx | Go rx |
|---:|---:|---:|
| 20–400 | 对齐、不丢 | 对齐、不丢 |
| 800 | 777 | 793 |
| 不限速（当时） | 561 | 851 |

### 相同 400 Mbps 下的资源（TLS+Salamander）

![cpu-400](docs/perf/cpu-400.svg)

![rss-400](docs/perf/rss-400.svg)

| | hy | Go |
|---|---:|---:|
| rx | 398 Mbps | 398 Mbps |
| server CPU | 85% | 154% |
| client CPU | 41% | 144% |
| **server+client CPU** | **127%** | **297%** |
| server / client RSS | 11 / 12 MB | 24 / 23 MB |

同速 hy CPU 约 Go 的 **43%**，RSS 约一半。

### 怎么读

1. 带 Salamander 不限速：hy 1050 > Go 811（`6fa6a40`）。
2. 同速资源：hy 一直更省。
3. 数字只代表本沙箱 loopback。
