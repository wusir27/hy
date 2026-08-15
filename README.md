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

环境：8 vCPU / 16G，全部 `127.0.0.1`（测的是 CPU/用户态上限，不是网卡）。  
路径：TLS + `udpForwarding` / SOCKS5。对比包：`hy-linux-amd64` `6f6b458`（SHA `2ef5e360…`）vs hysteria v2.8.1。  
`udpForwarding` 持续流已修（慢发 20/20；修前只有首包）。

### 顶峰吞吐

![peak](docs/perf/peak.svg)

| 场景 | hy rx | Go rx |
|---|---:|---:|
| TLS+Salamander 400 Mbps（限速） | 398 | 398 |
| TLS+Salamander 800 Mbps（限速） | **775**（丢 3.7%） | 689（丢 14%） |
| TLS+Salamander **不限速** | 560 | 645 |
| **无 Salamander 不限速** | **1040** | 716 |
| TLS+Salamander TCP / SOCKS5 | 1322 | 1831 |

限速阶梯（`f2dec24`，TLS+Salamander 1200B）：

![udp-ladder](docs/perf/udp-ladder.svg)

| 目标 Mbps | hy rx | Go rx | hy 丢包 | Go 丢包 |
|---:|---:|---:|---:|---:|
| 20 | 20 | 20 | 0 | 0 |
| 50 | 50 | 50 | 0.001 | 0 |
| 100 | 100 | 100 | 0.001 | 0 |
| 200 | 200 | 200 | 0 | 0 |
| 400 | 399 | 399 | 0 | 0 |
| 800 | 777 | 793 | 0.035 | 0.015 |
| 不限速 | 561 | 851 | 0.80 | 0.68 |

400 Mbps 及以下两边都不丢。Salamander 不限速灌 hy 会先被入站打崩（~560）；去掉混淆后 hy 顶峰 **1040 > Go 716**。税在混淆路径，不在 GC。

### 相同 400 Mbps 下的资源（TLS+Salamander，两边不丢）

![cpu-400](docs/perf/cpu-400.svg)

![rss-400](docs/perf/rss-400.svg)

| | hy | Go |
|---|---:|---:|
| rx | 398 Mbps | 398 Mbps |
| server CPU | 98% | 156% |
| client CPU | 47% | 149% |
| **server+client CPU** | **146%** | **305%** |
| server RSS | 12 MB | 23 MB |
| client RSS | 13 MB | 22 MB |

同速 hy CPU 约 Go 的一半，RSS 约一半。

### 怎么读这些数

1. **顶峰**：有 Salamander 时 Go 更抗不限速灌；限速 800 和去掉混淆时 hy 不差或更高。
2. **同速资源**：hy 明显更省。所以「Rust 没 GC 却更慢」不成立——每字节更便宜，差在吃突发。
3. 入站小改（4MiB sockbuf / 去 `biased` / 256 有界队列）**没有**抬高 Salamander 不限速顶峰（仍 ~560）。
4. 数字只代表本沙箱 loopback，不能当公网线速。
