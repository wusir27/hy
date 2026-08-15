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
