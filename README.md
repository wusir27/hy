# hy — Hysteria 2 Rust rewrite

Protocol-compatible rewrite of [apernet/hysteria](https://github.com/apernet/hysteria) (v4 / Hysteria 2).

| Crate | Role |
|---|---|
| `hy-core` | Protocol codec, QUIC/CC hooks, Client/Server interfaces |
| `hy-extras` | Auth / ACL / outbound / sniff / masq / obfs (depends on hy-core) |
| `hy-app` | CLI + YAML + inbounds (not started) |

Dependency direction: `hy-app` → `hy-extras` → `hy-core`.

See `/workspace/hysteria-analysis-report.md` §8 for the rewrite blueprint.
