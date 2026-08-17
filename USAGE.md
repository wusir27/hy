# hy 使用文档

`hy` 是 [Hysteria 2](https://github.com/apernet/hysteria)（协议 v4）的 Rust 实现，配置字段与官方 YAML 对齐（camelCase）。二进制：`hy`。

本文只写**已实现**的能力。未实现项见文末。

---

## 1. 命令行

```
hy client [-c config.yaml]
hy server [-c config.yaml]
hy version
```

不写子命令时按 **client** 处理（对齐官方）。

| 参数 | 含义 |
|---|---|
| `-c` / `--config` | YAML 路径。省略时按当前目录约定查找（与官方一致时用 `-c` 最稳） |

退出：SIGINT / SIGTERM。服务端关闭码 `0x100`。

---

## 2. 环境变量

| 变量 | 含义 | 默认 |
|---|---|---|
| `HYSTERIA_LOG_LEVEL` | `debug` / `info` / `warn` / `error` | `info` |
| `HYSTERIA_LOG_FORMAT` | `json` / `console` | `console` |
| `HYSTERIA_ACME_DIR` | ACME 证书缓存目录 | 实现默认目录 |
| `HYSTERIA_UDPHOP_DEBUG` | port hop 调试 | 关 |

---

## 3. 通用格式

### 3.1 地址

| 写法 | 含义 |
|---|---|
| `127.0.0.1:443` | IPv4 |
| `[::1]:443` | IPv6 |
| `:443` | 全接口（服务端 listen 常用） |
| `example.com:443` | 域名（客户端 `server`） |
| `host:443,10000-20000` | 端口跳跃：逗号**第一项是主端口**，后面是 hop 集合 |
| `https://TOKEN@realm.example/id` | Realm：userinfo 是 **token**（必填），path 是 realm id |

### 3.2 带宽

`bandwidth.up` / `bandwidth.down`：

- `100mbps`、`1gbps`、`512kbps`、`100m`、`1g`
- 纯数字按 **B/s**

服务端 `ignoreClientBandwidth: true` 时忽略客户端申报，用本端配置。

### 3.3 时长

Go 风格：`30s`、`10s`、`2s`、`60s`。

### 3.4 认证（服务端 `auth`）

| `type` | 字段 | 行为 |
|---|---|---|
| `password` | `password` | 整串相等，用户 id 固定 `user` |
| `userpass` | `userpass: { 用户: 密码 }` | `user:pass`，用户名小写 |
| `http` | `http.url`、`http.insecure` | POST JSON `{addr,auth,tx}`，期望 `{ok,id}`，超时 10s |
| `command` | `command` | 执行命令，argv=`[cmd, addr, auth, tx]`，exit 0 且 stdout 为 id |

客户端 `auth` 是**字符串**（password 或 `user:pass`）。

### 3.5 出站 `direct.mode`

| 值 | 行为 |
|---|---|
| `auto` | 双栈竞速，先成功的赢（约 10s 超时） |
| `64` | 有 AAAA **只连 v6**，没有才 v4 |
| `46` | 有 A 只连 v4，没有才 v6 |
| `4` / `6` | 单栈，没有就 Dial 失败 |

### 3.6 ACL 一行一条

```
outbound(address)
outbound(address, protoPort)
outbound(address, protoPort, hijackIP)
```

- 先写先中；无匹配走名为 `default` 的出站（否则列表第一项）
- 内置名：`direct`、`reject`、`default`
- `address`：`*`、域名、`suffix:example.com`、CIDR、单 IP、通配
- `protoPort`：`tcp`、`udp`、`tcp/443`、`udp/1000-2000`、`*`
- `geoip:` / `geosite:` 吃 V2Ray `.dat`（`acl.geoip` / `acl.geosite`）。空路径按需下 Loyalsoldier（默认 7 天）。未知码启动失败，不会空匹配
- `#` 注释；`file` 与 `inline` 互斥

管道顺序锁死：**Speedtest → Resolver → ACL → (direct \| socks5 \| http)**。

---

## 4. 客户端字段

| 字段 | 含义 |
|---|---|
| `server` | 服务端地址，见 §3.1 |
| `auth` | 认证串 |
| `fastOpen` | `true` 时不等 TCP 响应就写（对齐官方） |
| `lazy` | `true`：进程先听 inbound，**第一条入站**才连服务端 |
| `tls.sni` | SNI |
| `tls.insecure` | 跳过证书校验 |
| `tls.pinSHA256` | 只校验叶子证书指纹 |
| `tls.ca` | 自定义 CA PEM |
| `tls.clientCertificate` / `clientKey` | mTLS |
| `quic.*Window` | 流/连接收窗，默认流 8MB、连接 20MB |
| `quic.maxIdleTimeout` | 默认 `30s` |
| `quic.keepAlivePeriod` | 默认 `10s` |
| `quic.disableChromeParrot` | `false`（默认）发零长 source CID；`true` 回到 8 字节 |
| `bandwidth` | 见 §3.2 |
| `congestion.type` | `bbr`（默认，可切 Brutal）或 `reno` |
| `congestion.bbrProfile` | `standard` / `conservative` / `aggressive`（能解析；当前同一套 quinn BBR） |
| `obfs.type` | `plain` / `salamander` / `gecko` |
| `obfs.salamander.password` | PSK，至少 4 字节 |
| `obfs.gecko.password` | 内层仍是 Salamander；只拆 QUIC 长头 |
| `obfs.gecko.minPacketSize` / `maxPacketSize` | 默认 512–1200 |
| `transport.udp.hopInterval` | hop 间隔，默认 `30s` |
| `realm.*` | STUN / punch，见场景 11 |
| `mimic.*` | Linux XDP 助手，见场景 12 |
| `socks5.listen` | 本地 SOCKS5 |
| `socks5.username` / `password` | 可选；不配则无认证 |
| `socks5.disableUDP` | 关 ASSOCIATE |
| `http.listen` | 本地 HTTP 代理（CONNECT / 绝对 URI GET） |
| `http.username` / `password` / `realm` | 可选 Basic |
| `tcpForwarding` | `[{ listen, remote }]` |
| `udpForwarding` | `[{ listen, remote, timeout }]`，timeout 默认 60s |
| `tcpRedirect` / `tcpTProxy` / `udpTProxy` | Linux 透明入口 |
| `tun` | 虚拟网卡入口 |

`tls.ech` **拒绝**（客户端顶层或 `tls.ech`；服务端 `tls.ech` / `tls.ech.key` 同样拒，不能吞掉）。

---

## 5. 服务端字段

| 字段 | 含义 |
|---|---|
| `listen` | UDP 监听，默认 `:443`。hop 语法只绑**第一项**主端口 |
| `tls.cert` / `tls.key` | PEM；与 `acme` 互斥 |
| `tls.clientCA` | 要求客户端证书 |
| `acme` | HTTP-01 / TLS-ALPN-01，见场景 9。`type: dns` 未实现 |
| `obfs` | 同客户端 |
| `auth` | 见 §3.4 |
| `bandwidth` / `ignoreClientBandwidth` | 见 §3.2 |
| `disableUDP` | 官方字段名（注意大小写）。`true` 时握手 `Hysteria-UDP: false`，UDP 拒、TCP 仍通 |
| `udpIdleTimeout` | UDP 会话空闲回收，默认 `60s` |
| `speedTest` | `true` 允许目标 `@speedtest`（仅 TCP） |
| `resolver.type` | `system` / `tcp` / `udp` / `tls` / `https` |
| `resolver.*.addr` / `timeout` | 非 system 时的上游 |
| `sniff.enable` | 嗅探 HTTP Host / TLS SNI / QUIC SNI |
| `sniff.timeout` | 默认 `4s` |
| `sniff.rewriteDomain` | `true` 才改写 `req_addr` 的 host |
| `sniff.tcpPorts` / `udpPorts` | 如 `80,443,8000-9000`；`@` 前缀目标跳过 |
| `acl.file` / `acl.inline` | 规则；`inline` 是字符串序列；二者互斥 |
| `acl.geoip` / `acl.geosite` | V2Ray `.dat` 路径。省略则 cwd 下 `geoip.dat` / `geosite.dat`，按需自动下载 |
| `acl.geoUpdateInterval` | 仅自动下载：文件超过这个时间再下，默认 7 天 |
| `outbounds` | `direct` / `socks5` / `http` |
| `trafficStats.listen` / `secret` | 统计 HTTP。`Authorization` 头**等于** secret（不是 Bearer） |
| `masquerade.type` | 空/`404`、`string`、`file`、`proxy` |
| `masquerade.listenHTTP` / `listenHTTPS` | 额外 TCP 伪装站，带 `Alt-Svc: h3` |
| `masquerade.forceHTTPS` | 301 |

`ech` **拒绝**。

统计 API：

| 方法 | 路径 | 含义 |
|---|---|---|
| GET | `/` | 说明页 |
| GET | `/traffic` | 每用户 tx/rx；`?clear=1` 清零 |
| GET | `/online` | 在线数 |
| POST | `/kick` | JSON 用户 id 列表，**懒踢**（下次流量才断） |
| GET | `/dump/streams` | 流状态 |

测速（`speedTest: true`）：SOCKS5 CONNECT `@speedtest`。下行 `0x01 + u32 BE`；上行 `0x02`。UDP 对 `@speedtest` 拒绝。

---

## 6. 场景（由简到繁）

以下证书路径请换成自己的 PEM。自签示例：

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```

### 场景 1 — 最小可跑（password + SOCKS5）

服务端 `server.yaml`：

```yaml
listen: 127.0.0.1:443
tls:
  cert: server.crt
  key: server.key
auth:
  type: password
  password: secret
```

客户端 `client.yaml`：

```yaml
server: 127.0.0.1:443
auth: secret
tls:
  sni: localhost
  insecure: true
socks5:
  listen: 127.0.0.1:1080
```

```bash
hy server -c server.yaml
hy client -c client.yaml
# curl -x socks5h://127.0.0.1:1080 https://example.com
```

`insecure: true` 只适合自签/试验。生产用 `tls.ca` 或公网证书。

### 场景 2 — 延迟连接 + 本机端口转发

客户端先听本地口，**第一条流量**才握手（`lazy: true`）：

```yaml
server: 127.0.0.1:443
auth: secret
lazy: true
tls: { sni: localhost, insecure: true }
tcpForwarding:
  - listen: 127.0.0.1:2222
    remote: 127.0.0.1:22
udpForwarding:
  - listen: 127.0.0.1:5353
    remote: 1.1.1.1:53
    timeout: 60s
```

对照：`lazy: false` 且服务端未起时，进程会卡在 connect，不听 inbound。

### 场景 3 — 带宽协商与拥塞

```yaml
# 服务端
listen: :443
tls: { cert: server.crt, key: server.key }
auth: { type: password, password: secret }
bandwidth: { up: 1gbps, down: 1gbps }
# ignoreClientBandwidth: true   # 强制用本端
```

```yaml
# 客户端
server: example.com:443
auth: secret
tls: { sni: example.com }
bandwidth: { up: 100mbps, down: 500mbps }
congestion:
  type: bbr
  bbrProfile: standard
```

双方都报了带宽且未 `ignoreClientBandwidth` 时走 Brutal；否则 BBR。`bbrProfile` 三档都能解析，当前同一套 quinn BBR，不要按档位调参。

### 场景 4 — Salamander 混淆

PSK 双方相同，至少 4 字节：

```yaml
# 两端都加
obfs:
  type: salamander
  salamander:
    password: "correct-horse-battery"
```

### 场景 5 — 多用户、统计、测速、HTTP 代理

```yaml
# server.yaml
listen: :443
tls: { cert: /c.pem, key: /k.pem }
auth:
  type: userpass
  userpass:
    alice: wonder
    bob: builder
speedTest: true
trafficStats:
  listen: 127.0.0.1:9999
  secret: s3cret
masquerade:
  type: string
  string:
    status: 200
    headers:
      Content-Type: text/plain
    content: "hello"
```

```yaml
# client.yaml
server: example.com:443
auth: "alice:wonder"
tls: { sni: example.com }
socks5: { listen: 127.0.0.1:1080 }
http:
  listen: 127.0.0.1:8080
  username: local
  password: localpass
```

```bash
# 统计：Authorization 必须原样等于 secret
curl -H 'Authorization: s3cret' http://127.0.0.1:9999/traffic
curl -H 'Authorization: s3cret' http://127.0.0.1:9999/online
# 懒踢
curl -H 'Authorization: s3cret' -d '["alice"]' http://127.0.0.1:9999/kick

# 测速：SOCKS5 CONNECT 目标 @speedtest（仅 TCP）
```

未带正确 `Hysteria-Auth` 的 HTTP/3 请求走伪装（看起来像普通站点）。

### 场景 6 — 嗅探 + ACL + 多出站 + 指定 DNS

客户端连的是 IP，但 TLS SNI / HTTP Host 是域名时，打开 sniff 再给 ACL 用：

```yaml
# server.yaml
listen: :443
tls: { cert: /c.pem, key: /k.pem }
auth: { type: password, password: secret }
resolver:
  type: udp
  udp: { addr: 8.8.8.8:53, timeout: 5s }
sniff:
  enable: true
  timeout: 4s
  rewriteDomain: true
  tcpPorts: "80,443"
  udpPorts: "443"
acl:
  inline:
    - "reject(suffix:ads.example)"
    - "proxy(suffix:example.com)"
    - "direct(*)"
outbounds:
  - name: default
    type: direct
    direct: { mode: auto }
  - name: proxy
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
      username: ""
      password: ""
  # HTTP 出站用 url，不是 addr：
  # - name: proxy
  #   type: http
  #   http: { url: http://127.0.0.1:8080, insecure: false }
```

- SOCKS5 出站字段是 `socks5.addr`；HTTP 出站字段是 `http.url`（写 `addr` 会拒）。
- SOCKS5/HTTP **出站**把 hostname 交给上游，不强制本地解析。
- HTTP 出站不能做 UDP（`http outbound is tcp only`）。
- 有 ACL 时必须包一层 Resolver（system 或上面的 udp/tcp/tls/https）。

### 场景 6b — 服务端按国家 / 站点分流（Geo）

只在**服务端** ACL 里写。客户端没有 `acl.geoip`。`geoip:` 看的是解析后的 IP，所以前面必须有 Resolver（有 ACL 时本来就会包一层）。

```yaml
# server.yaml
listen: :443
tls: { cert: /c.pem, key: /k.pem }
auth: { type: password, password: secret }
acl:
  inline:
    - "reject(geoip:cn)"           # 中国 IP 拒绝
    - "direct(geosite:google@cn)"  # google 列表里带 cn 属性的域名直连
    - "direct(geosite:google)"
    - "default(*)"
  geoip: /var/lib/hy/geoip.dat      # 指定路径：只读这份，不下载
  geosite: /var/lib/hy/geosite.dat
  # geoUpdateInterval: 168h         # 仅路径省略时有用
```

路径**省略**时，进程工作目录找 `geoip.dat` / `geosite.dat`；没有或超过 7 天，会从 Loyalsoldier 下：

`https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat`  
`https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat`

写法：

- `geoip:cn` / `geoip:us` / `geoip:private`（码小写；`geoip:JP` 也可以，编译时会折成小写）
- `geosite:google`、`geosite:google@cn`（多个 `@attr` 是 AND）
- 库里没有这个码、文件读不开：启动失败，带行号。不会当成「没这条规则」

先写先中。`geoip` 只匹配 IP，域名还没解析出地址时不中（除非 dat 里是 inverse）。`geosite` 只匹配域名。

### 场景 7 — 文件/反代伪装 + Alt-Svc

```yaml
masquerade:
  type: file
  file:
    dir: /var/www/hy
  listenHTTP: :80
  listenHTTPS: :8443
  forceHTTPS: true
```

或反代：

```yaml
masquerade:
  type: proxy
  proxy:
    url: https://example.com
    rewriteHost: true
    insecure: false
  listenHTTP: :80
```

未认证 GET `/` 返回伪装内容，并带 `Alt-Svc: h3=":<quic端口>"; ma=2592000`。已认证 233 不受影响。

### 场景 8 — 端口跳跃 + Gecko

服务端只绑**主端口**（逗号第一项）。其余端口靠 iptables/nft DNAT 到主端口（本进程不做 iptables）。
客户端 hop **从主端口起跳**；没有 DNAT 时只有打到第一项才能通，随机打到 hop 口会丢。本机试验可以只写主端口、或 hop 集合但保证第一项就是实际监听口。

```yaml
# server.yaml
listen: :443,10000-20000
tls: { cert: /c.pem, key: /k.pem }
auth: { type: password, password: secret }
obfs:
  type: gecko
  gecko:
    password: "correct-horse-battery"
    minPacketSize: 512
    maxPacketSize: 1200
```

```yaml
# client.yaml
server: example.com:443,10000-20000
auth: secret
tls: { sni: example.com }
transport:
  type: udp
  udp:
    hopInterval: 30s
obfs:
  type: gecko
  gecko:
    password: "correct-horse-battery"
socks5: { listen: 127.0.0.1:1080 }
```

Gecko 只拆 QUIC **长头**，短头原样；内层仍是 Salamander。`mimic` 与 hop **互斥**。

### 场景 9 — ACME（HTTP-01 / TLS-ALPN-01）

与 `tls.cert` / `tls.key` **互斥**。需要公网域名指到本机，80（http）或 443（tls）可被 CA 访问。

```yaml
listen: :443
acme:
  domains: [hy.example.com]
  email: you@example.com
  ca: letsencrypt
  type: http          # 或 tls
auth:
  type: password
  password: secret
```

```bash
export HYSTERIA_ACME_DIR=/var/lib/hy/acme
hy server -c server.yaml
```

`type: dns` 及 Cloudflare 等提供方：**未实现**，会明确报错。

### 场景 10 — Linux 透明代理 / TUN

需要 `CAP_NET_ADMIN`。TPROXY 还要内核 `xt_TPROXY`（或等价 nft）。

**REDIRECT**（iptables 改目的端口，进程用 `SO_ORIGINAL_DST`）：

```yaml
# client.yaml 片段
tcpRedirect:
  listen: 127.0.0.1:12345
```

```bash
# 示例：把到 80 的流量 REDIRECT 到 hy
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 12345
```

**TPROXY**：

```yaml
tcpTProxy: { listen: :12345 }
udpTProxy: { listen: :12345, timeout: 60s }
```

非 Linux 配置这些键会 `not supported`。

**TUN**：

```yaml
tun:
  name: hy0
  mtu: 1500
  timeout: 60s
  address:
    ipv4: 100.100.100.1/30
  route:
    strict: false
    ipv4: [0.0.0.0/0]
```

无特权时会打明确错误（如 `failed to create tun interface`），不会静默空转。ICMP 不代理。

**Darwin utun**（P6.D1，对齐官方 Darwin CLI）：`name` 必须是 `utun` 加数字（`utun123`），不能写 `hy0`。创建走 `com.apple.net.utun_control`。配地址 / 加路由需要 `sudo`；失败要明确报错，不会留空接口。

```yaml
tun:
  name: utun123
  mtu: 1500
  timeout: 5m
  address:
    ipv4: 100.100.100.101/30
    ipv6: "2001::ffff:ffff:ffff:fff1/126"
  route:
    ipv4Exclude: ["<server-ip>/32"]   # 防环路；不自动填
```

没有 `route:` 只建接口、不加路由。有 `route:` 但没写 `ipv4` 时，官方 Darwin 会装 `1.0.0.0/8`…`128.0.0.0/1`（不含 `0.0.0.0/8`），不是直接改默认路由。显式 `route.ipv4: [0.0.0.0/0]` 才会装默认路由，这时必须自己 exclude 服务器地址。

### 场景 11 — Realm（NAT 穿透）

`server` / `listen` 写成 Realm URL。本实现**不自带**信令服务，只做 hy 侧 STUN → 官方 `/v1/{id}` → punch。

```yaml
# 客户端。token 写在 userinfo，缺了会报 realm token is required
server: https://your-token@realm.example/your-id
auth: secret
realm:
  stunServers: ["stun.l.google.com:19302"]
  stunTimeout: 5s
  punchTimeout: 10s
  insecure: false
  ipMode: dual
socks5: { listen: 127.0.0.1:1080 }
```

Punch 与 QUIC 共用同一 UDP。`PunchPacketConn` 只拦截已注册的 punch 包，STUN / QUIC 从 `recv_from` 原样出来。

### 场景 12 — Mimic（Linux XDP）+ Chrome 指纹

需要单独安装 [hack3ric/mimic](https://github.com/hack3ric/mimic)，hy **只拉起进程**，不重写 XDP。

```yaml
# 客户端；不要同时开 hop
server: 203.0.113.10:443
auth: secret
tls: { sni: example.com }
quic:
  disableChromeParrot: false    # 默认：零长 source CID
mimic:
  enabled: true
  interface: eth0
  xdpMode: native
  path: /usr/bin/mimic
  extraArgs: []
socks5: { listen: 127.0.0.1:1080 }
```

实际 argv：

```
/usr/bin/mimic run eth0 -f remote=203.0.113.10:443 --xdp-mode native
```

服务端 filter 为 `local=ip:port,handshake=0:3`。`enabled: false` 不启动。`path` 空则找 `PATH` 里的 `mimic`。非 Linux / 找不到二进制会明确报错。

---

## 7. 互操作注意

- 官方客户端/服务端可以和 hy 互打 TCP/UDP（含 ≥1400B UDP）。
- QUIC datagram **对外广告**固定 `max_datagram_frame_size=1200`，本端收窗另算。不要改这个。
- 字段名必须官方写法：`disableUDP`、`fastOpen`、`speedTest`、`bbrProfile`、`hopInterval`。
- SOCKS5 认证：对的 user/pass 通；错的 `01 01`；不带 `05 ff`。
- HTTP 统计：`Authorization: s3cret` 为 200，`Bearer s3cret` 为 401。

---

## 8. 本实现明确不做

| 项 | 行为 |
|---|---|
| `tls.ech` / `ech` | 拒绝 |
| ACME `type: dns` | `unimplemented` |
| 出站链式多跳 | 只有单跳 socks5/http |
| Chrome 以外的 QUIC 指纹 | 不做 |

---

## 9. 最小对照表

| 你想做 | 打开这些 |
|---|---|
| 浏览器走代理 | 服务端 password + 客户端 `socks5` 或 `http` |
| 只转一个端口 | `tcpForwarding` / `udpForwarding` |
| 抗探测 | `obfs.salamander` 或 `gecko` + `masquerade` |
| 限制网站 | `acl.inline` + `resolver` + 可选 `sniff` |
| 按国家/站点分流 | 服务端 `acl.geoip` / `geosite` + `reject(geoip:cn)` / `direct(geosite:google)` |
| 看用量 / 踢人 | `trafficStats` |
| 测速 | `speedTest: true`，连 `@speedtest` |
| 证书自动签 | `acme.type: http` 或 `tls`（要公网域名） |
| 全局接管 | Linux `tun` / `tcpRedirect` / `tproxy`；Darwin `tun.name: utunN`（要 sudo） |
| NAT 两边直连 | Realm URL + 外部信令 |
| 伪装成 Chrome QUIC | 默认 parrot；Linux 再加 `mimic` |
