# hy 使用说明

`hy` 是 [Hysteria 2](https://github.com/apernet/hysteria) 的 Rust 版。配置文件用 YAML，字段名和官方一样（驼峰，例如 `fastOpen`）。

下面只写**已经能用**的功能。还不支持的列在文末。

---

## 最快上手

先做一张自签证书（仅本机试验）：

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```

**服务端** `server.yaml`：

```yaml
listen: 127.0.0.1:443
tls:
  cert: server.crt
  key: server.key
auth:
  type: password
  password: secret
```

**客户端** `client.yaml`：

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
curl -x socks5h://127.0.0.1:1080 https://example.com
```

`insecure: true` 会跳过证书检查，只适合自签或本机试验。正式环境请用受信任的证书，或在客户端指定 `tls.ca`。

浏览器把 SOCKS5 代理指到 `127.0.0.1:1080` 即可上网。

---

## 1. 命令

```
hy client -c 配置.yaml
hy server -c 配置.yaml
hy version
```

不写 `client` / `server` 时，按客户端启动。建议始终加上 `-c`，以免找不到配置文件。

用 Ctrl+C 或发 SIGTERM 退出。

---

## 2. 环境变量

| 变量 | 作用 | 默认 |
|---|---|---|
| `HYSTERIA_LOG_LEVEL` | 日志级别：`debug` / `info` / `warn` / `error` | `info` |
| `HYSTERIA_LOG_FORMAT` | `json` 或 `console` | `console` |
| `HYSTERIA_ACME_DIR` | 自动签证书时，证书缓存目录 | 程序默认目录 |
| `HYSTERIA_UDPHOP_DEBUG` | 打开端口跳跃的调试日志 | 关 |

日常把 `HYSTERIA_LOG_LEVEL=info` 即可。排查连不上时再改成 `debug`。

---

## 3. 配置里怎么写

### 3.1 地址

| 写法 | 意思 |
|---|---|
| `127.0.0.1:443` | IPv4 |
| `[::1]:443` | IPv6 |
| `:443` | 本机所有网卡的 443（服务端常用） |
| `example.com:443` | 域名（客户端的 `server`） |
| `host:443,10000-20000` | 端口跳跃：逗号**第一项是主端口**，后面是备用端口范围 |
| `https://令牌@realm.example/房间id` | Realm 穿透：`@` 前面是令牌（必填），路径是房间 id |

### 3.2 带宽

`bandwidth.up` / `bandwidth.down` 可以写：

- `100mbps`、`1gbps`、`512kbps`
- `100m`、`1g`（按比特率理解）
- 纯数字按 **字节/秒**

服务端若写 `ignoreClientBandwidth: true`，就不管客户端报了多少，只用服务端自己的配置。

### 3.3 时间

和常见 Go 程序一样：`30s`、`10s`、`2s`、`60s`、`5m`。

### 3.4 服务端怎么验密码（`auth`）

| `type` | 怎么配 | 效果 |
|---|---|---|
| `password` | `password: 一串密码` | 整串对上就算过，用户名记成 `user` |
| `userpass` | `userpass: { 用户名: 密码 }` | 客户端写成 `用户名:密码`；用户名按小写比 |
| `http` | `http.url`、可选 `http.insecure` | 向这个 URL POST `{addr,auth,tx}`，期望返回 `{ok,id}`，10 秒超时 |
| `command` | `command: 可执行文件` | 执行该命令，参数是地址、密码、带宽；退出码 0 且标准输出是用户 id 才算过 |

客户端的 `auth` 就是一个**字符串**：共享密码，或多用户时写成 `alice:wonder`。

### 3.5 服务端直连出站（`direct.mode`）

访问目标网站时，服务端怎么选 IPv4 / IPv6：

| 值 | 行为 |
|---|---|
| `auto` | IPv4、IPv6 一起试，谁先通则用谁（大约 10 秒） |
| `64` | 有 IPv6 地址就只走 IPv6，没有才用 IPv4 |
| `46` | 有 IPv4 就只走 IPv4，没有才用 IPv6 |
| `4` / `6` | 只用这一栈，没有对应地址就失败 |

### 3.6 访问控制（ACL）

一行一条规则，**写在上面的先匹配**：

```
动作(地址)
动作(地址, 协议或端口)
动作(地址, 协议或端口, 劫持到这个IP)
```

- 动作：`direct`（直连）、`reject`（拒绝）、或你在 `outbounds` 里起的名字。没匹配到的走名为 `default` 的出站；没有 `default` 就走列表里第一个。
- 地址：`*`（任意）、完整域名、`suffix:example.com`（这个后缀）、单个 IP、网段（CIDR）、通配。
- 协议端口：`tcp`、`udp`、`tcp/443`、`udp/1000-2000`、`*`。
- `geoip:` / `geosite:` 用 V2Ray 的 `.dat` 库（路径写在 `acl.geoip` / `acl.geosite`）。不写路径时，会按需下载公开规则库（默认每 7 天最多下一次）。库里没有这个国家/站点码会**启动失败**，不会假装没这条规则。
- `#` 开头是注释。`acl.file`（从文件读）和 `acl.inline`（写在配置里）不能同时用。

请求在服务端的处理顺序固定：测速特殊目标 → DNS 解析 → ACL → 真正出站（直连 / SOCKS5 / HTTP）。

---

## 4. 客户端配置项

| 字段 | 说明 |
|---|---|
| `server` | 服务端地址，写法见上面「地址」 |
| `auth` | 密码，或多用户时的 `用户名:密码` |
| `fastOpen` | `true`：还没等到服务端确认 TCP 就先传数据，延迟更低 |
| `lazy` | `true`：程序先在本地听端口，**有第一条流量**才去连服务端 |
| `tls.sni` | TLS 握手时声明的域名 |
| `tls.insecure` | `true` 不检查证书（仅试验） |
| `tls.pinSHA256` | 只认这一枚叶子证书的指纹 |
| `tls.ca` | 自定义 CA 的 PEM 文件 |
| `tls.clientCertificate` / `clientKey` | 双向证书认证 |
| `quic.*Window` | 收包窗口。默认单条流 8MB、整条连接 20MB |
| `quic.maxIdleTimeout` | 多久没流量就断开，默认 `30s` |
| `quic.keepAlivePeriod` | 心跳间隔，默认 `10s` |
| `quic.disableChromeParrot` | 默认 `false`：连接 ID 长度模仿 Chrome；`true` 则用普通 8 字节 |
| `bandwidth` | 见「带宽」 |
| `congestion.type` | `bbr`（默认）或 `reno` |
| `congestion.bbrProfile` | `standard` / `conservative` / `aggressive`（都能识别，目前实际是同一套 BBR） |
| `obfs.type` | 混淆：`plain`（不混淆）/ `salamander` / `gecko` |
| `obfs.salamander.password` | 双方相同的密钥，至少 4 个字符 |
| `obfs.gecko.password` | 内层仍是 Salamander，只改 QUIC 长包头的外观 |
| `obfs.gecko.minPacketSize` / `maxPacketSize` | 默认 512–1200 |
| `transport.udp.hopInterval` | 端口跳跃间隔，默认 `30s` |
| `realm.*` | NAT 穿透，见场景 11 |
| `mimic.*` | Linux 上把流量伪装成 Chrome QUIC，见场景 12 |
| `socks5.listen` | 本机 SOCKS5 代理地址 |
| `socks5.username` / `password` | 可选；不写则本地代理不设密码 |
| `socks5.disableUDP` | `true` 则 SOCKS5 不支持 UDP |
| `http.listen` | 本机 HTTP 代理（浏览器 CONNECT） |
| `http.username` / `password` / `realm` | 可选的 HTTP 基本认证 |
| `tcpForwarding` | `[{ listen, remote }]`，把本地 TCP 转到对面某个地址 |
| `udpForwarding` | `[{ listen, remote, timeout }]`，`timeout` 默认 60s |
| `tcpRedirect` / `tcpTProxy` / `udpTProxy` | Linux 透明代理入口 |
| `tun` | 虚拟网卡，让系统流量进隧道 |

配置里出现 `tls.ech` 或顶层 `ech` 会直接拒绝启动（服务端同样）。这是刻意不支持，不是漏配。

---

## 5. 服务端配置项

| 字段 | 说明 |
|---|---|
| `listen` | 监听的 UDP 地址，默认 `:443`。写端口跳跃时，进程只绑**第一项**主端口 |
| `tls.cert` / `tls.key` | 证书和私钥（PEM）。和下面的 `acme` 不能一起用 |
| `tls.clientCA` | 要求客户端也出示证书 |
| `acme` | 自动向 Let's Encrypt 等申请证书，见场景 9。DNS 验证方式暂不支持 |
| `obfs` | 和客户端相同 |
| `auth` | 见「服务端怎么验密码」 |
| `bandwidth` / `ignoreClientBandwidth` | 见「带宽」 |
| `disableUDP` | 官方字段名，注意大小写。`true` 时只代理 TCP，UDP 会被拒绝 |
| `udpIdleTimeout` | UDP 会话闲置多久回收，默认 `60s` |
| `speedTest` | `true` 允许用特殊目标 `@speedtest` 测速（仅 TCP） |
| `resolver.type` | DNS：`system` / `tcp` / `udp` / `tls` / `https` |
| `resolver.*.addr` / `timeout` | 不用系统 DNS 时的上游地址 |
| `sniff.enable` | 从流量里识别 HTTP Host、TLS/QUIC 的域名 |
| `sniff.timeout` | 默认 `4s` |
| `sniff.rewriteDomain` | `true` 时用嗅探到的域名替换原来的目标主机名 |
| `sniff.tcpPorts` / `udpPorts` | 例如 `80,443,8000-9000`；目标以 `@` 开头的不嗅探 |
| `acl.file` / `acl.inline` | 访问规则。`inline` 是字符串列表。两者不能同时写 |
| `acl.geoip` / `acl.geosite` | 地理规则库路径。省略则在运行目录找 `geoip.dat` / `geosite.dat`，没有就自动下载 |
| `acl.geoUpdateInterval` | 仅自动下载时：文件超过这个时间才再下，默认 7 天 |
| `outbounds` | 出站列表：`direct` / `socks5` / `http` |
| `trafficStats.listen` / `secret` | 流量统计网页。请求头 `Authorization` 必须**原样等于** secret（不要加 `Bearer`） |
| `masquerade.type` | 未通过认证时假装成网站：空/`404`、`string`、`file`、`proxy` |
| `masquerade.listenHTTP` / `listenHTTPS` | 额外开一个普通网站端口，并提示浏览器还有 HTTP/3 |
| `masquerade.forceHTTPS` | HTTP 访问时 301 跳到 HTTPS |

统计接口：

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/` | 简短说明 |
| GET | `/traffic` | 每用户上传/下载；加 `?clear=1` 会清零计数 |
| GET | `/online` | 当前在线人数 |
| POST | `/kick` | JSON 用户 id 列表。不会立刻踢，等该用户下次有流量再断开 |
| GET | `/dump/streams` | 当前每条流的状态 |

测速：服务端打开 `speedTest: true` 后，用 SOCKS5 连接目标 `@speedtest`（只支持 TCP，不支持 UDP）。

---

## 6. 更多场景

### 场景 2 — 有流量才连服务器 + 端口转发

`lazy: true`：程序先在本地听着，直到有人真正来连，才去握手服务器。

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

如果 `lazy: false` 而服务端还没启动，客户端会卡在连接，本地端口也不会开始听。

### 场景 3 — 带宽和拥塞控制

```yaml
# 服务端
listen: :443
tls: { cert: server.crt, key: server.key }
auth: { type: password, password: secret }
bandwidth: { up: 1gbps, down: 1gbps }
# ignoreClientBandwidth: true   # 取消注释则强制用服务端数字
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

双方都写了带宽、且服务端没有 `ignoreClientBandwidth` 时，用 Brutal（按声明速率发送）。否则用 BBR。`bbrProfile` 三个词都能写，目前效果相同，不必按档位细调。

### 场景 4 — Salamander 混淆

两端密码必须相同，至少 4 个字符。用来让包看起来不像普通 QUIC：

```yaml
obfs:
  type: salamander
  salamander:
    password: "correct-horse-battery"
```

### 场景 5 — 多用户、看流量、测速、本机 HTTP 代理

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
# Authorization 必须和 secret 完全一样，不要写成 Bearer
curl -H 'Authorization: s3cret' http://127.0.0.1:9999/traffic
curl -H 'Authorization: s3cret' http://127.0.0.1:9999/online
curl -H 'Authorization: s3cret' -d '["alice"]' http://127.0.0.1:9999/kick
```

没带正确密码的访问，会看到伪装站点内容，而不是报「认证失败」。

### 场景 6 — 按域名分流（嗅探 + ACL + DNS）

客户端有时只告诉服务端一个 IP，真正的网站名在 TLS/HTTP 里头。打开 sniff，ACL 才能按域名判断：

```yaml
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
  # HTTP 出站用 url，不要写 addr：
  # - name: proxy
  #   type: http
  #   http: { url: http://127.0.0.1:8080, insecure: false }
```

注意：

- SOCKS5 出站写 `socks5.addr`；HTTP 出站写 `http.url`（写成 `addr` 会启动失败）。
- 走 SOCKS5/HTTP 出站时，域名由上游解析，不强制在本机查 DNS。
- HTTP 出站不能转发 UDP。
- 只要配了 ACL，就必须有 DNS（`resolver`，或至少用系统 DNS）。

### 场景 6b — 按国家或网站列表分流

这些规则只写在**服务端**。客户端没有 `acl.geoip`。`geoip:` 看的是解析后的 IP，所以必须先有 DNS。

```yaml
listen: :443
tls: { cert: /c.pem, key: /k.pem }
auth: { type: password, password: secret }
acl:
  inline:
    - "reject(geoip:cn)"           # 中国 IP 拒绝
    - "direct(geosite:google@cn)"  # Google 列表里带 cn 标记的域名直连
    - "direct(geosite:google)"
    - "default(*)"
  geoip: /var/lib/hy/geoip.dat      # 指定文件：只用这份，不会自动下载
  geosite: /var/lib/hy/geosite.dat
```

不写路径时，在运行目录找 `geoip.dat` / `geosite.dat`；没有或超过 7 天，会下载：

- https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat
- https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat

写法：`geoip:cn`、`geoip:us`、`geoip:private`（大小写无所谓）；`geosite:google`、`geosite:google@cn`（多个 `@` 条件要同时满足）。库里没有这个码、或文件打不开：启动失败，并告诉你是哪一行。

`geoip` 只匹配已经是 IP 的目标；还是域名、尚未解析时不会命中。`geosite` 只匹配域名。

### 场景 7 — 把未认证访问伪装成网站

```yaml
masquerade:
  type: file
  file:
    dir: /var/www/hy
  listenHTTP: :80
  listenHTTPS: :8443
  forceHTTPS: true
```

或反代到别的网站：

```yaml
masquerade:
  type: proxy
  proxy:
    url: https://example.com
    rewriteHost: true
    insecure: false
  listenHTTP: :80
```

没通过认证的人打开会看到这些内容。正常用户登录不受影响。

### 场景 8 — 端口跳跃 + Gecko 混淆

服务端进程只监听**主端口**（逗号前面那一个）。其它端口需要你自己用防火墙规则转到主端口，hy 不会改系统防火墙。

客户端会从主端口开始，按间隔换端口试。如果系统没有把 hop 端口转到主端口，只有打到第一项才能连上。本机试验可以只写主端口。

```yaml
# 服务端
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
# 客户端
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

Gecko 只改 QUIC 连接刚开始的长包头，后续短包不变；里面仍是 Salamander。`mimic` 和端口跳跃不能同时开。

### 场景 9 — 自动申请证书

不能和手写的 `tls.cert` / `tls.key` 一起用。域名的 DNS 要指到这台机器，并且 80（http 验证）或 443（tls 验证）能被证书颁发机构访问到。

```yaml
listen: :443
acme:
  domains: [hy.example.com]
  email: you@example.com
  ca: letsencrypt
  type: http          # 也可以写 tls
auth:
  type: password
  password: secret
```

```bash
export HYSTERIA_ACME_DIR=/var/lib/hy/acme
hy server -c server.yaml
```

通过 DNS 记录验证、以及 Cloudflare 等 DNS 服务商：**目前不支持**，配置了会明确报错。

### 场景 10 — Linux 透明代理 / 虚拟网卡

需要管理员权限（`CAP_NET_ADMIN`）。TPROXY 还需要内核支持。

**REDIRECT**（用 iptables 把目的端口改过来）：

```yaml
tcpRedirect:
  listen: 127.0.0.1:12345
```

```bash
# 示例：本机访问 80 端口的 TCP，转到 hy
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 12345
```

**TPROXY**：

```yaml
tcpTProxy: { listen: :12345 }
udpTProxy: { listen: :12345, timeout: 60s }
```

在非 Linux 系统上写这些项，会提示不支持。

**Linux 虚拟网卡（TUN）**：

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

没有权限时会打出明确错误（例如创建网卡失败），不会假装已经在工作。ping（ICMP）不会走隧道。

**macOS 虚拟网卡**：名字必须是 `utun` 加数字，例如 `utun123`，不能写成 `hy0`。配地址和加路由需要 `sudo`。失败会报错，不会留下半残网卡。

```yaml
tun:
  name: utun123
  mtu: 1500
  timeout: 5m
  address:
    ipv4: 100.100.100.101/30
    ipv6: "2001::ffff:ffff:ffff:fff1/126"
  route:
    ipv4Exclude: ["<服务器公网IP>/32"]   # 避免流量绕回自己；不会自动填写
```

不写 `route:` 就只建网卡、不加路由。写了 `route:` 但没写 `ipv4` 时，会加上一批拆开的默认路由（和官方 macOS 客户端一样），不是直接改「默认网关」那一条。只有显式写 `route.ipv4: [0.0.0.0/0]` 才会装真正的默认路由，这时务必把服务器 IP 写进 `ipv4Exclude`，否则会环路。

### 场景 11 — Realm（两台都在 NAT 后面时打洞）

把 `server` 或 `listen` 写成 Realm 地址。hy **不自带**中转信令服务，需要你另有一套 Realm 服务：本机先问 STUN 自己的公网地址，再找信令交换，然后打洞。

```yaml
# 客户端。令牌写在 https:// 后面、@ 前面，漏了会提示 token is required
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

打洞和代理共用同一个 UDP 端口。

### 场景 12 — 在 Linux 上伪装成 Chrome 的 QUIC

需要另外安装 [hack3ric/mimic](https://github.com/hack3ric/mimic)。hy 只负责把它拉起来，不代替它改内核。

```yaml
server: 203.0.113.10:443
auth: secret
tls: { sni: example.com }
quic:
  disableChromeParrot: false
mimic:
  enabled: true
  interface: eth0
  xdpMode: native
  path: /usr/bin/mimic
  extraArgs: []
socks5: { listen: 127.0.0.1:1080 }
```

实际执行类似：

```
/usr/bin/mimic run eth0 -f remote=203.0.113.10:443 --xdp-mode native
```

`enabled: false` 不启动。`path` 留空则在系统 PATH 里找 `mimic`。不是 Linux、或找不到这个程序，会明确报错。不要和端口跳跃一起开。

---

## 7. 和官方程序互用

- 官方客户端可以连 hy 服务端，hy 客户端也可以连官方服务端（TCP、UDP 都可以，较大的 UDP 包也行）。
- 单个 UDP 包对外按最多 1200 字节来发。
- 字段名必须按官方拼写：`disableUDP`、`fastOpen`、`speedTest`、`bbrProfile`、`hopInterval`。
- 本机 SOCKS5 若设了用户名密码：对的会通过，错的会被拒绝。
- 流量统计：`Authorization: s3cret` 可以，`Authorization: Bearer s3cret` 不行。

---

## 8. 目前不支持

| 项目 | 会怎样 |
|---|---|
| `tls.ech` / `ech` | 拒绝启动 |
| ACME 的 DNS 验证（`type: dns`） | 报不支持 |
| 出站再套一层、再套一层（多跳） | 只有一跳出站 |
| 除 Chrome 以外的 QUIC 外观 | 不做 |

---

## 9. 我想做……

| 目标 | 打开这些 |
|---|---|
| 浏览器走代理 | 服务端设密码 + 客户端 `socks5` 或 `http` |
| 只转发某一个端口 | `tcpForwarding` / `udpForwarding` |
| 不那么像代理协议 | `obfs` 用 salamander 或 gecko，再加 `masquerade` |
| 限制能访问的网站 | 服务端 `acl.inline` + `resolver`，需要时再开 `sniff` |
| 按国家或网站列表分流 | 服务端 `acl` 里写 `geoip:` / `geosite:` |
| 看用量、踢人 | `trafficStats` |
| 测速 | `speedTest: true`，连接目标 `@speedtest` |
| 证书自动续期 | `acme.type: http` 或 `tls`（域名要能从公网访问到本机） |
| 整台设备走隧道 | Linux 用 `tun` / `tcpRedirect` / `tproxy`；macOS 用 `tun.name: utun数字`（需要管理员权限） |
| 两边都在路由器后面直连 | Realm 地址 + 外部信令服务 |
| 看起来更像 Chrome 的联网 | 默认已模仿；Linux 上再加 `mimic` |
