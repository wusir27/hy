#!/usr/bin/env bash
# P6.D1 Darwin utun checks for GitHub macos-14 (passwordless sudo, no utun10).
set -euo pipefail

HY="${HY:-$(pwd)/target/release/hy}"
test -x "$HY"

WORK="$(mktemp -d /tmp/hy-p6d1.XXXXXX)"
cd "$WORK"
SERVER_LOG="$WORK/server.log"
CLIENT_LOG="$WORK/client.log"
CLIENT_PID=""
SERVER_PID=""

cleanup() {
  set +e
  if [[ -n "${CLIENT_PID}" ]]; then
    sudo -n kill "$CLIENT_PID" 2>/dev/null
    kill "$CLIENT_PID" 2>/dev/null
    wait "$CLIENT_PID" 2>/dev/null
  fi
  if [[ -n "${SERVER_PID}" ]]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  pkill -f "$HY client" 2>/dev/null
  pkill -f "$HY server" 2>/dev/null
  sleep 1
  for ifc in utun123 utun124 utun125; do
    ifconfig "$ifc" >/dev/null 2>&1 && echo "WARN leftover $ifc" >&2
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

cat > server.yaml <<'Y'
listen: 127.0.0.1:18443
tls:
  cert: cert.pem
  key: key.pem
auth:
  type: password
  password: test
Y

cat > client-c.yaml <<'Y'
server: 127.0.0.1:18443
auth: test
tls: { sni: localhost, insecure: true }
tun:
  name: utun123
Y

cat > client-e.yaml <<'Y'
server: 127.0.0.1:18443
auth: test
tls: { sni: localhost, insecure: true }
tun:
  name: utun124
  route:
    ipv4Exclude: ["127.0.0.0/8"]
Y

cat > client-d.yaml <<'Y'
server: 127.0.0.1:18443
auth: test
tls: { sni: localhost, insecure: true }
tun:
  name: utun125
  route:
    ipv4: ["1.1.1.1/32"]
Y

cat > empty.yaml <<'Y'
server: 127.0.0.1:1
auth: x
tls: { insecure: true }
tun: { name: "" }
Y

cat > bad-utun.yaml <<'Y'
server: 127.0.0.1:1
auth: x
tls: { insecure: true }
tun: { name: utun }
Y

cat > bad-hy0.yaml <<'Y'
server: 127.0.0.1:1
auth: x
tls: { insecure: true }
tun: { name: hy0 }
Y

expect_fail() {
  local cfg="$1" needle="$2" label="$3"
  set +e
  out="$("$HY" client -c "$cfg" 2>&1)"
  rc=$?
  set -e
  echo "$out"
  test "$rc" -ne 0
  echo "$out" | grep -q "$needle"
  echo "OK $label"
}

expect_fail empty.yaml "name is empty" "empty name"
expect_fail bad-utun.yaml "bad tun name" "utun"
expect_fail bad-hy0.yaml "bad tun name" "hy0"

"$HY" server -c server.yaml >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  grep -q "server listening" "$SERVER_LOG" && break
  sleep 0.2
done
grep -q "server listening" "$SERVER_LOG"

set +e
out="$("$HY" client -c client-c.yaml 2>&1)"
rc=$?
set -e
echo "$out"
test "$rc" -ne 0
echo "$out" | grep -qi "failed to create tun"
if ifconfig utun123 >/dev/null 2>&1; then
  echo "leftover utun123 after no-root"
  exit 1
fi
echo "OK no-root create fails, no leftover"

default_if() { route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}'; }
BEFORE="$(default_if)"

wait_iface_gone() {
  local ifc="$1"
  for _ in $(seq 1 40); do
    if ! ifconfig "$ifc" >/dev/null 2>&1 && ! pgrep -f "$HY client" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "still present: $ifc / hy client"
  ifconfig "$ifc" || true
  pgrep -lf "$HY client" || true
  return 1
}

start_client() {
  local cfg="$1" ifc="$2"
  wait_iface_gone "$ifc"
  : >"$CLIENT_LOG"
  sudo -n env HYSTERIA_LOG_LEVEL=debug "$HY" client -c "$cfg" >"$CLIENT_LOG" 2>&1 &
  CLIENT_PID=$!
  for _ in $(seq 1 60); do
    if grep -q "TUN listening" "$CLIENT_LOG"; then
      return 0
    fi
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
      echo "client died ($ifc):"
      cat "$CLIENT_LOG"
      ifconfig "$ifc" || true
      return 1
    fi
    sleep 0.25
  done
  echo "no TUN listening ($ifc):"
  cat "$CLIENT_LOG"
  return 1
}

stop_client() {
  local ifc="$1"
  sudo -n pkill -f "$HY client" 2>/dev/null || true
  if [[ -n "${CLIENT_PID}" ]]; then
    sudo -n kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
    CLIENT_PID=""
  fi
  wait_iface_gone "$ifc"
}

start_client client-c.yaml utun123
ifconfig utun123
ifconfig utun123 | grep -q "100.100.100.101"
ifconfig utun123 | grep -qi "2001::ffff:ffff:ffff:fff1"
AFTER="$(default_if)"
test "$BEFORE" = "$AFTER"
stop_client utun123
if ifconfig utun123 >/dev/null 2>&1; then
  echo "C leftover utun123"
  exit 1
fi
echo "OK C: utun123 up with v4+official v6, default route unchanged, gone after exit"

start_client client-e.yaml utun124
AFTER="$(default_if)"
test "$BEFORE" = "$AFTER"
rts="$(netstat -rn -f inet | awk '/utun124/{print $1}')"
echo "$rts"
# Darwin netstat: /8 → "1"/"126"; /1 → "128.0/1"; also "2/7", "64.0/3".
has_net() {
  local a="$1" b="$2"
  echo "$rts" | awk -v a="$a" -v b="$b" '
    $1==a || $1==a"/"b || $1==a".0/"b || $1==a".0.0/"b || $1==a".0.0.0/"b { found=1 }
    END { exit !found }
  ' || { echo "missing ${a}/${b}"; return 1; }
}
# 8 default ranges minus 127.0.0.0/8 (cuts 64/2 into 64/3, 96/4, …).
has_net 1 8
has_net 2 7
has_net 4 6
has_net 8 5
has_net 16 4
has_net 32 3
has_net 64 3
has_net 96 4
has_net 112 5
has_net 120 6
has_net 124 7
has_net 126 8
has_net 128 1
echo "$rts" | awk '$1=="127" || $1=="127/8" || $1=="127.0/8" || $1=="127.0.0.0/8" {found=1} END{exit !found}' && { echo "127/8 exclude leaked"; exit 1; }
echo "$rts" | awk '$1=="64/2" || $1=="64.0/2" || $1=="64.0.0.0/2" {found=1} END{exit !found}' && { echo "64/2 should have been split"; exit 1; }
stop_client utun124
echo "OK E: Darwin ranges minus 127/8 on utun124, default route unchanged"

set +e
if start_client client-d.yaml utun125; then
  if curl -sS --connect-timeout 8 --max-time 12 -o /dev/null -w "%{http_code}" https://1.1.1.1 | grep -qE '^[0-9]{3}$'; then
    echo "OK D optional TCP via utun to 1.1.1.1"
  else
    echo "WARN D optional TCP did not complete (not a gate)"
  fi
  stop_client utun125
else
  echo "WARN D optional client did not start (not a gate)"
fi
set -e

echo "P6.D1 darwin-utun checks passed"
